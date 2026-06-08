import Foundation

public let contextGuardFeasibilitySchemaVersion = "contextguard.metric-feasibility.v1"
public let contextGuardLatestFeasibilitySchemaVersion = "contextguard.metric-feasibility.v1.3"
public let contextGuardSupportedFeasibilitySchemaVersions: Set<String> = [
    contextGuardFeasibilitySchemaVersion,
    "contextguard.metric-feasibility.v1.1",
    "contextguard.metric-feasibility.v1.2",
    contextGuardLatestFeasibilitySchemaVersion,
]

public enum FeasibilityReportError: Error, Equatable, LocalizedError {
    case unsupportedSchema(String)

    public var errorDescription: String? {
        switch self {
        case .unsupportedSchema(let schema):
            return "Unsupported ContextGuard feasibility schema: \(schema)"
        }
    }
}

public struct FeasibilityReport: Decodable, Equatable {
    public let schemaVersion: String
    public let producer: String
    public let generatedAt: String
    public let consumerContract: ConsumerContract?
    public let sourceKind: String
    public let sourceFreshness: SourceFreshness
    public let scanIntegrity: ScanIntegrity
    public let metricAvailability: MetricAvailability
    public let metricCaveats: [String]
    public let redactionMode: RedactionMode
    public let contextAvailability: MetricStatus
    public let headroomAvailability: MetricStatus?
    public let cacheFriendliness: CacheFriendliness?
    public let cacheDiagnostics: CacheDiagnostics?
    public let cacheLayoutAdvice: CacheLayoutAdvice?
    public let macVisibility: MacVisibilityContract?
    public let totals: Totals
    public let diagnosticSummaryPresent: Bool

    private enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case producer
        case generatedAt = "generated_at"
        case consumerContract = "consumer_contract"
        case sourceKind = "source_kind"
        case sourceFreshness = "source_freshness"
        case scanIntegrity = "scan_integrity"
        case metricAvailability = "metric_availability"
        case metricCaveats = "metric_caveats"
        case redactionMode = "redaction_mode"
        case contextAvailability = "context_availability"
        case headroomAvailability = "headroom_availability"
        case cacheFriendliness = "cache_friendliness"
        case cacheDiagnostics = "cache_diagnostics"
        case cacheLayoutAdvice = "cache_layout_advice"
        case macVisibility = "mac_visibility"
        case totals
        case summary
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        schemaVersion = try container.decode(String.self, forKey: .schemaVersion)
        producer = try container.decode(String.self, forKey: .producer)
        generatedAt = try container.decode(String.self, forKey: .generatedAt)
        consumerContract = try container.decodeIfPresent(ConsumerContract.self, forKey: .consumerContract)
        sourceKind = try container.decode(String.self, forKey: .sourceKind)
        sourceFreshness = try container.decode(SourceFreshness.self, forKey: .sourceFreshness)
        scanIntegrity = try container.decode(ScanIntegrity.self, forKey: .scanIntegrity)
        metricAvailability = try container.decode(MetricAvailability.self, forKey: .metricAvailability)
        metricCaveats = try container.decodeIfPresent([String].self, forKey: .metricCaveats) ?? []
        redactionMode = try container.decode(RedactionMode.self, forKey: .redactionMode)
        contextAvailability = try container.decode(MetricStatus.self, forKey: .contextAvailability)
        headroomAvailability = try container.decodeIfPresent(MetricStatus.self, forKey: .headroomAvailability)
        cacheFriendliness = try container.decodeIfPresent(CacheFriendliness.self, forKey: .cacheFriendliness)
        cacheDiagnostics = try container.decodeIfPresent(CacheDiagnostics.self, forKey: .cacheDiagnostics)
        cacheLayoutAdvice = try container.decodeIfPresent(CacheLayoutAdvice.self, forKey: .cacheLayoutAdvice)
        macVisibility = try container.decodeIfPresent(MacVisibilityContract.self, forKey: .macVisibility)
        totals = try container.decode(Totals.self, forKey: .totals)
        diagnosticSummaryPresent = container.contains(.summary)
    }

    public func validateSupportedSchema() throws {
        guard contextGuardSupportedFeasibilitySchemaVersions.contains(schemaVersion) else {
            throw FeasibilityReportError.unsupportedSchema(schemaVersion)
        }
    }
}

public struct ConsumerContract: Decodable, Equatable {
    public let stableTopLevelFields: [String]
    public let diagnosticFields: [String]
    public let summaryContract: String?

    private enum CodingKeys: String, CodingKey {
        case stableTopLevelFields = "stable_top_level_fields"
        case diagnosticFields = "diagnostic_fields"
        case summaryContract = "summary_contract"
    }
}

public struct MacVisibilityContract: Decodable, Equatable {
    public let schemaVersion: String
    public let surfaceKind: String
    public let readiness: MacVisibilityReadiness
    public let bindToTopLevelFields: [String]
    public let diagnosticOnlyFields: [String]
    public let primaryCards: [MacVisibilityCard]
    public let missingLiveObservations: [MissingLiveObservation]
    public let claimBoundaries: [String]
    public let redactionRequired: Bool

    private enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case surfaceKind = "surface_kind"
        case readiness
        case bindToTopLevelFields = "bind_to_top_level_fields"
        case diagnosticOnlyFields = "diagnostic_only_fields"
        case primaryCards = "primary_cards"
        case missingLiveObservations = "missing_live_observations"
        case claimBoundaries = "claim_boundaries"
        case redactionRequired = "redaction_required"
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        schemaVersion = try container.decode(String.self, forKey: .schemaVersion)
        surfaceKind = try container.decode(String.self, forKey: .surfaceKind)
        readiness = try container.decode(MacVisibilityReadiness.self, forKey: .readiness)
        bindToTopLevelFields = try container.decodeIfPresent([String].self, forKey: .bindToTopLevelFields) ?? []
        diagnosticOnlyFields = try container.decodeIfPresent([String].self, forKey: .diagnosticOnlyFields) ?? []
        primaryCards = try container.decodeIfPresent([MacVisibilityCard].self, forKey: .primaryCards) ?? []
        missingLiveObservations = try container.decodeIfPresent([MissingLiveObservation].self, forKey: .missingLiveObservations) ?? []
        claimBoundaries = try container.decodeIfPresent([String].self, forKey: .claimBoundaries) ?? []
        redactionRequired = try container.decodeIfPresent(Bool.self, forKey: .redactionRequired) ?? false
    }
}

public struct MacVisibilityReadiness: Decodable, Equatable {
    public let status: String
    public let reason: String?
}

public struct MacVisibilityCard: Decodable, Equatable {
    public let id: String
    public let title: String
    public let status: String
    public let bindingPaths: [String]
    public let requiredObservation: String?

    private enum CodingKeys: String, CodingKey {
        case id
        case title
        case status
        case bindingPaths = "binding_paths"
        case requiredObservation = "required_observation"
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(String.self, forKey: .id)
        title = try container.decode(String.self, forKey: .title)
        status = try container.decode(String.self, forKey: .status)
        bindingPaths = try container.decodeIfPresent([String].self, forKey: .bindingPaths) ?? []
        requiredObservation = try container.decodeIfPresent(String.self, forKey: .requiredObservation)
    }
}

public struct MissingLiveObservation: Decodable, Equatable {
    public let id: String
    public let requiredObservation: String
    public let affects: [String]
    public let reason: String?

    private enum CodingKeys: String, CodingKey {
        case id
        case requiredObservation = "required_observation"
        case affects
        case reason
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(String.self, forKey: .id)
        requiredObservation = try container.decode(String.self, forKey: .requiredObservation)
        affects = try container.decodeIfPresent([String].self, forKey: .affects) ?? []
        reason = try container.decodeIfPresent(String.self, forKey: .reason)
    }
}

public struct CacheFriendliness: Decodable, Equatable {
    public let status: String
    public let confidence: String?
    public let evidence: String?
    public let heuristic: Bool
    public let score: Double?
    public let summary: String?
    public let caveats: [String]

    private enum CodingKeys: String, CodingKey {
        case status
        case confidence
        case evidence
        case heuristic
        case score
        case summary
        case caveats
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        status = try container.decodeIfPresent(String.self, forKey: .status) ?? "missing"
        confidence = try container.decodeIfPresent(String.self, forKey: .confidence)
        evidence = try container.decodeIfPresent(String.self, forKey: .evidence)
        heuristic = try container.decodeIfPresent(Bool.self, forKey: .heuristic) ?? false
        score = try container.decodeIfPresent(Double.self, forKey: .score)
        summary = try container.decodeIfPresent(String.self, forKey: .summary)
        caveats = try container.decodeIfPresent([String].self, forKey: .caveats) ?? []
    }
}

public struct CacheDiagnostics: Decodable, Equatable {
    public let status: String
    public let confidence: String?
    public let headroomDiagnostics: MetricStatus?
    public let dynamicPrefixBreakers: [CacheDiagnosticSignal]

    private enum CodingKeys: String, CodingKey {
        case status
        case confidence
        case headroomDiagnostics = "headroom_diagnostics"
        case dynamicPrefixBreakers = "dynamic_prefix_breakers"
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        status = try container.decodeIfPresent(String.self, forKey: .status) ?? "missing"
        confidence = try container.decodeIfPresent(String.self, forKey: .confidence)
        headroomDiagnostics = try container.decodeIfPresent(MetricStatus.self, forKey: .headroomDiagnostics)
        dynamicPrefixBreakers = try container.decodeIfPresent([CacheDiagnosticSignal].self, forKey: .dynamicPrefixBreakers) ?? []
    }
}

public struct CacheDiagnosticSignal: Decodable, Equatable {
    public let position: Int?
    public let trigger: String?
    public let volatileShare: Double?
    public let action: String?

    private enum CodingKeys: String, CodingKey {
        case position
        case trigger
        case volatileShare = "volatile_share"
        case action
    }
}

public struct CacheLayoutAdvice: Decodable, Equatable {
    public let status: String
    public let confidence: String?
    public let heuristic: Bool
    public let observedIssue: String?
    public let priority: String?
    public let summary: String?
    public let nextChecks: [CacheLayoutAction]
    public let recommendedExperiments: [CacheLayoutAction]
    public let recommendations: [CacheLayoutAction]
    public let caveats: [String]

    private enum CodingKeys: String, CodingKey {
        case status
        case confidence
        case heuristic
        case observedIssue = "observed_issue"
        case priority
        case summary
        case nextChecks = "next_checks"
        case recommendedExperiments = "recommended_experiments"
        case recommendations
        case caveats
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        status = try container.decodeIfPresent(String.self, forKey: .status) ?? "missing"
        confidence = try container.decodeIfPresent(String.self, forKey: .confidence)
        heuristic = try container.decodeIfPresent(Bool.self, forKey: .heuristic) ?? false
        observedIssue = try container.decodeIfPresent(String.self, forKey: .observedIssue)
        priority = try container.decodeIfPresent(String.self, forKey: .priority)
        summary = try container.decodeIfPresent(String.self, forKey: .summary)
        nextChecks = try container.decodeIfPresent([CacheLayoutAction].self, forKey: .nextChecks) ?? []
        recommendedExperiments = try container.decodeIfPresent([CacheLayoutAction].self, forKey: .recommendedExperiments) ?? []
        recommendations = try container.decodeIfPresent([CacheLayoutAction].self, forKey: .recommendations) ?? []
        caveats = try container.decodeIfPresent([String].self, forKey: .caveats) ?? []
    }
}

public struct CacheLayoutAction: Decodable, Equatable {
    public let id: String?
    public let priority: String?
    public let action: String?
    public let verification: String?

    private enum CodingKeys: String, CodingKey {
        case id
        case priority
        case action
        case verification
    }
}

public struct SourceFreshness: Decodable, Equatable {
    public let status: String
    public let live: Bool
    public let generatedAt: String?
    public let description: String?

    private enum CodingKeys: String, CodingKey {
        case status
        case live
        case generatedAt = "generated_at"
        case description
    }
}

public struct ScanIntegrity: Decodable, Equatable {
    public let status: String
    public let filesScanned: Int
    public let recordsScanned: Int
    public let skippedFiles: Int
    public let skippedRecords: Int
    public let parseErrorCount: Int
    public let complete: Bool?

    private enum CodingKeys: String, CodingKey {
        case status
        case filesScanned = "files_scanned"
        case recordsScanned = "records_scanned"
        case skippedFiles = "skipped_files"
        case skippedRecords = "skipped_records"
        case parseErrorCount = "parse_error_count"
        case complete
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        status = try container.decode(String.self, forKey: .status)
        filesScanned = try container.decodeIfPresent(Int.self, forKey: .filesScanned) ?? 0
        recordsScanned = try container.decodeIfPresent(Int.self, forKey: .recordsScanned) ?? 0
        skippedFiles = try container.decodeIfPresent(Int.self, forKey: .skippedFiles) ?? 0
        skippedRecords = try container.decodeIfPresent(Int.self, forKey: .skippedRecords) ?? 0
        parseErrorCount = try container.decodeIfPresent(Int.self, forKey: .parseErrorCount) ?? 0
        complete = try container.decodeIfPresent(Bool.self, forKey: .complete)
    }
}

public struct MetricAvailability: Decodable, Equatable {
    public let tokens: MetricStatus?
    public let cache: MetricStatus?
    public let cost: MetricStatus?
    public let context: MetricStatus?
    public let input: MetricStatus?
    public let output: MetricStatus?
}

public struct MetricStatus: Decodable, Equatable {
    public let status: String
    public let reason: String?
    public let presentCount: Int?
    public let observedCostUSD: Double?
    public let evidence: String?
    public let observableVia: String?
    public let presentFields: [String: Int]
    public let zeroValuesObserved: [String: Bool]

    private enum CodingKeys: String, CodingKey {
        case status
        case reason
        case presentCount = "present_count"
        case observedCostUSD = "observed_cost_usd"
        case evidence
        case observableVia = "observable_via"
        case presentFields = "present_fields"
        case zeroValuesObserved = "zero_values_observed"
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        status = try container.decode(String.self, forKey: .status)
        reason = try container.decodeIfPresent(String.self, forKey: .reason)
        presentCount = try container.decodeIfPresent(Int.self, forKey: .presentCount)
        observedCostUSD = try container.decodeIfPresent(Double.self, forKey: .observedCostUSD)
        evidence = try container.decodeIfPresent(String.self, forKey: .evidence)
        observableVia = try container.decodeIfPresent(String.self, forKey: .observableVia)
        presentFields = try container.decodeIfPresent([String: Int].self, forKey: .presentFields) ?? [:]
        zeroValuesObserved = try container.decodeIfPresent([String: Bool].self, forKey: .zeroValuesObserved) ?? [:]
    }

    public var isAvailableOrPartial: Bool {
        let normalized = status.lowercased()
        return normalized == "available" || normalized == "partial"
    }
}

public struct RedactionMode: Decodable, Equatable {
    public let paths: String?
    public let commands: String?
    public let secretLikeValues: String?
    public let rawPathAndCommandFlags: [String]

    private enum CodingKeys: String, CodingKey {
        case paths
        case commands
        case secretLikeValues = "secret_like_values"
        case rawPathAndCommandFlags = "raw_path_and_command_flags"
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        paths = try container.decodeIfPresent(String.self, forKey: .paths)
        commands = try container.decodeIfPresent(String.self, forKey: .commands)
        secretLikeValues = try container.decodeIfPresent(String.self, forKey: .secretLikeValues)
        rawPathAndCommandFlags = try container.decodeIfPresent([String].self, forKey: .rawPathAndCommandFlags) ?? []
    }
}

public struct Totals: Decodable, Equatable {
    public let totalTokens: Int
    public let tokens: TokenTotals
    public let costUSDObserved: Double?
    public let cacheReadShare: Double?
    public let cacheReuseRatio: Double?

    private enum CodingKeys: String, CodingKey {
        case totalTokens = "total_tokens"
        case tokens
        case costUSDObserved = "cost_usd_observed"
        case cacheReadShare = "cache_read_share"
        case cacheReuseRatio = "cache_reuse_ratio"
    }
}

public struct TokenTotals: Decodable, Equatable {
    public let input: Int
    public let output: Int
    public let cacheRead: Int
    public let cacheCreation: Int

    private enum CodingKeys: String, CodingKey {
        case input
        case output
        case cacheRead = "cache_read"
        case cacheCreation = "cache_creation"
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        input = try container.decodeIfPresent(Int.self, forKey: .input) ?? 0
        output = try container.decodeIfPresent(Int.self, forKey: .output) ?? 0
        cacheRead = try container.decodeIfPresent(Int.self, forKey: .cacheRead) ?? 0
        cacheCreation = try container.decodeIfPresent(Int.self, forKey: .cacheCreation) ?? 0
    }
}
