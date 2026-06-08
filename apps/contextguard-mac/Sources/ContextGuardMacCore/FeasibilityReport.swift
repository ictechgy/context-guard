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
    public let presentFields: [String: Int]
    public let zeroValuesObserved: [String: Bool]

    private enum CodingKeys: String, CodingKey {
        case status
        case reason
        case presentCount = "present_count"
        case observedCostUSD = "observed_cost_usd"
        case presentFields = "present_fields"
        case zeroValuesObserved = "zero_values_observed"
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        status = try container.decode(String.self, forKey: .status)
        reason = try container.decodeIfPresent(String.self, forKey: .reason)
        presentCount = try container.decodeIfPresent(Int.self, forKey: .presentCount)
        observedCostUSD = try container.decodeIfPresent(Double.self, forKey: .observedCostUSD)
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
