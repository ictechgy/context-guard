import Foundation

public enum VisibilitySeverity: String, Equatable {
    case ready
    case partial
    case unavailable
    case warning
    case loading
    case error
}

public struct MetricCard: Equatable {
    public let title: String
    public let value: String
    public let detail: String?
    public let isAvailable: Bool

    public init(title: String, value: String, detail: String? = nil, isAvailable: Bool = true) {
        self.title = title
        self.value = value
        self.detail = detail
        self.isAvailable = isAvailable
    }
}

public struct VisibilitySnapshot: Equatable {
    public let statusTitle: String
    public let headline: String
    public let severity: VisibilitySeverity
    public let sourceMessage: String
    public let contextMessage: String
    public let cards: [MetricCard]
    public let caveats: [String]

    public init(
        statusTitle: String,
        headline: String,
        severity: VisibilitySeverity,
        sourceMessage: String,
        contextMessage: String,
        cards: [MetricCard],
        caveats: [String]
    ) {
        self.statusTitle = statusTitle
        self.headline = headline
        self.severity = severity
        self.sourceMessage = sourceMessage
        self.contextMessage = contextMessage
        self.cards = cards
        self.caveats = caveats
    }
}

public enum VisibilityViewModel {
    public static func loading() -> VisibilitySnapshot {
        VisibilitySnapshot(
            statusTitle: "CG …",
            headline: "Scanning transcripts…",
            severity: .loading,
            sourceMessage: "Running context-guard-audit locally.",
            contextMessage: "Context availability will be shown after scan.",
            cards: [],
            caveats: []
        )
    }

    public static func setup(defaultDirectory: URL?) -> VisibilitySnapshot {
        let source = defaultDirectory.map { "Default transcript directory: \($0.path)" } ?? "Choose a Claude transcript directory to begin."
        return VisibilitySnapshot(
            statusTitle: "CG setup",
            headline: "ContextGuard visibility is ready to scan.",
            severity: .unavailable,
            sourceMessage: source,
            contextMessage: "Transcript scans cannot provide live context-window availability.",
            cards: [],
            caveats: ["Metrics are local transcript observations, not official billing records."]
        )
    }

    public static func error(_ error: Error) -> VisibilitySnapshot {
        VisibilitySnapshot(
            statusTitle: "CG ⚠",
            headline: "Could not load ContextGuard metrics.",
            severity: .error,
            sourceMessage: error.localizedDescription,
            contextMessage: "No transcript metrics are available for this refresh.",
            cards: [],
            caveats: ["No data was sent over the network by the Mac prototype."]
        )
    }

    public static func snapshot(report: FeasibilityReport) -> VisibilitySnapshot {
        let scanStatus = report.scanIntegrity.status.lowercased()
        let cacheStatus = report.metricAvailability.cache?.status.lowercased()
        let hasSkippedData = report.scanIntegrity.skippedFiles > 0 || report.scanIntegrity.skippedRecords > 0 || report.scanIntegrity.parseErrorCount > 0
        let severity: VisibilitySeverity
        if scanStatus == "complete" && !hasSkippedData {
            severity = cacheStatus == "missing" ? .unavailable : .ready
        } else if scanStatus == "partial" || hasSkippedData {
            severity = .partial
        } else {
            severity = .warning
        }

        let statusTitle: String
        switch severity {
        case .ready:
            statusTitle = "CG"
        case .partial:
            statusTitle = "CG partial"
        case .unavailable:
            statusTitle = "CG missing"
        case .warning, .error:
            statusTitle = "CG ⚠"
        case .loading:
            statusTitle = "CG …"
        }

        let tokens = report.totals.tokens
        let sourceMessage = report.sourceFreshness.live
            ? "Live source generated at \(report.generatedAt)."
            : "Snapshot scan generated at \(report.generatedAt); not a live statusline signal."
        let contextMessage = contextCopy(report.contextAvailability)

        var cards: [MetricCard] = [
            MetricCard(title: "Total tokens", value: formatInteger(report.totals.totalTokens), detail: "input + output + cache read + cache creation"),
            MetricCard(title: "Input", value: formatInteger(tokens.input)),
            MetricCard(title: "Output", value: formatInteger(tokens.output)),
            MetricCard(title: "Cache read", value: formatInteger(tokens.cacheRead), detail: availabilityDetail(report.metricAvailability.cache)),
            MetricCard(title: "Cache creation", value: formatInteger(tokens.cacheCreation)),
            MetricCard(title: "Cache-read share", value: formatPercent(report.totals.cacheReadShare), detail: "cache_read / (input + cache_read + cache_creation)", isAvailable: report.totals.cacheReadShare != nil),
            MetricCard(title: "Reuse ratio", value: formatRatio(report.totals.cacheReuseRatio), detail: "cache_read / cache_creation", isAvailable: report.totals.cacheReuseRatio != nil),
            MetricCard(title: "Observed cost", value: formatCost(report.totals.costUSDObserved), detail: "Observed transcript field; not invoice-grade billing", isAvailable: report.totals.costUSDObserved != nil),
            MetricCard(title: "Scan integrity", value: report.scanIntegrity.status, detail: scanDetail(report.scanIntegrity)),
            MetricCard(title: "Context availability", value: report.contextAvailability.status, detail: report.contextAvailability.reason, isAvailable: report.contextAvailability.isAvailableOrPartial)
        ]
        if let headroomAvailability = report.headroomAvailability {
            cards.append(MetricCard(
                title: "Headroom availability",
                value: headroomAvailability.status,
                detail: headroomDetail(headroomAvailability, macVisibility: report.macVisibility),
                isAvailable: headroomAvailability.isAvailableOrPartial
            ))
        }
        if let cacheLayoutCard = cacheLayoutAdviceCard(report: report) {
            cards.append(cacheLayoutCard)
        }
        cards.removeAll { !$0.isAvailable && ($0.title == "Observed cost") }
        let caveats = report.metricCaveats + (report.macVisibility?.claimBoundaries ?? [])

        return VisibilitySnapshot(
            statusTitle: statusTitle,
            headline: "ContextGuard local transcript metrics",
            severity: severity,
            sourceMessage: sourceMessage,
            contextMessage: contextMessage,
            cards: cards,
            caveats: caveats
        )
    }

    private static func contextCopy(_ status: MetricStatus) -> String {
        if status.isAvailableOrPartial {
            return "Context availability is \(status.status)."
        }
        return status.reason ?? "Transcript scans do not include live Claude Code context-window data."
    }

    private static func availabilityDetail(_ status: MetricStatus?) -> String? {
        guard let status else { return nil }
        if status.presentFields.isEmpty {
            return status.reason ?? "Availability: \(status.status)"
        }
        let fields = status.presentFields.sorted { $0.key < $1.key }.map { "\($0.key): \($0.value)" }.joined(separator: ", ")
        return "Availability: \(status.status) (\(fields))"
    }

    private static func scanDetail(_ integrity: ScanIntegrity) -> String {
        "files \(integrity.filesScanned), records \(integrity.recordsScanned), skipped files \(integrity.skippedFiles), skipped records \(integrity.skippedRecords), parse errors \(integrity.parseErrorCount)"
    }

    private static func headroomDetail(_ status: MetricStatus, macVisibility: MacVisibilityContract?) -> String? {
        if let missingHeadroom = macVisibility?.missingLiveObservations.first(where: { $0.id == "live_headroom" }) {
            let observation = "\(missingHeadroom.reason ?? "Historical transcript scans do not include live headroom observations.") Required observation: \(missingHeadroom.requiredObservation)."
            if let reason = status.reason, !reason.isEmpty {
                return "\(reason) \(observation)"
            }
            return observation
        }
        if let reason = status.reason {
            return reason
        }
        if let observableVia = status.observableVia {
            return "Observable via \(observableVia)."
        }
        return nil
    }

    private static func cacheLayoutAdviceCard(report: FeasibilityReport) -> MetricCard? {
        guard let advice = report.cacheLayoutAdvice else {
            return nil
        }
        let contractCard = report.macVisibility?.primaryCards.first { $0.id == "cache_layout_advice" }
        let title = contractCard?.title ?? "Cache layout advice"
        return MetricCard(
            title: title,
            value: advice.status,
            detail: cacheLayoutAdviceDetail(
                advice: advice,
                friendliness: report.cacheFriendliness,
                diagnostics: report.cacheDiagnostics
            ),
            isAvailable: advice.isAvailableOrPartial
        )
    }

    private static func cacheLayoutAdviceDetail(
        advice: CacheLayoutAdvice,
        friendliness: CacheFriendliness?,
        diagnostics: CacheDiagnostics?
    ) -> String {
        var parts: [String] = []
        if let summary = advice.summary, !summary.isEmpty {
            parts.append(summary)
        } else if let observedIssue = advice.observedIssue, !observedIssue.isEmpty {
            parts.append("Observed issue: \(observedIssue).")
        }
        if let priority = advice.priority, !priority.isEmpty {
            parts.append("Priority: \(priority).")
        }
        if let action = (advice.recommendedExperiments.first?.action ?? advice.recommendations.first?.action ?? advice.nextChecks.first?.action),
           !action.isEmpty {
            parts.append(action)
        }
        if let breaker = diagnostics?.dynamicPrefixBreakers.first, let position = breaker.position {
            parts.append("Dynamic prefix breaker position: \(position).")
        }
        if let score = friendliness?.score {
            parts.append(String(format: "Cache-friendliness score: %.2f.", score))
        }
        let caveat = advice.caveats.first ?? "Cache layout advice is a local transcript heuristic, not billing authority or provider-cache proof."
        parts.append(caveat)
        return parts.joined(separator: " ")
    }

    private static func formatInteger(_ value: Int) -> String {
        let formatter = NumberFormatter()
        formatter.numberStyle = .decimal
        return formatter.string(from: NSNumber(value: value)) ?? String(value)
    }

    private static func formatPercent(_ value: Double?) -> String {
        guard let value else { return "Unavailable" }
        return String(format: "%.1f%%", value * 100)
    }

    private static func formatRatio(_ value: Double?) -> String {
        guard let value else { return "Undefined" }
        return String(format: "%.2f×", value)
    }

    private static func formatCost(_ value: Double?) -> String {
        guard let value else { return "Unavailable" }
        return String(format: "$%.4f", value)
    }
}

private extension CacheLayoutAdvice {
    var isAvailableOrPartial: Bool {
        let normalized = status.lowercased()
        return normalized == "available" || normalized == "partial"
    }
}
