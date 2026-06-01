import AppKit
import Combine
import ContextGuardMacCore
import SwiftUI

@MainActor
final class AppState: ObservableObject {
    @Published var snapshot: VisibilitySnapshot
    @Published var transcriptDirectory: URL?

    private let fallbackExecutableURL: URL?

    init(fallbackExecutableURL: URL?) {
        self.fallbackExecutableURL = fallbackExecutableURL
        let defaultDirectory = DefaultTranscriptLocator.defaultClaudeProjectsDirectory()
        transcriptDirectory = defaultDirectory
        snapshot = VisibilityViewModel.setup(defaultDirectory: defaultDirectory)
        if defaultDirectory != nil {
            refresh()
        }
    }

    func chooseDirectory() {
        let panel = NSOpenPanel()
        panel.title = "Choose Claude transcript directory"
        panel.prompt = "Use Directory"
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false
        panel.canCreateDirectories = false
        panel.begin { [weak self] response in
            guard response == .OK, let url = panel.url else { return }
            Task { @MainActor in
                self?.transcriptDirectory = url
                self?.refresh()
            }
        }
    }

    func refresh() {
        guard let transcriptDirectory else {
            snapshot = VisibilityViewModel.setup(defaultDirectory: DefaultTranscriptLocator.defaultClaudeProjectsDirectory())
            return
        }
        snapshot = VisibilityViewModel.loading()
        let fallback = fallbackExecutableURL
        let target = transcriptDirectory
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let adapter = AuditCLIAdapter(fallbackExecutableURL: fallback, timeout: 30)
            let result = Result { try adapter.loadReport(transcriptDirectory: target, includeRecommendations: true) }
            DispatchQueue.main.async {
                switch result {
                case .success(let report):
                    self?.snapshot = VisibilityViewModel.snapshot(report: report)
                case .failure(let error):
                    self?.snapshot = VisibilityViewModel.error(error)
                }
            }
        }
    }
}

struct ContextGuardContentView: View {
    @ObservedObject var state: AppState

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            header
            controls
            Divider()
            if state.snapshot.cards.isEmpty {
                Text(state.snapshot.contextMessage)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            } else {
                cards
            }
            if !state.snapshot.caveats.isEmpty {
                Divider()
                caveats
            }
        }
        .padding(16)
        .frame(width: 430)
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(state.snapshot.headline)
                .font(.headline)
            Text(state.snapshot.sourceMessage)
                .font(.caption)
                .foregroundStyle(.secondary)
            if let directory = state.transcriptDirectory {
                Text(directory.path)
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
                    .lineLimit(2)
            }
        }
    }

    private var controls: some View {
        HStack {
            Button("Refresh") { state.refresh() }
                .keyboardShortcut("r")
            Button("Choose…") { state.chooseDirectory() }
            Spacer()
            Text(state.snapshot.statusTitle)
                .font(.caption.weight(.semibold))
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
                .background(statusColor.opacity(0.16), in: Capsule())
        }
    }

    private var cards: some View {
        VStack(spacing: 8) {
            ForEach(state.snapshot.cards, id: \.title) { card in
                HStack(alignment: .firstTextBaseline) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(card.title)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        if let detail = card.detail, !detail.isEmpty {
                            Text(detail)
                                .font(.caption2)
                                .foregroundStyle(.tertiary)
                                .lineLimit(2)
                        }
                    }
                    Spacer(minLength: 12)
                    Text(card.value)
                        .font(.body.monospacedDigit())
                        .foregroundStyle(card.isAvailable ? .primary : .secondary)
                }
                .padding(8)
                .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
            }
        }
    }

    private var caveats: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Caveats")
                .font(.caption.weight(.semibold))
            ForEach(state.snapshot.caveats, id: \.self) { caveat in
                Text("• \(caveat)")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private var statusColor: Color {
        switch state.snapshot.severity {
        case .ready:
            return .green
        case .partial, .warning:
            return .orange
        case .unavailable, .loading:
            return .blue
        case .error:
            return .red
        }
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private var statusItem: NSStatusItem?
    private let popover = NSPopover()
    private var cancellable: AnyCancellable?
    private lazy var appState = AppState(fallbackExecutableURL: Self.defaultRepoLocalAuditExecutable())

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        item.button?.title = appState.snapshot.statusTitle
        item.button?.target = self
        item.button?.action = #selector(togglePopover(_:))
        statusItem = item

        popover.behavior = .transient
        popover.contentSize = NSSize(width: 430, height: 560)
        popover.contentViewController = NSHostingController(rootView: ContextGuardContentView(state: appState))

        cancellable = appState.$snapshot.sink { [weak self] snapshot in
            self?.statusItem?.button?.title = snapshot.statusTitle
        }
    }

    @objc private func togglePopover(_ sender: Any?) {
        guard let button = statusItem?.button else { return }
        if popover.isShown {
            popover.performClose(sender)
        } else {
            popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
        }
    }

    private static func defaultRepoLocalAuditExecutable() -> URL? {
        let fileManager = FileManager.default
        let current = URL(fileURLWithPath: fileManager.currentDirectoryPath, isDirectory: true)
        let candidates = [
            current.appendingPathComponent("plugins/context-guard/bin/context-guard-audit"),
            current.appendingPathComponent("../../plugins/context-guard/bin/context-guard-audit").standardizedFileURL
        ]
        return candidates.first { fileManager.isExecutableFile(atPath: $0.path) }
    }
}

@main
enum ContextGuardMacMain {
    private static var delegate: AppDelegate?

    @MainActor
    static func main() {
        let app = NSApplication.shared
        let appDelegate = AppDelegate()
        delegate = appDelegate
        app.delegate = appDelegate
        app.run()
    }
}
