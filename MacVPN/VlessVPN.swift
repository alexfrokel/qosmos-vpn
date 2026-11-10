import AppKit
import CoreServices
import Darwin
import SwiftUI
import UniformTypeIdentifiers

struct Profile: Codable, Equatable {
    var name: String
    let host: String
    let port: Int
    let user: String
    let flow: String
    let encryption: String
    let network: String
    let security: String
    let sni: String
    let fingerprint: String
    let key: String
    let shortID: String
    let spider: String
    var cloudflareHost: String?
    var sshUser: String?
    var sshPort: Int?
    var sshIdentity: String?

    var entryHost: String { cloudflareHost ?? host }
    var entryIsIPAddress: Bool {
        var ipv4 = in_addr()
        var ipv6 = in6_addr()
        return inet_pton(AF_INET, entryHost, &ipv4) == 1 || inet_pton(AF_INET6, entryHost, &ipv6) == 1
    }

    var endpoint: String {
        if let cloudflareHost { return "\(cloudflareHost):443" }
        if sshUser != nil { return "\(host):\(sshPort ?? 22) · SSH" }
        let address = host.contains(":") ? "[\(host)]" : host
        return "\(address):\(port)"
    }
}

struct SavedProfile: Codable, Identifiable {
    var id = UUID()
    var profile: Profile
    var entryIP: String?
    var exitIP: String?
}

struct BackendEvent: Decodable {
    let kind: String
    let message: String
    let entryIP: String?
}

struct AppError: LocalizedError {
    let message: String
    var errorDescription: String? { message }
}

final class VPNModel: ObservableObject {
    enum State {
        case idle, connecting, connected, reconnecting, terminalConnected, disconnecting
    }

    @Published private(set) var profiles: [SavedProfile] = []
    @Published var selection: UUID?
    @Published private(set) var state: State = .idle {
        didSet {
            guard oldValue != state else { return }
            ipCheckID = nil
            exitIP = nil
            checkingIP = false
        }
    }
    @Published private(set) var detail = "Выберите профиль и подключитесь."
    @Published private(set) var exitIP: String?
    @Published private(set) var internetBlocked = false
    @Published private(set) var checkingIP = false
    @Published private(set) var importBusy = false
    @Published var provisioning = false
    @Published var errorMessage: String?
    @Published var showSettings = false

    let preferences: AppPreferences
    private var backend: Process?
    private var terminalCheckPending = false
    private var autoConnectPending = false
    private var resumeAfterUpdate = false
    private var reconnectWithSettingsPending = false
    private var activeRequest: ConnectionRequest?
    private var ipCheckID: UUID?
    private var quitCompletion: (() -> Void)?
    private let storage: URL
    private let defaults: UserDefaults
    private let worker = DispatchQueue(label: "local.vlessvpn.backend", qos: .userInitiated)
    private(set) var restartingForUpdate = false

    init(defaults: UserDefaults = .standard, directory: URL? = nil) {
        self.defaults = defaults
        let directory = directory ?? FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("VLESS VPN", isDirectory: true)
        storage = directory.appendingPathComponent("profiles.json")
        preferences = AppPreferences(defaults: defaults, directory: directory)
        if FileManager.default.fileExists(atPath: storage.path) {
            do {
                profiles = try JSONDecoder().decode([SavedProfile].self, from: Data(contentsOf: storage))
            } catch {
                errorMessage = "Не удалось прочитать сохранённые профили."
            }
        }
        if let saved = defaults.string(forKey: "selectedProfile"),
           let identifier = UUID(uuidString: saved), profiles.contains(where: { $0.id == identifier }) {
            selection = identifier
        } else {
            selection = profiles.first?.id
        }
    }

    var selectedProfile: Profile? { profiles.first(where: { $0.id == selection })?.profile }
    var isIdle: Bool { state == .idle }
    var isRunning: Bool { backend != nil }
    var isConnected: Bool { state == .connected || state == .terminalConnected }
    var showsVPNExitIP: Bool { state == .connected && activeRequest?.vpnSites != nil }
    var canToggle: Bool {
        state != .disconnecting && !importBusy && !provisioning && (!isIdle || selectedProfile != nil)
    }
    var stateLabel: String {
        switch state {
        case .idle: return internetBlocked ? "Интернет заблокирован" : "Отключено"
        case .connecting: return "Подключение"
        case .reconnecting: return "Переподключение"
        case .connected, .terminalConnected: return "Подключено"
        case .disconnecting: return "Отключение"
        }
    }
    var actionLabel: String {
        if state == .reconnecting { return "Остановить переподключение" }
        return isIdle ? "Подключить" : "Отключить"
    }

    func toggleConnection() {
        guard canToggle else { return }
        if isIdle {
            connect()
        } else {
            disconnect()
        }
    }

    func reconnect() {
        guard state == .connected, let backend, backend.isRunning,
              kill(backend.processIdentifier, SIGUSR1) == 0 else { return }
        state = .reconnecting
        detail = "Восстанавливаем соединение с VPN…"
    }

    func reconnectWithCurrentSettings() {
        guard state == .connected, let request = connectionRequest, let activeRequest else { return }
        if request.profile == activeRequest.profile && request.directSites == activeRequest.directSites
            && request.directRuSites == activeRequest.directRuSites && request.vpnSites == activeRequest.vpnSites {
            reconnect()
        } else {
            reconnectWithSettingsPending = true
            disconnect(keepingProtection: true)
        }
    }

    func restoreInternet() {
        guard isIdle, internetBlocked else { return }
        state = .disconnecting
        startBackend("release-protection")
    }

    func prepareLaunch(resumeAfterUpdate: Bool = false) {
        self.resumeAfterUpdate = resumeAfterUpdate
        autoConnectPending = resumeAfterUpdate || preferences.autoConnect
        if preferences.autoUpdates { preferences.checkForUpdates() }
        preferences.record("Application launched")
        refreshTerminal(refreshIP: true)
    }

    func refreshPublicIP() {
        guard state != .connecting, state != .reconnecting, state != .disconnecting,
              !internetBlocked, !terminalCheckPending, !checkingIP, !showsVPNExitIP else { return }
        let checkID = UUID()
        ipCheckID = checkID
        checkingIP = true
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let value: String?
            do {
                let (process, input, output) = try Self.makeBackend(["public-ip"])
                try process.run()
                try input.fileHandleForWriting.close()
                let data = output.fileHandleForReading.readDataToEndOfFile()
                process.waitUntilExit()
                value = process.terminationStatus == 0
                    ? String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
                    : nil
            } catch {
                value = nil
            }
            DispatchQueue.main.async { [weak self] in
                guard let self, self.ipCheckID == checkID else { return }
                self.exitIP = value
                self.checkingIP = false
            }
        }
    }

    func refreshTerminal(refreshIP: Bool = false) {
        guard (isIdle || state == .terminalConnected), !importBusy, !terminalCheckPending else { return }
        terminalCheckPending = true
        worker.async { [weak self] in
            let status: String?
            do {
                let (process, input, output) = try Self.makeBackend(["terminal-status"])
                try process.run()
                try input.fileHandleForWriting.close()
                let data = output.fileHandleForReading.readDataToEndOfFile()
                process.waitUntilExit()
                status = process.terminationStatus == 0
                    ? String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines) : nil
            } catch {
                status = nil
            }
            DispatchQueue.main.async { [weak self] in
                guard let self else { return }
                self.terminalCheckPending = false
                guard let status, !self.importBusy, self.isIdle || self.state == .terminalConnected else { return }
                let active = status == "active"
                let blocked = status == "blocked"
                let protectionReleased = self.internetBlocked && !blocked
                if blocked != self.internetBlocked {
                    self.internetBlocked = blocked
                    if blocked {
                        self.exitIP = nil
                        self.ipCheckID = nil
                        self.checkingIP = false
                    }
                }
                if active && self.isIdle {
                    self.state = .terminalConnected
                    self.detail = "VPN запущен из Терминала."
                    self.refreshPublicIP()
                } else if !active && self.state == .terminalConnected {
                    self.state = .idle
                    self.detail = "VPN отключён."
                    self.refreshPublicIP()
                }
                if self.autoConnectPending {
                    self.autoConnectPending = false
                    if !active && (!blocked || self.resumeAfterUpdate) && self.isIdle {
                        self.connect(allowInstall: false)
                    }
                    self.resumeAfterUpdate = false
                }
                if self.reconnectWithSettingsPending {
                    self.reconnectWithSettingsPending = false
                    if !active && self.isIdle { self.connect() }
                }
                if refreshIP || protectionReleased {
                    self.refreshPublicIP()
                }
            }
        }
    }

    func select(_ id: UUID?) {
        selection = id
        defaults.set(id?.uuidString, forKey: "selectedProfile")
    }

    private func save(_ entries: [SavedProfile]) throws {
        try FileManager.default.createDirectory(
            at: storage.deletingLastPathComponent(), withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        try JSONEncoder().encode(entries).write(to: storage, options: .atomic)
    }

    func importFile(_ url: URL, onSuccess: @escaping () -> Void = {}) {
        do {
            let size = try url.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0
            guard size <= 1_048_576 else { throw AppError(message: "Файл профилей больше 1 МБ.") }
            let content = try String(contentsOf: url, encoding: .utf8)
            importText(content, name: url.deletingPathExtension().lastPathComponent, onSuccess: onSuccess)
        } catch {
            errorMessage = (error as? AppError)?.message ?? "Не удалось прочитать файл в формате UTF-8."
        }
    }

    func importText(_ text: String, name: String = "", onSuccess: @escaping () -> Void = {}) {
        guard !importBusy, !provisioning, isIdle else { return }
        guard text.utf8.count <= 1_048_576 else {
            errorMessage = "Профили занимают больше 1 МБ."
            return
        }
        importBusy = true
        worker.async { [weak self] in
            do {
                let (process, input, output) = try Self.makeBackend(["import", name])
                try process.run()
                try input.fileHandleForWriting.write(contentsOf: Data(text.utf8))
                try input.fileHandleForWriting.close()
                let data = output.fileHandleForReading.readDataToEndOfFile()
                process.waitUntilExit()
                if process.terminationStatus != 0 {
                    let event = try? JSONDecoder().decode(BackendEvent.self, from: data)
                    throw AppError(message: event?.message ?? "Не удалось импортировать профиль.")
                }
                let imported = try JSONDecoder().decode([Profile].self, from: data)
                DispatchQueue.main.async { [weak self] in
                    if self?.storeImports(imported) == true { onSuccess() }
                }
            } catch {
                let message = (error as? AppError)?.message ?? "Не удалось импортировать профиль."
                DispatchQueue.main.async { [weak self] in
                    self?.importBusy = false
                    self?.errorMessage = message
                }
            }
        }
    }

    @discardableResult
    func storeImports(_ imported: [Profile], exitIP: String? = nil, reportError: Bool = true) -> Bool {
        defer {
            importBusy = false
            if autoConnectPending { refreshTerminal() }
        }
        var entries = profiles
        var firstID: UUID?
        for profile in imported {
            let index = entries.firstIndex { entry in
                var candidate = profile
                candidate.name = entry.profile.name
                return entry.profile == candidate
            } ?? entries.endIndex
            if index == entries.endIndex { entries.append(SavedProfile(profile: profile)) }
            if let exitIP, imported.count == 1 { entries[index].exitIP = exitIP }
            if firstID == nil { firstID = entries[index].id }
        }
        do {
            try save(entries)
            profiles = entries
            select(firstID)
            detail = "Профиль готов к подключению."
            return true
        } catch {
            if reportError { errorMessage = "Не удалось сохранить профили на Mac." }
            return false
        }
    }

    @discardableResult
    func renameProfile(_ id: UUID, to proposedName: String) -> Bool {
        guard !importBusy, let index = profiles.firstIndex(where: { $0.id == id }) else { return false }
        guard let name = Self.normalizedProfileName(proposedName) else {
            errorMessage = "Введите название от 1 до 90 символов в одну строку."
            return false
        }
        var entries = profiles
        entries[index].profile.name = name
        do {
            try save(entries)
            profiles = entries
            return true
        } catch {
            errorMessage = "Не удалось сохранить имя профиля."
            return false
        }
    }

    static func normalizedProfileName(_ value: String) -> String? {
        let name = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty, name.count <= 90, name.rangeOfCharacter(from: .newlines) == nil else { return nil }
        return name
    }

    func resetData() {
        guard isIdle, !importBusy else { return }
        do {
            try preferences.reset()
            if FileManager.default.fileExists(atPath: storage.path) {
                try FileManager.default.removeItem(at: storage)
            }
            profiles = []
            select(nil)
            detail = "Выберите профиль и подключитесь."
            autoConnectPending = false
        } catch {
            errorMessage = "Не удалось полностью сбросить данные приложения."
        }
    }

    func removeProfile(_ id: UUID) {
        guard isIdle, !importBusy, !provisioning else { return }
        let remaining = profiles.filter { $0.id != id }
        do {
            try save(remaining)
            profiles = remaining
            if selection == id { select(remaining.first?.id) }
        } catch {
            errorMessage = "Не удалось удалить профиль."
        }
    }

    private struct ConnectionRequest: Encodable {
        let profile: Profile
        let directSites: String
        let directRuSites: Bool
        let previousEntryIP: String?
        let vpnSites: String?
    }

    private var connectionRequest: ConnectionRequest? {
        guard let profile = selectedProfile else { return nil }
        let only = preferences.splitMode == .only
        return ConnectionRequest(
            profile: profile, directSites: only ? "" : preferences.directSites,
            directRuSites: !only && preferences.directRuSites,
            previousEntryIP: profiles.first(where: { $0.id == selection })?.entryIP,
            vpnSites: only ? preferences.vpnSites : nil
        )
    }

    func connect(allowInstall: Bool = true) {
        guard isIdle, !importBusy, !provisioning, let request = connectionRequest else { return }
        guard let payload = try? JSONEncoder().encode(request) else {
            errorMessage = "Не удалось прочитать выбранный профиль."
            return
        }
        state = internetBlocked ? .reconnecting : .connecting
        activeRequest = request
        preferences.record("Connection requested")
        detail = "Проверяем профиль и соединение с сервером…"
        exitIP = nil
        startBackend(allowInstall ? "connect" : "connect-auto", payload: payload)
    }

    private func startBackend(_ command: String, payload: Data = Data()) {
        let stoppingTerminal = command == "stop-terminal"
        do {
            let connection = command == "connect" || command == "connect-auto"
            let flags = connection && !preferences.killSwitch ? ["--no-kill-switch"] : []
            let (process, input, output) = try Self.makeBackend([command] + flags)
            try process.run()
            backend = process
            worker.async { [weak self] in
                do {
                    try input.fileHandleForWriting.write(contentsOf: payload)
                    try input.fileHandleForWriting.close()
                } catch {
                    if process.isRunning { process.terminate() }
                }
                var pending = Data()
                let decoder = JSONDecoder()
                while true {
                    let data = output.fileHandleForReading.availableData
                    if data.isEmpty { break }
                    pending.append(data)
                    while let end = pending.firstIndex(of: 0x0a) {
                        if let event = try? decoder.decode(BackendEvent.self, from: pending[..<end]) {
                            DispatchQueue.main.async { [weak self] in self?.consume(event) }
                        }
                        pending.removeSubrange(...end)
                    }
                }
                process.waitUntilExit()
                let status = process.terminationStatus
                DispatchQueue.main.async { [weak self] in self?.finish(status, command: command) }
            }
        } catch {
            state = stoppingTerminal ? .terminalConnected : .idle
            detail = stoppingTerminal ? "Не удалось отключить VPN." : "Не удалось запустить VPN."
            errorMessage = (error as? AppError)?.message ?? detail
        }
    }

    func disconnect(keepingProtection: Bool = false) {
        if state == .terminalConnected {
            preferences.record("Terminal VPN stop requested")
            state = .disconnecting
            detail = "Останавливаем VPN, запущенный из Терминала…"
            startBackend("stop-terminal")
            return
        }
        guard let backend, state != .disconnecting else { return }
        let keepProtection = keepingProtection || state == .reconnecting
        preferences.record("Disconnection requested")
        state = .disconnecting
        detail = "Останавливаем системный туннель…"
        if backend.isRunning {
            if keepProtection { backend.interrupt() }
            else { backend.terminate() }
        }
    }

    func quit(afterDisconnect completion: @escaping () -> Void) {
        quitCompletion = completion
        disconnect(keepingProtection: restartingForUpdate)
    }

    func restartForUpdate(_ staging: URL) throws {
        guard !provisioning, !importBusy, state != .disconnecting else {
            throw AppError(message: "Дождитесь завершения текущего действия и повторите обновление.")
        }
        let resume = isRunning && !isIdle
        let installer = AppPreferences.installer(staging, [
            "install", Bundle.main.bundleURL.resolvingSymlinksInPath().path,
            String(ProcessInfo.processInfo.processIdentifier), resume ? "resume" : "idle",
        ])
        try installer.run()
        restartingForUpdate = true
        NSApp.terminate(nil)
    }

    private func consume(_ event: BackendEvent) {
        switch event.kind {
        case "progress":
            if state != .disconnecting { detail = event.message }
        case "reconnecting":
            guard state != .disconnecting else { return }
            state = .reconnecting
            detail = event.message
        case "connected":
            guard state != .disconnecting else { return }
            state = .connected
            internetBlocked = false
            exitIP = event.message
            rememberRoute(entryIP: event.entryIP, exitIP: event.message)
            detail = "Системный VPN активен."
            preferences.record("VPN connected")
        case "disconnected":
            detail = event.message
            preferences.record("VPN disconnected")
        case "error":
            detail = event.message
            preferences.record("VPN operation failed")
        default:
            break
        }
    }

    private func rememberRoute(entryIP: String?, exitIP: String) {
        guard let index = profiles.firstIndex(where: { $0.id == selection }) else { return }
        var entries = profiles
        let updatedEntryIP = entryIP ?? entries[index].entryIP
        guard entries[index].entryIP != updatedEntryIP || entries[index].exitIP != exitIP else { return }
        entries[index].entryIP = updatedEntryIP
        entries[index].exitIP = exitIP
        profiles = entries
        do { try save(entries) }
        catch { preferences.record("Could not save the last successful profile route") }
    }

    private func finish(_ status: Int32, command: String) {
        let stoppingTerminal = command == "stop-terminal"
        if command == "release-protection" && status == 0 { internetBlocked = false }
        if state == .disconnecting && status == 0 && command != "release-protection" { detail = "VPN отключён." }
        if status != 0 && detail.hasSuffix("…") {
            detail = "Подключение остановилось."
        }
        backend = nil
        activeRequest = nil
        exitIP = nil
        state = stoppingTerminal && status != 0 ? .terminalConnected : .idle
        let completion = quitCompletion
        quitCompletion = nil
        completion?()
        refreshTerminal(refreshIP: true)
    }

    static func makeBackend(_ arguments: [String], resource: String = "backend") throws -> (Process, Pipe, Pipe) {
        guard let script = Bundle.main.url(forResource: resource, withExtension: "py") else {
            throw AppError(message: "Файлы приложения не найдены. Пересоберите Qosmos VPN.")
        }
        let process = Process()
        let input = Pipe()
        let output = Pipe()
        let bundledPython = script.deletingLastPathComponent().appendingPathComponent("python/bin/python3")
        process.executableURL = FileManager.default.isExecutableFile(atPath: bundledPython.path)
            ? bundledPython : URL(fileURLWithPath: "/usr/bin/python3")
        process.arguments = ["-I", "-B", script.path] + arguments
        process.standardInput = input
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        return (process, input, output)
    }
}

struct VPNView: View {
    private enum Page { case dashboard, profiles, add, paste, setup, edit }

    @ObservedObject var model: VPNModel
    @ObservedObject var preferences: AppPreferences
    @State private var page = Page.dashboard
    @State private var addReturnPage = Page.dashboard
    @State private var pastedText = ""
    @State private var confirmRemoval = false
    @State private var profileName = ""
    @State private var editingID: UUID?

    private let canvas = Color(red: 0.051, green: 0.055, blue: 0.066)
    private let surface = Color(red: 0.091, green: 0.096, blue: 0.110)
    private let ink = Color(red: 0.96, green: 0.95, blue: 0.93)
    private let muted = Color(red: 0.64, green: 0.66, blue: 0.70)
    private let accent = Color(red: 1.0, green: 0.68, blue: 0.46)

    private var connected: Bool { model.isConnected }
    private var busy: Bool {
        model.state == .connecting || model.state == .reconnecting || model.state == .disconnecting
    }

    private var heading: some View {
        HStack(spacing: 11) {
            Image(nsImage: NSApp.applicationIconImage)
                .resizable()
                .frame(width: 42, height: 42)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text("Qosmos VPN")
                    .font(.system(size: 23, weight: .semibold, design: .rounded))
                    .tracking(-0.8)
                Text("v\(AppBuild.version)")
                    .font(.system(size: 11, weight: .medium, design: .monospaced))
                    .foregroundStyle(muted)
            }
            Spacer()
            Button {
                preferences.refreshLoginStatus()
                model.showSettings = true
            } label: {
                Image(systemName: "gearshape")
                    .font(.system(size: 15, weight: .medium))
                    .frame(width: 35, height: 35)
                    .background(surface, in: RoundedRectangle(cornerRadius: 10))
                    .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(.white.opacity(0.10)))
            }
            .buttonStyle(.borderless)
            .accessibilityLabel(preferences.text("Настройки"))
            .help(preferences.text("Настройки"))
            Button { openAdd(from: .dashboard) } label: {
                Image(systemName: "plus")
                    .font(.system(size: 15, weight: .medium))
                    .frame(width: 35, height: 35)
                    .background(surface, in: RoundedRectangle(cornerRadius: 10))
                    .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(.white.opacity(0.10)))
            }
            .buttonStyle(.borderless)
            .accessibilityLabel(preferences.text("Добавить профиль"))
            .help(preferences.text("Добавить профиль"))
            .disabled(!canAdd)
        }
    }

    private var orbit: some View {
        ZStack {
            Circle().strokeBorder(accent.opacity(connected ? 0.22 : 0.12), lineWidth: 1)
                .frame(width: 184, height: 184)
            Circle().strokeBorder(.white.opacity(0.08), style: StrokeStyle(lineWidth: 1, dash: [2, 5]))
                .frame(width: 212, height: 212)
            Circle().fill(accent.opacity(connected ? 0.8 : 0.45))
                .frame(width: 5, height: 5).offset(x: 85, y: -61)
            Circle().fill(.white.opacity(0.32))
                .frame(width: 3, height: 3).offset(x: -93, y: 50)
        }
        .accessibilityHidden(true)
        .allowsHitTesting(false)
    }

    private var connectionControl: some View {
        VStack(spacing: 9) {
            ZStack {
                orbit
                Button(action: model.toggleConnection) {
                    ZStack {
                        Circle().fill(connected ? accent : surface)
                        Circle().strokeBorder(connected ? .white.opacity(0.12) : accent.opacity(0.42))
                        if busy {
                            ProgressView()
                                .tint(connected ? canvas : accent)
                                .controlSize(.regular)
                        } else {
                            Image(systemName: "power")
                                .font(.system(size: 41, weight: .light))
                                .foregroundStyle(connected ? canvas : accent)
                        }
                    }
                    .frame(width: 138, height: 138)
                    .contentShape(Circle())
                }
                .buttonStyle(OrbitButtonStyle())
                .accessibilityLabel(preferences.text(model.actionLabel))
                .help(preferences.text(model.actionLabel))
                .disabled(!model.canToggle)
            }
            .frame(height: 218)

            Text(preferences.text(model.stateLabel))
                .font(.system(size: 25, weight: .semibold, design: .rounded))
                .tracking(-0.7)
                .foregroundStyle(connected ? accent : ink)
            Text(preferences.text(model.detail))
                .font(.system(size: 12))
                .foregroundStyle(muted)
                .multilineTextAlignment(.center)
                .frame(minHeight: 34, alignment: .top)
                .fixedSize(horizontal: false, vertical: true)
            if model.state == .connected {
                Button(preferences.text("Переподключить"), action: model.reconnectWithCurrentSettings)
                    .buttonStyle(.link)
            } else if model.isIdle && model.internetBlocked {
                Button(preferences.text("Вернуть доступ"), action: model.restoreInternet)
                    .buttonStyle(.link)
            }
        }
        .frame(maxWidth: .infinity)
        .animation(.easeOut(duration: 0.18), value: connected)
    }

    private var address: some View {
        HStack(spacing: 10) {
            Image(systemName: "globe.europe.africa")
                .font(.system(size: 15, weight: .medium))
                .foregroundStyle(accent)
                .accessibilityHidden(true)
            Text(preferences.text(model.showsVPNExitIP ? "IP выхода VPN" : "Ваш IP"))
                .font(.system(size: 13, weight: .medium))
                .foregroundStyle(muted)
            Spacer()
            Text(model.exitIP ?? (model.checkingIP ? preferences.text("Определяем…") : "—"))
                .font(.system(size: 14, weight: .medium, design: .monospaced))
                .foregroundStyle(model.exitIP == nil ? muted : ink)
                .textSelection(.enabled)
            Button(action: model.refreshPublicIP) {
                Image(systemName: "arrow.clockwise")
                    .font(.system(size: 13, weight: .medium))
                    .frame(width: 26, height: 26)
                    .contentShape(Rectangle())
            }
            .buttonStyle(.borderless)
            .foregroundStyle(muted)
            .help(preferences.text("Обновить IP"))
            .accessibilityLabel(preferences.text("Обновить IP"))
            .disabled(busy || model.checkingIP || model.showsVPNExitIP)
        }
        .padding(.leading, 14)
        .padding(.trailing, 8)
        .padding(.vertical, 8)
        .background(surface, in: RoundedRectangle(cornerRadius: 11))
    }

    private var canAdd: Bool { model.isIdle && !model.importBusy && !model.provisioning }

    private var profileControls: some View {
        Button {
            page = model.profiles.isEmpty ? .add : .profiles
            if model.profiles.isEmpty { addReturnPage = .dashboard }
        } label: {
            HStack(spacing: 12) {
                tileIcon("point.3.connected.trianglepath.dotted")
                VStack(alignment: .leading, spacing: 5) {
                    Text(preferences.text("Профиль")).font(.system(size: 11, weight: .medium))
                        .foregroundStyle(muted)
                    if let profile = model.selectedProfile {
                        Text(profile.name).font(.system(size: 14, weight: .semibold)).lineLimit(1)
                        Text(profile.endpoint).font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(muted).lineLimit(1)
                    } else {
                        Text(preferences.text("Добавьте профиль VLESS Reality"))
                            .font(.system(size: 13, weight: .medium))
                    }
                }
                Spacer(minLength: 6)
                Image(systemName: "chevron.right")
                    .font(.system(size: 12, weight: .semibold)).foregroundStyle(muted)
            }
            .padding(13)
            .background(surface, in: RoundedRectangle(cornerRadius: 13))
            .overlay(RoundedRectangle(cornerRadius: 13).strokeBorder(.white.opacity(0.08)))
        }
        .buttonStyle(.plain)
        .help(preferences.text(model.profiles.isEmpty ? "Добавить профиль" : "Выбрать профиль"))
        .disabled(model.profiles.isEmpty && !canAdd)
    }

    private func tileIcon(_ name: String) -> some View {
        Image(systemName: name)
            .font(.system(size: 16, weight: .medium))
            .foregroundStyle(accent)
            .frame(width: 34, height: 34)
            .background(accent.opacity(0.10), in: RoundedRectangle(cornerRadius: 8))
            .accessibilityHidden(true)
    }

    private func pageHeader(_ title: String, back: Page, canGoBack: Bool = true, add: Bool = false) -> some View {
        HStack(spacing: 12) {
            Button { page = back } label: {
                Image(systemName: "chevron.left").font(.system(size: 14, weight: .semibold))
                    .frame(width: 32, height: 32)
            }
            .buttonStyle(.borderless)
            .accessibilityLabel(preferences.text("Назад"))
            .disabled(!canGoBack)
            Text(preferences.text(title)).font(.system(size: 22, weight: .semibold, design: .rounded))
                .accessibilityAddTraits(.isHeader)
            Spacer()
            if add {
                Button { openAdd(from: .profiles) } label: {
                    Image(systemName: "plus").frame(width: 32, height: 32)
                }
                .buttonStyle(.borderless)
                .accessibilityLabel(preferences.text("Добавить профиль"))
                .disabled(!canAdd)
            }
        }
        .padding(.bottom, 4)
    }

    private func addOption(_ title: String, _ description: String, icon: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(spacing: 12) {
                tileIcon(icon)
                VStack(alignment: .leading, spacing: 4) {
                    Text(preferences.text(title)).font(.system(size: 14, weight: .semibold))
                    Text(preferences.text(description)).font(.system(size: 12)).foregroundStyle(muted)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 8)
                Image(systemName: "chevron.right").font(.system(size: 11, weight: .semibold)).foregroundStyle(muted)
            }
            .padding(13)
            .background(surface, in: RoundedRectangle(cornerRadius: 12))
            .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(.white.opacity(0.08)))
        }
        .buttonStyle(.plain)
        .disabled(!canAdd)
    }

    private var addPage: some View {
        VStack(alignment: .leading, spacing: 12) {
            pageHeader("Добавить профиль", back: addReturnPage, canGoBack: !model.importBusy)
            addOption("Настроить свой сервер", "Установить VPN на один VPS или настроить вход и выход.", icon: "server.rack") {
                page = .setup
            }
            addOption("Вставить ссылку", "Добавить готовый профиль по ссылке vless://.", icon: "link") {
                pastedText = NSPasteboard.general.string(forType: .string) ?? ""
                page = .paste
            }
            addOption("Импортировать файл", "Открыть файл со ссылками или конфигурацией Xray.", icon: "doc.badge.plus") {
                chooseFile()
            }
            if model.importBusy { importProgress }
            Spacer()
        }
    }

    private var importProgress: some View {
        HStack(spacing: 8) {
            ProgressView().controlSize(.small)
            Text(preferences.text("Импортируем…")).foregroundStyle(muted)
        }
    }

    private var pastePage: some View {
        VStack(alignment: .leading, spacing: 14) {
            pageHeader("Вставить ссылку", back: .add, canGoBack: !model.importBusy)
            Text(preferences.text("Вставьте ссылку vless:// или несколько ссылок, по одной на строку."))
                .foregroundStyle(muted)
            TextEditor(text: $pastedText)
                .font(.system(.body, design: .monospaced))
                .scrollContentBackground(.hidden)
                .padding(8)
                .background(surface, in: RoundedRectangle(cornerRadius: 12))
                .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(.white.opacity(0.1)))
                .frame(height: 200)
                .accessibilityLabel(preferences.text("Вставить ссылку"))
                .disabled(model.importBusy)
            HStack {
                if model.importBusy { importProgress }
                Spacer()
                Button(preferences.text("Импортировать")) {
                    model.importText(pastedText, onSuccess: finishImport)
                }
                .buttonStyle(.borderedProminent)
                .keyboardShortcut(.defaultAction)
                .disabled(!canAdd || pastedText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
            Spacer()
        }
    }

    private var profilesPage: some View {
        VStack(alignment: .leading, spacing: 12) {
            pageHeader("Профили", back: .dashboard, add: true)
            if model.profiles.isEmpty {
                Text(preferences.text("Добавьте профиль VLESS Reality")).foregroundStyle(muted)
            } else if !model.isIdle {
                Text(preferences.text("Чтобы сменить профиль, сначала отключите VPN."))
                    .font(.system(size: 12)).foregroundStyle(muted)
            }
            ScrollView {
                LazyVStack(spacing: 9) {
                    ForEach(model.profiles) { entry in profileRow(entry) }
                }
                .padding(.bottom, 4)
            }
        }
    }

    private func profileRow(_ entry: SavedProfile) -> some View {
        let selected = model.selection == entry.id
        return HStack(alignment: .top, spacing: 8) {
            Button {
                model.select(entry.id)
                page = .dashboard
            } label: {
                HStack(alignment: .top, spacing: 11) {
                    Image(systemName: selected ? "checkmark.circle.fill" : "circle")
                        .font(.system(size: 17)).foregroundStyle(selected ? accent : muted)
                        .padding(.top, 1)
                        .accessibilityHidden(true)
                    VStack(alignment: .leading, spacing: 7) {
                        Text(entry.profile.name)
                            .font(.system(size: 14, weight: .semibold))
                            .fixedSize(horizontal: false, vertical: true)
                        profileRoute(entry)
                    }
                    Spacer(minLength: 0)
                }
                .padding(.vertical, 12)
                .padding(.leading, 12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityAddTraits(selected ? .isSelected : [])
            .disabled(!canAdd)
            Button {
                editingID = entry.id
                profileName = entry.profile.name
                confirmRemoval = false
                page = .edit
            } label: {
                Image(systemName: "pencil")
                    .font(.system(size: 13, weight: .medium))
                    .foregroundStyle(muted)
                    .frame(width: 30, height: 30)
                    .background(.white.opacity(0.05), in: RoundedRectangle(cornerRadius: 7))
            }
            .buttonStyle(.borderless)
            .help(preferences.text("Редактировать профиль"))
            .accessibilityLabel(preferences.text("Редактировать профиль") + ": " + entry.profile.name)
            .padding(.top, 8)
            .padding(.trailing, 8)
        }
        .background(selected ? accent.opacity(0.07) : surface, in: RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(selected ? accent.opacity(0.42) : .white.opacity(0.08)))
    }

    private func profileRoute(_ entry: SavedProfile) -> some View {
        let entryIP = entry.entryIP ?? (entry.profile.entryIsIPAddress ? entry.profile.entryHost : nil)
        let direct = entry.profile.sshUser == nil && entry.profile.cloudflareHost == nil
        let configuredExit = direct && entry.profile.entryIsIPAddress ? entry.profile.entryHost : nil
        return Grid(alignment: .leading, horizontalSpacing: 8, verticalSpacing: 3) {
            routeLine("Вход", value: entryIP ?? entry.profile.entryHost, isIP: entryIP != nil)
            routeLine("Выход", value: entry.exitIP ?? configuredExit ?? preferences.text("После подключения"),
                      isIP: entry.exitIP != nil || configuredExit != nil)
        }
    }

    private func routeLine(_ title: String, value: String, isIP: Bool) -> some View {
        GridRow {
            Text(preferences.text(title)).foregroundStyle(muted)
            Text(value)
                .font(isIP ? .system(size: 11, weight: .medium, design: .monospaced) : .system(size: 11))
                .foregroundStyle(isIP ? ink : muted)
                .lineLimit(1)
                .truncationMode(.middle)
                .help(value)
        }
        .font(.system(size: 11))
    }

    private var editPage: some View {
        VStack(alignment: .leading, spacing: 14) {
            pageHeader("Редактировать профиль", back: .profiles)
            if let id = editingID, let entry = model.profiles.first(where: { $0.id == id }) {
                TextField(preferences.text("Название профиля"), text: $profileName)
                    .textFieldStyle(.roundedBorder)
                profileRoute(entry).padding(.bottom, 6)
                HStack {
                    Spacer()
                    Button(preferences.text("Сохранить")) {
                        if model.renameProfile(id, to: profileName) { page = .profiles }
                    }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
                    .disabled(VPNModel.normalizedProfileName(profileName) == nil || confirmRemoval)
                }
                Divider()
                if confirmRemoval {
                    Text(preferences.text("Удалить этот профиль?"))
                    HStack {
                        Button(preferences.text("Отмена")) { confirmRemoval = false }
                        Button(preferences.text("Удалить"), role: .destructive) {
                            model.removeProfile(id)
                            if !model.profiles.contains(where: { $0.id == id }) { page = .profiles }
                        }
                        .tint(.red)
                        .disabled(!canAdd)
                    }
                } else {
                    Button(preferences.text("Удалить профиль"), role: .destructive) { confirmRemoval = true }
                        .foregroundStyle(.red)
                        .disabled(!canAdd)
                }
            }
            Spacer()
        }
    }

    private func openAdd(from origin: Page) {
        addReturnPage = origin
        page = .add
    }

    private func finishImport() {
        pastedText = ""
        page = .profiles
    }

    private func subpage<Content: View>(_ content: Content) -> some View {
        content
            .padding(.horizontal, 24)
            .padding(.top, 18)
            .padding(.bottom, 24)
            .frame(width: 430, height: 540, alignment: .topLeading)
            .foregroundStyle(ink)
            .tint(accent)
            .background(canvas)
    }

    private var dashboard: some View {
        VStack(alignment: .leading, spacing: 16) {
            heading
            connectionControl
            address
            profileControls
        }
        .padding(.horizontal, 24)
        .padding(.top, 18)
        .padding(.bottom, 24)
        .frame(width: 430)
        .foregroundStyle(ink)
        .background(canvas)
    }

    var body: some View {
        Group {
            if model.showSettings {
                QosmosSettingsView(model: model, preferences: preferences)
            } else {
                switch page {
                case .dashboard: dashboard
                case .profiles: subpage(profilesPage)
                case .add: subpage(addPage)
                case .paste: subpage(pastePage)
                case .setup:
                    ServerSetupView(model: model) { saved in page = saved ? .profiles : .add }
                        .frame(width: 430, height: 540)
                        .foregroundStyle(ink)
                        .background(canvas)
                case .edit: subpage(editPage)
                }
            }
        }
        .preferredColorScheme(.dark)
        .alert("Qosmos VPN", isPresented: Binding(
            get: { model.errorMessage != nil },
            set: { if !$0 { model.errorMessage = nil } }
        )) {
            Button("OK") { model.errorMessage = nil }
        } message: {
            Text(preferences.text(model.errorMessage ?? ""))
        }
    }

    private func chooseFile() {
        let panel = NSOpenPanel()
        panel.prompt = preferences.text("Импортировать")
        panel.allowedContentTypes = [.plainText, .json]
        panel.allowsOtherFileTypes = true
        panel.canChooseDirectories = false
        if panel.runModal() == .OK, let file = panel.url { model.importFile(file, onSuccess: finishImport) }
    }
}

private struct OrbitButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        Interaction(configuration: configuration)
    }

    private struct Interaction: View {
        let configuration: Configuration
        @Environment(\.isEnabled) private var enabled
        @Environment(\.accessibilityReduceMotion) private var reduceMotion
        @State private var hovering = false

        var body: some View {
            configuration.label
                .opacity(enabled ? 1 : 0.56)
                .brightness(enabled && hovering ? 0.035 : 0)
                .scaleEffect(configuration.isPressed ? 0.96 : 1)
                .onHover { hovering = $0 }
                .animation(reduceMotion ? nil : .easeOut(duration: 0.14), value: configuration.isPressed)
                .animation(reduceMotion ? nil : .easeOut(duration: 0.14), value: hovering)
        }
    }
}

final class VPNDelegate: NSObject, NSApplicationDelegate {
    let model = VPNModel()
    private var terminalMonitor: Timer?

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.appearance = NSAppearance(named: .darkAqua)
        let launchEvent = NSAppleEventManager.shared().currentAppleEvent
        let hasLoginMarker = launchEvent?.eventID == AEEventID(kAEOpenApplication)
            && launchEvent?.paramDescriptor(forKeyword: AEKeyword(keyAEPropData))?.enumCodeValue
                == AEKeyword(keyAELaunchedAsLogInItem)
        // SMAppService can launch the app without sending an open-application event.
        let loginLaunch = hasLoginMarker || (launchEvent == nil && model.preferences.loginStatus == .enabled)
        let args = ProcessInfo.processInfo.arguments
        if let index = args.firstIndex(of: "--import"), args.indices.contains(index + 1) {
            model.importFile(URL(fileURLWithPath: args[index + 1]))
        }
        let updateLaunch = args.contains("--update-installed") || args.contains("--update-failed")
        if args.contains("--update-failed") {
            model.errorMessage = "Не удалось установить обновление. Запущена предыдущая версия."
        }
        model.prepareLaunch(resumeAfterUpdate: args.contains("--resume-after-update"))
        NSWorkspace.shared.notificationCenter.addObserver(
            self, selector: #selector(didWake), name: NSWorkspace.didWakeNotification, object: nil
        )
        terminalMonitor = Timer.scheduledTimer(withTimeInterval: 3, repeats: true) { [weak self] _ in
            self?.model.refreshTerminal()
        }
        if !updateLaunch && loginLaunch && model.preferences.loginRegistered && model.preferences.launchMinimized {
            DispatchQueue.main.async { NSApp.hide(nil) }
        } else {
            NSApp.activate(ignoringOtherApps: true)
        }
    }

    func applicationDidBecomeActive(_ notification: Notification) {
        model.preferences.refreshLoginStatus()
        if model.state == .connected { model.refreshPublicIP() }
        else { model.refreshTerminal(refreshIP: true) }
    }

    @objc private func didWake(_ notification: Notification) { model.reconnect() }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        if model.provisioning { return .terminateCancel }
        guard model.isRunning else { return .terminateNow }
        model.quit(afterDisconnect: { sender.reply(toApplicationShouldTerminate: true) })
        return .terminateLater
    }
}

private struct VPNMenu: View {
    @ObservedObject var model: VPNModel
    @ObservedObject var preferences: AppPreferences
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Text("Qosmos VPN v\(AppBuild.version)")
        Text(preferences.text(model.stateLabel))
        if let ip = model.exitIP {
            Text("\(preferences.text(model.showsVPNExitIP ? "IP выхода VPN" : "Ваш IP"))  \(ip)")
        }
        Divider()
        Button(preferences.text(model.actionLabel), action: model.toggleConnection)
            .disabled(!model.canToggle)
        if model.state == .connected {
            Button(preferences.text("Переподключить"), action: model.reconnectWithCurrentSettings)
        } else if model.isIdle && model.internetBlocked {
            Button(preferences.text("Вернуть доступ"), action: model.restoreInternet)
        }
        Button(preferences.text("Открыть Qosmos VPN")) { showWindow(settings: false) }
        Button(preferences.text("Настройки…")) { showWindow(settings: true) }
        Divider()
        Button(preferences.text("Выйти из Qosmos VPN")) { NSApp.terminate(nil) }
    }

    private func showWindow(settings: Bool) {
        model.showSettings = settings
        preferences.refreshLoginStatus()
        NSApp.unhide(nil)
        NSApp.activate(ignoringOtherApps: true)
        openWindow(id: "main")
    }
}

private struct VPNMenuIcon: View {
    @ObservedObject var model: VPNModel

    var body: some View {
        Image(nsImage: Self.symbol(connected: model.isConnected, blocked: model.internetBlocked))
            .accessibilityLabel("Qosmos VPN")
    }

    private static func symbol(connected: Bool, blocked: Bool) -> NSImage {
        let icon = NSImage(size: NSSize(width: 24, height: 20), flipped: false) { _ in
            NSColor.black.set()
            let ring = NSBezierPath(ovalIn: NSRect(x: 1.75, y: 2.5, width: 15, height: 15))
            ring.lineWidth = 2.8
            ring.stroke()
            let tail = NSBezierPath()
            tail.move(to: NSPoint(x: 11, y: 6.5))
            tail.line(to: NSPoint(x: 18, y: 1.5))
            tail.lineWidth = 2.8
            tail.lineCapStyle = .round
            tail.stroke()
            if blocked {
                let mark = NSBezierPath(roundedRect: NSRect(x: 20, y: 7.5, width: 2.5, height: 8), xRadius: 1, yRadius: 1)
                mark.fill()
                NSBezierPath(ovalIn: NSRect(x: 20, y: 3.25, width: 2.5, height: 2.5)).fill()
            } else if connected {
                NSBezierPath(ovalIn: NSRect(x: 19.25, y: 12.5, width: 4.25, height: 4.25)).fill()
            }
            return true
        }
        icon.isTemplate = true
        return icon
    }
}

@main
struct VlessVPN: App {
    @NSApplicationDelegateAdaptor(VPNDelegate.self) private var delegate

    init() {
        umask(0o077)
    }

    var body: some Scene {
        Window("Qosmos VPN", id: "main") {
            VPNView(model: delegate.model, preferences: delegate.model.preferences)
        }
        .windowResizability(.contentSize)
        MenuBarExtra {
            VPNMenu(model: delegate.model, preferences: delegate.model.preferences)
        } label: {
            VPNMenuIcon(model: delegate.model)
        }
        .menuBarExtraStyle(.menu)
    }
}
