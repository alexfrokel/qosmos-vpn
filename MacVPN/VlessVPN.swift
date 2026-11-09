import AppKit
import CoreServices
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

    var endpoint: String {
        let address = host.contains(":") ? "[\(host)]" : host
        return "\(address):\(port)"
    }
}

struct SavedProfile: Codable, Identifiable {
    var id = UUID()
    var profile: Profile
}

struct BackendEvent: Decodable {
    let kind: String
    let message: String
}

struct AppError: LocalizedError {
    let message: String
    var errorDescription: String? { message }
}

final class VPNModel: ObservableObject {
    enum State {
        case idle, connecting, connected, terminalConnected, disconnecting
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
    @Published var errorMessage: String?
    @Published var showSettings = false

    let preferences: AppPreferences
    private var backend: Process?
    private var terminalCheckPending = false
    private var autoConnectPending = false
    private var ipCheckID: UUID?
    private var quitCompletion: (() -> Void)?
    private let storage: URL
    private let defaults: UserDefaults
    private let worker = DispatchQueue(label: "local.vlessvpn.backend", qos: .userInitiated)

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
    var canToggle: Bool {
        state != .disconnecting && !importBusy && (!isIdle || internetBlocked || selectedProfile != nil)
    }
    var stateLabel: String {
        switch state {
        case .idle: return internetBlocked ? "Интернет заблокирован" : "Отключено"
        case .connecting: return "Подключение"
        case .connected, .terminalConnected: return "Подключено"
        case .disconnecting: return "Отключение"
        }
    }
    var actionLabel: String { isIdle ? (internetBlocked ? "Вернуть доступ" : "Подключить") : "Отключить" }

    func toggleConnection() {
        guard canToggle else { return }
        if isIdle && internetBlocked {
            state = .disconnecting
            startBackend("release-protection")
        } else if isIdle {
            connect()
        } else {
            disconnect()
        }
    }

    func prepareLaunch() {
        autoConnectPending = preferences.autoConnect
        if preferences.autoUpdates { preferences.checkForUpdates() }
        preferences.record("Application launched")
        refreshTerminal()
        refreshPublicIP()
    }

    func refreshPublicIP() {
        guard state != .connecting, state != .disconnecting, !internetBlocked, !checkingIP else { return }
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

    func refreshTerminal() {
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
                if blocked != self.internetBlocked {
                    self.internetBlocked = blocked
                    if blocked {
                        self.exitIP = nil
                        self.ipCheckID = nil
                        self.checkingIP = false
                    } else {
                        self.refreshPublicIP()
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
                    if !active && !blocked && self.isIdle { self.connect(allowInstall: false) }
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

    func importFile(_ url: URL) {
        do {
            let size = try url.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0
            guard size <= 1_048_576 else { throw AppError(message: "Файл профилей больше 1 МБ.") }
            let content = try String(contentsOf: url, encoding: .utf8)
            importText(content, name: url.deletingPathExtension().lastPathComponent)
        } catch {
            errorMessage = (error as? AppError)?.message ?? "Не удалось прочитать файл в формате UTF-8."
        }
    }

    func importText(_ text: String, name: String = "") {
        guard !importBusy, isIdle else { return }
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
                    self?.storeImports(imported)
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

    private func storeImports(_ imported: [Profile]) {
        defer {
            importBusy = false
            if autoConnectPending { refreshTerminal() }
        }
        var entries = profiles
        var firstID: UUID?
        for profile in imported {
            let entry = entries.first { entry in
                var candidate = profile
                candidate.name = entry.profile.name
                return entry.profile == candidate
            } ?? SavedProfile(profile: profile)
            if !entries.contains(where: { $0.id == entry.id }) { entries.append(entry) }
            if firstID == nil { firstID = entry.id }
        }
        do {
            try save(entries)
            profiles = entries
            select(firstID)
            detail = "Профиль готов к подключению."
        } catch {
            errorMessage = "Не удалось сохранить профили на Mac."
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

    func removeSelection() {
        guard isIdle, let selection else { return }
        let remaining = profiles.filter { $0.id != selection }
        do {
            try save(remaining)
            profiles = remaining
            select(remaining.first?.id)
        } catch {
            errorMessage = "Не удалось удалить профиль."
        }
    }

    func connect(allowInstall: Bool = true) {
        guard isIdle, !importBusy, let profile = selectedProfile else { return }
        guard let payload = try? JSONEncoder().encode(profile) else {
            errorMessage = "Не удалось прочитать выбранный профиль."
            return
        }
        state = .connecting
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

    func disconnect() {
        if state == .terminalConnected {
            preferences.record("Terminal VPN stop requested")
            state = .disconnecting
            detail = "Останавливаем VPN, запущенный из Терминала…"
            startBackend("stop-terminal")
            return
        }
        guard let backend, state != .disconnecting else { return }
        preferences.record("Disconnection requested")
        state = .disconnecting
        detail = "Останавливаем системный туннель…"
        if backend.isRunning { backend.terminate() }
    }

    func quit(afterDisconnect completion: @escaping () -> Void) {
        quitCompletion = completion
        disconnect()
    }

    private func consume(_ event: BackendEvent) {
        switch event.kind {
        case "progress":
            if state != .disconnecting { detail = event.message }
        case "connected":
            guard state != .disconnecting else { return }
            state = .connected
            internetBlocked = false
            exitIP = event.message
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

    private func finish(_ status: Int32, command: String) {
        let stoppingTerminal = command == "stop-terminal"
        if command == "release-protection" && status == 0 { internetBlocked = false }
        if state == .disconnecting && status == 0 && command != "release-protection" { detail = "VPN отключён." }
        if status != 0 && detail.hasSuffix("…") {
            detail = "Подключение остановилось."
        }
        backend = nil
        exitIP = nil
        state = stoppingTerminal && status != 0 ? .terminalConnected : .idle
        let completion = quitCompletion
        quitCompletion = nil
        completion?()
        refreshTerminal()
        refreshPublicIP()
    }

    private static func makeBackend(_ arguments: [String]) throws -> (Process, Pipe, Pipe) {
        guard let script = Bundle.main.url(forResource: "backend", withExtension: "py") else {
            throw AppError(message: "Файлы приложения не найдены. Пересоберите Qosmos VPN.")
        }
        let process = Process()
        let input = Pipe()
        let output = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        process.arguments = ["-B", script.path] + arguments
        process.standardInput = input
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        return (process, input, output)
    }
}

struct VPNView: View {
    @ObservedObject var model: VPNModel
    @ObservedObject var preferences: AppPreferences
    @State private var pasteOpen = false
    @State private var pastedText = ""
    @State private var confirmRemoval = false
    @State private var renameOpen = false
    @State private var profileName = ""
    @State private var renameID: UUID?

    private let canvas = Color(red: 0.051, green: 0.055, blue: 0.066)
    private let surface = Color(red: 0.091, green: 0.096, blue: 0.110)
    private let ink = Color(red: 0.96, green: 0.95, blue: 0.93)
    private let muted = Color(red: 0.64, green: 0.66, blue: 0.70)
    private let accent = Color(red: 1.0, green: 0.68, blue: 0.46)

    private var connected: Bool { model.isConnected }
    private var busy: Bool { model.state == .connecting || model.state == .disconnecting }

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
            Menu {
                Button(action: chooseFile) {
                    Label(preferences.text("Импорт файла…"), systemImage: "doc.badge.plus")
                }
                Button {
                    pastedText = NSPasteboard.general.string(forType: .string) ?? ""
                    pasteOpen = true
                } label: {
                    Label(preferences.text("Вставить ссылку…"), systemImage: "link")
                }
            } label: {
                Image(systemName: "plus")
                    .font(.system(size: 15, weight: .medium))
                    .frame(width: 35, height: 35)
                    .background(surface, in: RoundedRectangle(cornerRadius: 10))
                    .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(.white.opacity(0.10)))
            }
            .menuStyle(.borderlessButton)
            .menuIndicator(.hidden)
            .fixedSize()
            .accessibilityLabel(preferences.text("Добавить профиль"))
            .help(preferences.text("Добавить профиль"))
            .disabled(!model.isIdle || model.importBusy)
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
            Text(preferences.text("Ваш IP"))
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
            .disabled(busy || model.checkingIP)
        }
        .padding(.leading, 14)
        .padding(.trailing, 8)
        .padding(.vertical, 8)
        .background(surface, in: RoundedRectangle(cornerRadius: 11))
    }

    private var profileControls: some View {
        HStack(spacing: 12) {
            Image(systemName: "point.3.connected.trianglepath.dotted")
                .font(.system(size: 18, weight: .medium))
                .foregroundStyle(accent)
                .frame(width: 34, height: 34)
                .background(accent.opacity(0.10), in: RoundedRectangle(cornerRadius: 8))
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 5) {
                Text(preferences.text("Профиль"))
                    .font(.system(size: 11, weight: .medium))
                    .foregroundStyle(muted)
                if let profile = model.selectedProfile {
                    Text(profile.name)
                        .font(.system(size: 14, weight: .semibold))
                        .lineLimit(1)
                    Text(profile.endpoint)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(muted)
                        .textSelection(.enabled)
                } else {
                    Text(preferences.text(model.importBusy ? "Импортируем…" : "Добавьте профиль VLESS Reality"))
                        .font(.system(size: 13, weight: .medium))
                }
            }
            Spacer(minLength: 6)
            if let selectedID = model.selection, let selected = model.selectedProfile {
                Menu {
                    ForEach(model.profiles) { entry in
                        Button {
                            model.select(entry.id)
                        } label: {
                            if model.selection == entry.id {
                                Label(entry.profile.name, systemImage: "checkmark")
                            } else {
                                Text(entry.profile.name)
                            }
                        }
                        .disabled(!model.isIdle)
                    }
                    Divider()
                    Button(preferences.text("Переименовать профиль…")) {
                        renameID = selectedID
                        profileName = selected.name
                        renameOpen = true
                    }
                    Button(preferences.text("Удалить выбранный профиль…"), role: .destructive) {
                        confirmRemoval = true
                    }
                    .disabled(!model.isIdle)
                } label: {
                    Image(systemName: "chevron.up.chevron.down")
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundStyle(muted)
                        .frame(width: 32, height: 32)
                        .background(.white.opacity(0.05), in: RoundedRectangle(cornerRadius: 8))
                }
                .menuStyle(.borderlessButton)
                .menuIndicator(.hidden)
                .fixedSize()
                .accessibilityLabel(preferences.text("Выбрать профиль"))
                .help(preferences.text("Выбрать профиль"))
                .disabled(model.importBusy)
            }
        }
        .padding(13)
        .background(surface, in: RoundedRectangle(cornerRadius: 13))
        .overlay(RoundedRectangle(cornerRadius: 13).strokeBorder(.white.opacity(0.08)))
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
                dashboard
            }
        }
        .preferredColorScheme(.dark)
        .sheet(isPresented: $renameOpen) {
            VStack(alignment: .leading, spacing: 14) {
                Text(preferences.text("Переименовать профиль")).font(.headline)
                TextField(preferences.text("Название профиля"), text: $profileName)
                    .textFieldStyle(.roundedBorder)
                HStack {
                    Spacer()
                    Button(preferences.text("Отмена"), role: .cancel) { renameOpen = false }
                    Button(preferences.text("Сохранить")) {
                        if let id = renameID, model.renameProfile(id, to: profileName) { renameOpen = false }
                    }
                    .keyboardShortcut(.defaultAction)
                    .disabled(VPNModel.normalizedProfileName(profileName) == nil)
                }
            }
            .padding(22).frame(width: 400)
        }
        .sheet(isPresented: $pasteOpen) {
            VStack(alignment: .leading, spacing: 14) {
                Text(preferences.text("Импорт VLESS Reality")).font(.headline)
                Text(preferences.text("Вставьте ссылку vless:// или несколько ссылок, по одной на строку."))
                    .foregroundStyle(.secondary)
                TextEditor(text: $pastedText).font(.system(.body, design: .monospaced))
                    .frame(minHeight: 112)
                    .border(.secondary.opacity(0.3))
                HStack {
                    Spacer()
                    Button(preferences.text("Отмена"), role: .cancel) { pasteOpen = false }
                    Button(preferences.text("Импортировать")) {
                        model.importText(pastedText)
                        pasteOpen = false
                    }
                    .keyboardShortcut(.defaultAction)
                    .disabled(pastedText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
            }
            .padding(22).frame(width: 430)
        }
        .alert(preferences.text("Удалить выбранный профиль?"), isPresented: $confirmRemoval) {
            Button(preferences.text("Удалить"), role: .destructive) { model.removeSelection() }
            Button(preferences.text("Отмена"), role: .cancel) {}
        }
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
        if panel.runModal() == .OK, let file = panel.url { model.importFile(file) }
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
        model.prepareLaunch()
        terminalMonitor = Timer.scheduledTimer(withTimeInterval: 3, repeats: true) { [weak self] _ in
            self?.model.refreshTerminal()
        }
        if loginLaunch && model.preferences.loginRegistered && model.preferences.launchMinimized {
            DispatchQueue.main.async { NSApp.hide(nil) }
        } else {
            NSApp.activate(ignoringOtherApps: true)
        }
    }

    func applicationDidBecomeActive(_ notification: Notification) {
        model.preferences.refreshLoginStatus()
        model.refreshTerminal()
        model.refreshPublicIP()
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
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
            Text("\(preferences.text("Ваш IP"))  \(ip)")
        }
        Divider()
        Button(preferences.text(model.actionLabel), action: model.toggleConnection)
            .disabled(!model.canToggle)
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
