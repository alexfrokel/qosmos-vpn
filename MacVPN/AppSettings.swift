import AppKit
import ServiceManagement
import SwiftUI

enum AppLanguage: String, CaseIterable {
    case russian = "ru"
    case english = "en"
}

enum AppBuild {
    static let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0"
    static let updateSource = Bundle.main.object(forInfoDictionaryKey: "QosmosUpdateSource") as? String ?? ""
}

final class AppPreferences: ObservableObject {
    private let defaults: UserDefaults
    private let directory: URL
    private let service = SMAppService.mainApp
    private var updateTask: URLSessionDataTask?
    private var updateID: UUID?

    @Published var autoConnect: Bool { didSet { defaults.set(autoConnect, forKey: "autoConnect") } }
    @Published var killSwitch: Bool { didSet { defaults.set(killSwitch, forKey: "killSwitch") } }
    @Published var launchMinimized: Bool { didSet { defaults.set(launchMinimized, forKey: "launchMinimized") } }
    @Published var autoUpdates: Bool { didSet { defaults.set(autoUpdates, forKey: "autoUpdates") } }
    @Published var updateSource: String {
        didSet {
            defaults.set(updateSource, forKey: "updateSource")
            updateTask?.cancel()
            updateTask = nil
            updateID = nil
            checkingUpdate = false
            updateMessage = nil
            availableUpdate = nil
        }
    }
    @Published var language: AppLanguage { didSet { defaults.set(language.rawValue, forKey: "uiLanguage") } }
    @Published var logging: Bool {
        didSet {
            defaults.set(logging, forKey: "logging")
            if logging { record("Logging enabled") }
        }
    }
    @Published private(set) var loginStatus: SMAppService.Status = .notRegistered
    @Published private(set) var checkingUpdate = false
    @Published private(set) var updateMessage: String?
    @Published private(set) var availableUpdate: URL?

    init(defaults: UserDefaults = .standard, directory: URL? = nil) {
        self.defaults = defaults
        self.directory = directory ?? FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("VLESS VPN", isDirectory: true)
        autoConnect = defaults.bool(forKey: "autoConnect")
        killSwitch = defaults.object(forKey: "killSwitch") as? Bool ?? true
        launchMinimized = defaults.bool(forKey: "launchMinimized")
        autoUpdates = defaults.object(forKey: "autoUpdates") as? Bool ?? true
        updateSource = defaults.string(forKey: "updateSource").flatMap(Self.httpsURL)?.absoluteString ?? AppBuild.updateSource
        language = AppLanguage(rawValue: defaults.string(forKey: "uiLanguage") ?? "") ?? .russian
        logging = defaults.bool(forKey: "logging")
        refreshLoginStatus()
    }

    private static let english = Bundle.main.path(forResource: "en", ofType: "lproj").flatMap(Bundle.init(path:))

    func text(_ key: String) -> String {
        guard language == .english, let bundle = Self.english else { return key }
        return bundle.localizedString(forKey: key, value: key, table: nil)
    }

    var loginRegistered: Bool { loginStatus == .enabled || loginStatus == .requiresApproval }
    var hasUpdateSource: Bool { Self.httpsURL(updateSource) != nil }
    var logURL: URL { directory.appendingPathComponent("qosmos.log") }

    func refreshLoginStatus() {
        loginStatus = service.status
    }

    func setLaunchAtLogin(_ enabled: Bool) throws {
        defer { refreshLoginStatus() }
        if enabled {
            try service.register()
        } else {
            try service.unregister()
        }
    }

    func openLog() throws {
        if !FileManager.default.fileExists(atPath: logURL.path) {
            try writeLog(Data(), append: false)
        }
        NSWorkspace.shared.open(logURL)
    }

    func record(_ event: String) {
        guard logging else { return }
        let stamp = ISO8601DateFormatter().string(from: Date())
        do {
            try writeLog(Data("\(stamp) \(event)\n".utf8), append: true)
        } catch {
            NSLog("Qosmos VPN could not write its local event log.")
        }
    }

    private func writeLog(_ bytes: Data, append: Bool) throws {
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        let size = (try? logURL.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0
        if append, size < 131_072, FileManager.default.fileExists(atPath: logURL.path) {
            let handle = try FileHandle(forWritingTo: logURL)
            defer { try? handle.close() }
            try handle.seekToEnd()
            try handle.write(contentsOf: bytes)
        } else {
            try bytes.write(to: logURL, options: .atomic)
        }
    }

    func reset() throws {
        if loginRegistered { try setLaunchAtLogin(false) }
        if FileManager.default.fileExists(atPath: logURL.path) {
            try FileManager.default.removeItem(at: logURL)
        }
        autoConnect = false
        killSwitch = true
        launchMinimized = false
        autoUpdates = true
        updateSource = AppBuild.updateSource
        language = .russian
        logging = false
    }

    private struct Release: Decodable {
        let version: String
        let url: String
    }

    private static func httpsURL(_ string: String) -> URL? {
        guard let parts = URLComponents(string: string.trimmingCharacters(in: .whitespacesAndNewlines)),
              parts.scheme?.lowercased() == "https", let host = parts.host, !host.isEmpty,
              parts.user == nil, parts.password == nil else { return nil }
        return parts.url
    }

    func checkForUpdates() {
        guard let url = Self.httpsURL(updateSource), !checkingUpdate else { return }
        checkingUpdate = true
        updateMessage = nil
        availableUpdate = nil
        let checkID = UUID()
        updateID = checkID
        let current = AppBuild.version
        var request = URLRequest(url: url, timeoutInterval: 12)
        request.cachePolicy = .reloadIgnoringLocalCacheData
        let task = URLSession.shared.dataTask(with: request) { [weak self] data, response, _ in
            let release = data.flatMap { $0.count <= 65_536 ? try? JSONDecoder().decode(Release.self, from: $0) : nil }
            let validResponse = (response as? HTTPURLResponse)?.statusCode == 200 && response?.url?.scheme == "https"
            DispatchQueue.main.async { [weak self] in
                guard let self, self.updateID == checkID else { return }
                self.checkingUpdate = false
                self.updateTask = nil
                self.updateID = nil
                guard validResponse, let release, let download = Self.httpsURL(release.url),
                      release.version.range(of: #"^\d+(\.\d+){0,3}$"#, options: .regularExpression) != nil else {
                    self.updateMessage = "Не удалось проверить обновления."
                    return
                }
                if release.version.compare(current, options: .numeric) == .orderedDescending {
                    self.availableUpdate = download
                    self.updateMessage = "Доступна новая версия."
                } else {
                    self.updateMessage = "У вас актуальная версия."
                }
            }
        }
        updateTask = task
        task.resume()
    }
}

struct QosmosSettingsView: View {
    @ObservedObject var model: VPNModel
    @ObservedObject var preferences: AppPreferences
    @State private var confirmReset = false

    var body: some View {
        VStack(alignment: .leading, spacing: 11) {
            HStack(spacing: 12) {
                Button {
                    model.showSettings = false
                } label: {
                    Image(systemName: "chevron.left")
                        .font(.system(size: 14, weight: .semibold))
                        .frame(width: 28, height: 28)
                }
                .buttonStyle(.borderless)
                .accessibilityLabel(preferences.text("Назад"))
                Text(preferences.text("Настройки")).font(.system(size: 23, weight: .semibold, design: .rounded))
            }

            ScrollView {
                VStack(spacing: 0) {
                    row("Автозапуск", "Запускать приложение при входе в macOS") {
                        Toggle(preferences.text("Автозапуск"), isOn: Binding(
                            get: { preferences.loginRegistered },
                            set: { value in
                                do { try preferences.setLaunchAtLogin(value) }
                                catch { model.errorMessage = "Не удалось изменить автозапуск в macOS." }
                            }
                        )).labelsHidden().toggleStyle(.switch)
                    }
                    if preferences.loginStatus == .requiresApproval {
                        Button(preferences.text("Разрешить в настройках macOS")) {
                            SMAppService.openSystemSettingsLoginItems()
                        }
                        .padding(.bottom, 9)
                    }
                    Divider()
                    row("Автоподключение", "Подключать выбранный профиль при запуске после установки службы VPN.") {
                        Toggle(preferences.text("Автоподключение"), isOn: $preferences.autoConnect)
                            .labelsHidden().toggleStyle(.switch)
                    }
                    Divider()
                    row("Kill Switch", "Блокировать интернет при обрыве VPN. Изменение применяется при следующем подключении.") {
                        Toggle("Kill Switch", isOn: $preferences.killSwitch)
                            .labelsHidden().toggleStyle(.switch)
                    }
                    Divider()
                    row("Запускать свёрнутым", "При автозапуске оставлять значок в строке меню") {
                        Toggle(preferences.text("Запускать свёрнутым"), isOn: $preferences.launchMinimized)
                            .labelsHidden().toggleStyle(.switch).disabled(!preferences.loginRegistered)
                    }
                    Divider()
                    updates
                    Divider()
                    row("Язык", "Язык интерфейса Qosmos VPN") {
                        Picker(preferences.text("Язык"), selection: $preferences.language) {
                            Text(verbatim: "Русский").tag(AppLanguage.russian)
                            Text(verbatim: "English").tag(AppLanguage.english)
                        }
                        .labelsHidden()
                        .fixedSize()
                    }
                    Divider()
                    row("Логирование", "Сохранять события подключения в локальный журнал") {
                        Toggle(preferences.text("Логирование"), isOn: $preferences.logging)
                            .labelsHidden().toggleStyle(.switch)
                    }
                    if preferences.logging || FileManager.default.fileExists(atPath: preferences.logURL.path) {
                        Button(preferences.text("Открыть журнал")) {
                            do { try preferences.openLog() }
                            catch { model.errorMessage = "Не удалось открыть журнал." }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.bottom, 10)
                    }
                    Divider()
                    Button(role: .destructive) { confirmReset = true } label: {
                        HStack {
                            Text(preferences.text("Сбросить настройки и удалить профили"))
                            Spacer()
                            Image(systemName: "chevron.right")
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .contentShape(Rectangle())
                        .padding(.vertical, 13)
                    }
                    .buttonStyle(.borderless)
                    .foregroundStyle(.red)
                    .disabled(!model.isIdle || model.importBusy)
                }
                .padding(.trailing, 3)
            }
        }
        .padding(24)
        .frame(width: 430, height: 615)
        .tint(Color(red: 1, green: 0.68, blue: 0.46))
        .foregroundStyle(Color(red: 0.96, green: 0.95, blue: 0.93))
        .background(Color(red: 0.051, green: 0.055, blue: 0.066))
        .preferredColorScheme(.dark)
        .alert(preferences.text("Сбросить настройки и удалить профили?"), isPresented: $confirmReset) {
            Button(preferences.text("Сбросить"), role: .destructive) { model.resetData() }
            Button(preferences.text("Отмена"), role: .cancel) {}
        } message: {
            Text(preferences.text("Сохранённые профили и журнал будут удалены с этого Mac."))
        }
    }

    private var updates: some View {
        VStack(alignment: .leading, spacing: 7) {
            row("Проверять обновления автоматически", "Проверять новую версию при запуске") {
                Toggle(preferences.text("Проверять обновления автоматически"), isOn: $preferences.autoUpdates)
                    .labelsHidden().toggleStyle(.switch).disabled(!preferences.hasUpdateSource)
            }
            TextField(preferences.text("HTTPS-адрес файла обновлений"), text: $preferences.updateSource)
                .textFieldStyle(.roundedBorder)
            if !preferences.hasUpdateSource {
                Text(preferences.text("Укажите HTTPS-адрес источника обновлений."))
                    .font(.caption).foregroundStyle(.secondary)
            }
            HStack {
                Button(preferences.text(preferences.checkingUpdate ? "Проверяем…" : "Проверить сейчас")) {
                    preferences.checkForUpdates()
                }
                .disabled(!preferences.hasUpdateSource || preferences.checkingUpdate)
                if let message = preferences.updateMessage {
                    Text(preferences.text(message)).font(.caption).foregroundStyle(.secondary)
                }
                if let url = preferences.availableUpdate {
                    Link(preferences.text("Скачать"), destination: url)
                }
            }
            .padding(.bottom, 12)
        }
    }

    private func row<T: View>(_ title: String, _ subtitle: String, @ViewBuilder control: () -> T) -> some View {
        HStack(alignment: .center, spacing: 12) {
            VStack(alignment: .leading, spacing: 5) {
                Text(preferences.text(title)).font(.system(size: 14, weight: .medium))
                Text(preferences.text(subtitle)).font(.system(size: 12)).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 7)
            control()
        }
        .padding(.vertical, 11)
    }
}
