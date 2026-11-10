import AppKit
import ServiceManagement
import SwiftUI

enum AppLanguage: String, CaseIterable {
    case russian = "ru"
    case english = "en"
}

enum SplitMode: String, CaseIterable {
    case bypass, only

    var title: String {
        self == .only ? "Выбранные сайты через VPN" : "Выбранные сайты без VPN"
    }
}

enum AppBuild {
    static let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0"
    static let updateSource = Bundle.main.object(forInfoDictionaryKey: "QosmosUpdateSource") as? String ?? ""
    static let directSites = Bundle.main.object(forInfoDictionaryKey: "QosmosDirectSites") as? String ?? ""
}

private final class UpdateDownloadDelegate: NSObject, URLSessionDownloadDelegate, @unchecked Sendable {
    private let progress: (Int?) -> Void
    private let finished: (URL?, URLResponse?) -> Void

    init(progress: @escaping (Int?) -> Void, finished: @escaping (URL?, URLResponse?) -> Void) {
        self.progress = progress
        self.finished = finished
    }

    func urlSession(_ session: URLSession, downloadTask: URLSessionDownloadTask, didWriteData bytesWritten: Int64,
                    totalBytesWritten: Int64, totalBytesExpectedToWrite: Int64) {
        let percentage = totalBytesExpectedToWrite > 0
            ? Int(min(100, 100 * Double(totalBytesWritten) / Double(totalBytesExpectedToWrite))) : nil
        progress(percentage)
    }

    func urlSession(_ session: URLSession, downloadTask: URLSessionDownloadTask, didFinishDownloadingTo location: URL) {
        finished(location, downloadTask.response)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        if error != nil { finished(nil, task.response) }
    }
}

final class AppPreferences: ObservableObject {
    private let defaults: UserDefaults
    private let directory: URL
    private let service = SMAppService.mainApp
    private var updateTask: URLSessionDataTask?
    private var updateID: UUID?

    @Published var autoConnect: Bool { didSet { defaults.set(autoConnect, forKey: "autoConnect") } }
    @Published var killSwitch: Bool { didSet { defaults.set(killSwitch, forKey: "killSwitch") } }
    @Published var directSites: String { didSet { defaults.set(directSites, forKey: "directSites") } }
    @Published var vpnSites: String { didSet { defaults.set(vpnSites, forKey: "vpnSites") } }
    @Published var splitMode: SplitMode { didSet { defaults.set(splitMode.rawValue, forKey: "splitMode") } }
    @Published var directRuSites: Bool { didSet { defaults.set(directRuSites, forKey: "directRuSites") } }
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
    @Published private(set) var availableUpdate: Release?
    @Published private(set) var installingUpdate = false
    @Published private(set) var downloadPercent: Int?

    init(defaults: UserDefaults = .standard, directory: URL? = nil) {
        self.defaults = defaults
        self.directory = directory ?? FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("VLESS VPN", isDirectory: true)
        autoConnect = defaults.bool(forKey: "autoConnect")
        killSwitch = defaults.object(forKey: "killSwitch") as? Bool ?? true
        directSites = defaults.string(forKey: "directSites") ?? AppBuild.directSites
        vpnSites = defaults.string(forKey: "vpnSites") ?? ""
        splitMode = SplitMode(rawValue: defaults.string(forKey: "splitMode") ?? "") ?? .bypass
        directRuSites = defaults.bool(forKey: "directRuSites")
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
        directSites = AppBuild.directSites
        vpnSites = ""
        splitMode = .bypass
        directRuSites = false
        launchMinimized = false
        autoUpdates = true
        updateSource = AppBuild.updateSource
        language = .russian
        logging = false
    }

    struct Release: Decodable {
        let version: String
        let url: String
        let sha256: String?

        var checksum: String? {
            guard let sha256, sha256.range(of: #"^[0-9a-fA-F]{64}$"#, options: .regularExpression) != nil else {
                return nil
            }
            return sha256.lowercased()
        }
    }

    private static func httpsURL(_ string: String) -> URL? {
        guard let parts = URLComponents(string: string.trimmingCharacters(in: .whitespacesAndNewlines)),
              parts.scheme?.lowercased() == "https", let host = parts.host, !host.isEmpty,
              parts.user == nil, parts.password == nil else { return nil }
        return parts.url
    }

    func checkForUpdates() {
        guard let url = Self.httpsURL(updateSource), !checkingUpdate, !installingUpdate else { return }
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
                guard validResponse, let release, Self.httpsURL(release.url) != nil,
                      release.version.range(of: #"^\d+(\.\d+){0,3}$"#, options: .regularExpression) != nil else {
                    self.updateMessage = "Не удалось проверить обновления."
                    return
                }
                if release.version.compare(current, options: .numeric) == .orderedDescending {
                    self.availableUpdate = release
                    self.updateMessage = release.checksum == nil
                        ? "Для этой версии недоступна установка из приложения." : "Доступна новая версия."
                } else {
                    self.updateMessage = "У вас актуальная версия."
                }
            }
        }
        updateTask = task
        task.resume()
    }

    func installUpdate(restart: @escaping (URL, @escaping (Error) -> Void) -> Void) {
        guard !installingUpdate, let release = availableUpdate, let checksum = release.checksum,
              let url = Self.httpsURL(release.url) else { return }
        let target = Bundle.main.bundleURL.resolvingSymlinksInPath()
        let parent = target.deletingLastPathComponent()
        guard FileManager.default.isWritableFile(atPath: parent.path) else {
            updateMessage = "Переместите Qosmos VPN в папку, доступную для записи."
            return
        }
        installingUpdate = true
        updateMessage = "Загружаем обновление…"
        downloadPercent = 0
        var request = URLRequest(url: url, timeoutInterval: 60)
        request.cachePolicy = .reloadIgnoringLocalCacheData
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForResource = 900
        let delegate = UpdateDownloadDelegate(progress: { [weak self] percent in
            DispatchQueue.main.async { [weak self] in
                guard let self, self.downloadPercent != percent else { return }
                self.downloadPercent = percent
            }
        }, finished: { [weak self] file, response in
            let staging = parent.appendingPathComponent(".qosmos-update-\(UUID().uuidString)", isDirectory: true)
            do {
                guard let file, let response = response as? HTTPURLResponse,
                      response.statusCode == 200, response.url?.scheme == "https" else {
                    throw AppError(message: "Не удалось загрузить обновление.")
                }
                let manager = FileManager.default
                try manager.createDirectory(at: staging, withIntermediateDirectories: false,
                                            attributes: [.posixPermissions: 0o700])
                try manager.moveItem(at: file, to: staging.appendingPathComponent("update.zip"))
                guard let script = Bundle.main.url(forResource: "update_installer", withExtension: "py") else {
                    throw AppError(message: "Не удалось подготовить обновление.")
                }
                try manager.copyItem(at: script, to: staging.appendingPathComponent("update_installer.py"))
                DispatchQueue.main.async { self?.showUpdateStep("Проверяем обновление…") }
                let installer = Self.installer(staging, ["prepare", target.path, release.version, checksum])
                try installer.run()
                installer.waitUntilExit()
                guard installer.terminationStatus == 0 else {
                    throw AppError(message: "Проверка обновления не пройдена.")
                }
                DispatchQueue.main.async {
                    restart(staging) { [weak self] error in
                        try? FileManager.default.removeItem(at: staging)
                        self?.finishUpdate(error)
                    }
                }
            } catch {
                try? FileManager.default.removeItem(at: staging)
                DispatchQueue.main.async { self?.finishUpdate(error) }
            }
        })
        let session = URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil)
        session.downloadTask(with: request).resume()
        session.finishTasksAndInvalidate()
    }

    func showUpdateStep(_ message: String) {
        downloadPercent = nil
        updateMessage = message
    }

    private func finishUpdate(_ error: Error) {
        installingUpdate = false
        showUpdateStep((error as? AppError)?.message ?? "Не удалось подготовить обновление.")
    }

    static func installer(_ staging: URL, _ arguments: [String]) -> Process {
        let process = Process()
        let bundled = Bundle.main.resourceURL?.appendingPathComponent("python/bin/python3")
        process.executableURL = bundled.flatMap { FileManager.default.isExecutableFile(atPath: $0.path) ? $0 : nil }
            ?? URL(fileURLWithPath: "/usr/bin/python3")
        process.arguments = ["-I", "-B", staging.appendingPathComponent("update_installer.py").path] + arguments
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        return process
    }
}

struct QosmosSettingsView: View {
    private enum Section: String, CaseIterable {
        case application = "Приложение"
        case split = "Раздельное туннелирование"
        case security = "Kill Switch"
        case updates = "Обновления"
        case diagnostics = "Диагностика и сброс"

        var icon: String {
            switch self {
            case .application: return "gearshape"
            case .split: return "arrow.triangle.branch"
            case .security: return "shield"
            case .updates: return "arrow.down.circle"
            case .diagnostics: return "doc.text"
            }
        }
    }

    @ObservedObject var model: VPNModel
    @ObservedObject var preferences: AppPreferences
    @State private var confirmReset = false
    @State private var section: Section?

    var body: some View {
        VStack(alignment: .leading, spacing: 11) {
            HStack(spacing: 12) {
                Button {
                    if section == nil { model.showSettings = false }
                    else { section = nil }
                } label: {
                    Image(systemName: "chevron.left")
                        .font(.system(size: 14, weight: .semibold))
                        .frame(width: 28, height: 28)
                }
                .buttonStyle(.borderless)
                .accessibilityLabel(preferences.text("Назад"))
                Text(preferences.text(section?.rawValue ?? "Настройки"))
                    .font(.system(size: 23, weight: .semibold, design: .rounded))
            }

            ScrollView {
                VStack(spacing: 0) {
                    if let section {
                        sectionContent(section)
                    } else {
                        ForEach(Section.allCases, id: \.self) { entry in
                            Button { section = entry } label: {
                                HStack(spacing: 12) {
                                    Image(systemName: entry.icon).frame(width: 24)
                                    Text(preferences.text(entry.rawValue)).font(.system(size: 14, weight: .medium))
                                    Spacer()
                                    Image(systemName: "chevron.right").font(.system(size: 11, weight: .semibold))
                                }
                                .padding(.vertical, 14)
                                .contentShape(Rectangle())
                            }
                            .buttonStyle(.borderless)
                            Divider()
                        }
                    }
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

    @ViewBuilder
    private func sectionContent(_ section: Section) -> some View {
        switch section {
        case .application:
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
            row("Запускать свёрнутым", "При автозапуске оставлять значок в строке меню") {
                Toggle(preferences.text("Запускать свёрнутым"), isOn: $preferences.launchMinimized)
                    .labelsHidden().toggleStyle(.switch).disabled(!preferences.loginRegistered)
            }
            Divider()
            row("Язык", "Язык интерфейса Qosmos VPN") {
                Picker(preferences.text("Язык"), selection: $preferences.language) {
                    Text(verbatim: "Русский").tag(AppLanguage.russian)
                    Text(verbatim: "English").tag(AppLanguage.english)
                }
                .labelsHidden().fixedSize()
            }
        case .split:
            splitSettings
        case .security:
            row("Kill Switch", "Блокировать интернет при обрыве VPN. Изменение применяется при следующем подключении.") {
                Toggle("Kill Switch", isOn: $preferences.killSwitch)
                    .labelsHidden().toggleStyle(.switch)
            }
        case .updates:
            updates
        case .diagnostics:
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
                .padding(.vertical, 13)
                .contentShape(Rectangle())
            }
            .buttonStyle(.borderless)
            .foregroundStyle(.red)
            .disabled(!model.isIdle || model.importBusy || preferences.installingUpdate)
        }
    }

    private var splitSettings: some View {
        let only = preferences.splitMode == .only
        return VStack(alignment: .leading, spacing: 12) {
            Picker(preferences.text("Режим"), selection: $preferences.splitMode) {
                ForEach(SplitMode.allCases, id: \.self) { mode in
                    Text(preferences.text(mode.title)).tag(mode)
                }
            }
            .pickerStyle(.radioGroup)
            .labelsHidden()
            Text(preferences.text(only
                ? "Выбранные домены и их поддомены идут через VPN. Остальные сайты открываются напрямую."
                : "Выбранные домены открываются напрямую. Остальные сайты идут через VPN."))
                .font(.system(size: 12)).foregroundStyle(.secondary)
            TextField(preferences.text("Домены сайтов"), text: only ? $preferences.vpnSites : $preferences.directSites,
                      prompt: Text(only ? "youtube.com, github.com" : "aeza.ru, my.aeza.ru"))
                .textFieldStyle(.roundedBorder)
            Text(preferences.text(only
                ? "Укажите до 20 доменов через запятую. Применяется при следующем подключении."
                : "Введите до 20 доменов через запятую. Добавляйте поддомены отдельно. Применяется после переподключения."))
                .font(.system(size: 12)).foregroundStyle(.secondary)
            if !only {
                Divider()
                row("Сайты .ru напрямую", "Открывать сайты .ru и их поддомены через обычное подключение. Применяется после переподключения.") {
                    Toggle(preferences.text("Сайты .ru напрямую"), isOn: $preferences.directRuSites)
                        .labelsHidden().toggleStyle(.switch)
                }
            }
        }
        .padding(.vertical, 11)
    }

    private var updates: some View {
        VStack(alignment: .leading, spacing: 7) {
            row("Проверять обновления автоматически", "Проверять новую версию при запуске") {
                Toggle(preferences.text("Проверять обновления автоматически"), isOn: $preferences.autoUpdates)
                    .labelsHidden().toggleStyle(.switch).disabled(!preferences.hasUpdateSource)
            }
            TextField(preferences.text("HTTPS-адрес файла обновлений"), text: $preferences.updateSource)
                .textFieldStyle(.roundedBorder)
                .disabled(preferences.installingUpdate)
            if !preferences.hasUpdateSource {
                Text(preferences.text("Укажите HTTPS-адрес источника обновлений."))
                    .font(.caption).foregroundStyle(.secondary)
            }
            HStack {
                Button(preferences.text(preferences.checkingUpdate ? "Проверяем…" : "Проверить сейчас")) {
                    preferences.checkForUpdates()
                }
                .disabled(!preferences.hasUpdateSource || preferences.checkingUpdate || preferences.installingUpdate)
                if let release = preferences.availableUpdate {
                    if release.checksum != nil {
                        Button("\(preferences.text("Обновить")) · \(release.version)") {
                            preferences.installUpdate(restart: model.restartForUpdate)
                        }
                        .disabled(preferences.installingUpdate)
                    } else if let url = URL(string: release.url) {
                        Link(preferences.text("Скачать"), destination: url)
                    }
                }
            }
            if preferences.installingUpdate, let percent = preferences.downloadPercent {
                HStack(spacing: 10) {
                    ProgressView(value: Double(percent), total: 100)
                        .animation(.easeOut(duration: 0.2), value: percent)
                    Text("\(percent)%").monospacedDigit()
                }
                .font(.caption)
                .accessibilityLabel(preferences.text("Загрузка обновления"))
                .accessibilityValue("\(percent)%")
            } else if preferences.installingUpdate {
                ProgressView().controlSize(.small)
            }
            if let message = preferences.updateMessage {
                Text(preferences.text(message)).font(.caption).foregroundStyle(.secondary)
            }
        }
        .padding(.bottom, 12)
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
