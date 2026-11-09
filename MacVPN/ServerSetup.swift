import AppKit
import SwiftUI
import UniformTypeIdentifiers

private enum SetupMode: String, Encodable {
    case single, singleSSH, pair, existing
}

private struct SetupServer: Encodable {
    var host = ""
    var port = 22
    var user = "root"
    var password = ""
    var key = ""
    var hostKey = ""
    var useKey = false

    enum CodingKeys: String, CodingKey { case host, port, user, password, key, hostKey }

    var ready: Bool {
        !host.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        && !user.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        && (1...65535).contains(port)
        && (useKey ? !key.isEmpty : !password.isEmpty)
    }

    func prepared(withCredentials: Bool) -> Self {
        var value = self
        value.host = host.trimmingCharacters(in: .whitespacesAndNewlines)
        value.user = user.trimmingCharacters(in: .whitespacesAndNewlines)
        if !withCredentials { value.password = ""; value.key = "" }
        else if !useKey { value.key = "" }
        return value
    }
}

private struct SetupRequest: Encodable {
    let mode: SetupMode
    let entry: SetupServer
    let exit: SetupServer
    let name: String
    let vpnPort: Int
    let link: String
}

private struct SetupHost: Decodable, Identifiable {
    let role: String
    let address: String
    let key: String
    let fingerprint: String
    var id: String { role }
}

private struct SetupEvent: Decodable {
    let kind: String
    let message: String?
    let hosts: [SetupHost]?
    let profile: Profile?
    let exitIP: String?
}

struct ServerSetupView: View {
    @ObservedObject var model: VPNModel
    let dismiss: (Bool) -> Void
    @State private var pair = false
    @State private var singleOverSSH = true
    @State private var existing = false
    @State private var entry = SetupServer()
    @State private var exit = SetupServer()
    @State private var name = ""
    @State private var vpnPort = 443
    @State private var link = ""
    @State private var hosts: [SetupHost] = []
    @State private var busy = false
    @State private var progress = ""
    @State private var error: String?
    @State private var provisioned: Profile?
    @State private var externalIP = ""
    @State private var saved = false

    private let orange = Color(red: 1, green: 0.68, blue: 0.46)
    private var mode: SetupMode {
        if pair { return existing ? .existing : .pair }
        return singleOverSSH ? .singleSSH : .single
    }
    private var ready: Bool {
        (!pair || entry.ready)
        && (mode == .existing
            ? link.trimmingCharacters(in: .whitespacesAndNewlines).hasPrefix("vless://")
            : exit.ready && (mode == .singleSSH || ((1...65535).contains(vpnPort) && vpnPort != exit.port)))
        && name.count <= 90
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 12) {
                Image(systemName: saved ? "checkmark.circle.fill" : "server.rack")
                    .font(.title2).foregroundStyle(orange)
                    .frame(width: 38, height: 38)
                    .background(orange.opacity(0.12), in: RoundedRectangle(cornerRadius: 11))
                VStack(alignment: .leading, spacing: 3) {
                    Text("Настроить свой сервер").font(.title2.weight(.semibold))
                    Text(saved ? "Профиль готов" : hosts.isEmpty ? "Шаг 1 из 2 · Данные VPS" : "Шаг 2 из 2 · Проверка и установка")
                        .font(.subheadline).foregroundStyle(.secondary)
                }
                Spacer()
            }
            .padding(20)
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    if let provisioned {
                        Text(provisioned.name).font(.title3.bold())
                        if saved {
                            Text("Профиль добавлен в Qosmos VPN. Нажмите «Подключить» в главном окне, чтобы включить VPN на Mac.")
                        }
                        Text("IP выхода: \(externalIP)").font(.system(.body, design: .monospaced))
                    } else if !hosts.isEmpty {
                        review
                    } else {
                        form
                    }
                    if busy {
                        HStack(spacing: 10) {
                            ProgressView().controlSize(.small)
                            Text(progress).foregroundStyle(.secondary)
                        }
                        .accessibilityElement(children: .combine)
                    }
                    if let error {
                        Text(error).foregroundStyle(.red)
                            .textSelection(.enabled)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(20)
            }
            Divider()
            HStack {
                if !busy && !hosts.isEmpty && provisioned == nil {
                    Button("Назад") { hosts = []; error = nil }
                }
                Spacer()
                if !saved {
                    Button(provisioned == nil ? "Отмена" : "Закрыть", role: .cancel) { dismiss(false) }
                        .disabled(busy)
                }
                if saved {
                    Button("Готово") { dismiss(true) }
                        .keyboardShortcut(.defaultAction)
                } else if provisioned != nil {
                    Button("Сохранить профиль", action: save)
                        .keyboardShortcut(.defaultAction)
                } else if !hosts.isEmpty {
                    Button("Подтвердить и установить") { run("install") }
                        .keyboardShortcut(.defaultAction)
                        .disabled(busy || !ready)
                } else {
                    Button("Продолжить") { run("inspect") }
                        .keyboardShortcut(.defaultAction)
                        .disabled(busy || !ready)
                }
            }
            .padding(16)
        }
        .tint(orange)
    }

    private var form: some View {
        VStack(alignment: .leading, spacing: 16) {
            Picker("Схема", selection: $pair) {
                Text("Один VPS").tag(false)
                Text("Вход и выход").tag(true)
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            if pair {
                Text("Mac подключается к входу по SSH. Сайты видят IP выхода.")
                    .foregroundStyle(.secondary)
            } else {
                Picker("Способ подключения", selection: $singleOverSSH) {
                    Text("Через SSH").tag(true)
                    Text("Reality напрямую").tag(false)
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                Text(singleOverSSH
                     ? "Mac подключается по SSH, а сайты видят IP этого VPS. Достаточно открыть порт SSH."
                     : "Mac подключается к Reality на открытом порту VPS.")
                    .foregroundStyle(.secondary)
            }
            TextField("Название профиля (необязательно)", text: $name)
            if pair {
                SetupServerFields(title: "Вход · сервер, доступный с Mac", server: $entry)
                Toggle("У меня уже есть VLESS-ссылка выхода", isOn: $existing)
            }
            if mode == .existing {
                VStack(alignment: .leading, spacing: 6) {
                    SecureField("vless://…", text: $link)
                        .accessibilityLabel("Прямая VLESS-ссылка выхода")
                    Text("Вставьте прямую ссылку выхода с публичным IPv4. На выходе ничего переустанавливать не нужно.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            } else {
                SetupServerFields(title: pair ? "Выход · сервер для выхода в интернет" : "Доступ к серверу", server: $exit)
                if mode != .singleSSH {
                    vpnPortField
                }
            }
        }
        .textFieldStyle(.roundedBorder)
        .disabled(busy)
    }

    private var vpnPortField: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text("TCP-порт VPN")
                Spacer()
                TextField("443", value: $vpnPort, format: .number.grouping(.never))
                    .frame(width: 78)
            }
            Text(vpnPort == exit.port
                 ? "Порт VPN должен отличаться от порта SSH."
                 : "Если у хостинга есть сетевой экран, разрешите этот TCP-порт в панели VPS. Нужен Debian 12+ или Ubuntu 22.04+.")
                .font(.caption).foregroundStyle(.secondary)
        }
    }

    private var review: some View {
        VStack(alignment: .leading, spacing: 13) {
            Text("Сверьте отпечаток SSH с данными в панели VPS или в его консоли. Подтверждайте только знакомый сервер.")
                .foregroundStyle(.secondary)
            ForEach(hosts) { host in
                VStack(alignment: .leading, spacing: 5) {
                    Text("\(host.role) · \(host.address)").font(.headline)
                    Text(host.fingerprint).font(.system(size: 11, design: .monospaced))
                        .textSelection(.enabled)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(12)
                .background(.white.opacity(0.05), in: RoundedRectangle(cornerRadius: 10))
            }
            switch mode {
            case .existing:
                Text("Qosmos настроит SSH-вход и проверит соединение через готовый выход.")
            case .singleSSH:
                Text("Qosmos установит VPN на сервере, создаст отдельный ключ SSH и проверит доступ к сайтам.")
            case .single, .pair:
                Text("Qosmos установит Xray на порт \(vpnPort.formatted(.number.grouping(.never))) и проверит доступ к сайтам.")
            }
            if pair {
                Text("На входе будет создана отдельная учётная запись только для пересылки трафика.")
            }
            Text("Пароли для установки не сохраняются.")
                .font(.caption).foregroundStyle(.secondary)
        }
    }

    private func save() {
        guard let provisioned else { return }
        saved = model.storeImports([provisioned], exitIP: externalIP, reportError: false)
        error = saved ? nil : "Не удалось сохранить профиль на Mac. Повторите сохранение."
    }

    private func run(_ action: String) {
        let install = action == "install"
        guard ready, !busy else { return }
        guard model.isIdle, !model.internetBlocked else {
            error = "Отключите VPN или восстановите доступ к интернету в главном окне, затем повторите."
            return
        }
        var entryRequest = entry.prepared(withCredentials: install && pair)
        var exitRequest = exit.prepared(withCredentials: install && mode != .existing)
        if install {
            entryRequest.hostKey = hosts.first(where: { $0.role == "Вход" })?.key ?? ""
            exitRequest.hostKey = hosts.first(where: { $0.role != "Вход" })?.key ?? ""
        }
        let request = SetupRequest(mode: mode, entry: entryRequest, exit: exitRequest,
                                   name: name, vpnPort: vpnPort, link: install ? link : "")
        busy = true
        if install { model.provisioning = true }
        error = nil
        progress = install ? "Подключаемся к серверам…" : "Получаем отпечатки SSH…"
        DispatchQueue.global(qos: .userInitiated).async {
            var result: SetupEvent?
            do {
                let payload = try JSONEncoder().encode(request)
                let (process, input, output) = try VPNModel.makeBackend([action], resource: "server_setup")
                try process.run()
                do {
                    try input.fileHandleForWriting.write(contentsOf: payload)
                    try input.fileHandleForWriting.close()
                } catch {
                    try? input.fileHandleForWriting.close()
                }
                var buffer = Data()
                while true {
                    let chunk = output.fileHandleForReading.availableData
                    if chunk.isEmpty { break }
                    buffer.append(chunk)
                    while let newline = buffer.firstIndex(of: 10) {
                        let line = buffer.prefix(upTo: newline)
                        if let event = try? JSONDecoder().decode(SetupEvent.self, from: Data(line)) {
                            if event.kind == "progress" {
                                DispatchQueue.main.async { progress = event.message ?? "" }
                            } else {
                                result = event
                            }
                        }
                        buffer.removeSubrange(...newline)
                    }
                }
                process.waitUntilExit()
            } catch {
                result = nil
            }
            let event = result
            DispatchQueue.main.async {
                busy = false
                if install { model.provisioning = false }
                if let fingerprints = event?.hosts, !fingerprints.isEmpty {
                    hosts = fingerprints
                } else if let profile = event?.profile, let ip = event?.exitIP {
                    entry.password = ""; exit.password = ""; link = ""
                    provisioned = profile
                    externalIP = ip
                    save()
                } else {
                    error = event?.message ?? "Не удалось завершить работу мастера."
                }
            }
        }
    }
}

private struct SetupServerFields: View {
    let title: String
    @Binding var server: SetupServer

    var body: some View {
        VStack(alignment: .leading, spacing: 9) {
            Text(title).font(.headline)
            HStack {
                TextField("Публичный IPv4", text: $server.host)
                Text("Порт SSH").font(.caption).foregroundStyle(.secondary)
                TextField("22", value: $server.port, format: .number.grouping(.never))
                    .frame(width: 68).accessibilityLabel("Порт SSH")
            }
            TextField("Пользователь SSH", text: $server.user)
            Picker("Авторизация SSH", selection: $server.useKey) {
                Text("Пароль").tag(false)
                Text("Файл ключа").tag(true)
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .onChange(of: server.useKey) { _ in server.password = "" }
            if server.useKey {
                HStack {
                    Button("Выбрать ключ…", action: chooseKey)
                    Text(server.key.isEmpty ? "Файл не выбран" : URL(fileURLWithPath: server.key).lastPathComponent)
                        .lineLimit(1).foregroundStyle(.secondary)
                }
                SecureField("Парольная фраза ключа (если есть)", text: $server.password)
            } else {
                SecureField("Пароль SSH", text: $server.password)
            }
        }
        .padding(12)
        .background(.white.opacity(0.05), in: RoundedRectangle(cornerRadius: 10))
    }

    private func chooseKey() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.showsHiddenFiles = true
        let ssh = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".ssh")
        if FileManager.default.fileExists(atPath: ssh.path) { panel.directoryURL = ssh }
        if let window = NSApp.keyWindow {
            panel.beginSheetModal(for: window) { response in
                if response == .OK, let url = panel.url { server.key = url.path }
            }
        } else {
            panel.begin { response in
                if response == .OK, let url = panel.url { server.key = url.path }
            }
        }
    }
}
