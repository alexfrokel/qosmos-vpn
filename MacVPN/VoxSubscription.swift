import Foundation
import Security

enum VoxProtocol: String, Codable, CaseIterable, Identifiable {
    case vless, wireguard, amneziawg

    var id: Self { self }

    var label: String {
        switch self {
        case .vless: "VLESS + REALITY"
        case .wireguard: "WireGuard"
        case .amneziawg: "AmneziaWG"
        }
    }
}

enum ConnectionProfile: Encodable, Equatable {
    case manual(Profile)
    case voxUDP(VoxUDPProfile)

    struct VoxUDPProfile: Encodable, Equatable {
        let voxProtocol: VoxProtocol
        let config: String
    }

    func encode(to encoder: Encoder) throws {
        var value = encoder.singleValueContainer()
        switch self {
        case let .manual(profile): try value.encode(profile)
        case let .voxUDP(profile): try value.encode(profile)
        }
    }
}

struct VoxCountry: Decodable, Identifiable {
    let code: String
    let name: String
    let protocols: [String]?
    var id: String { code }

    func supports(_ choice: VoxProtocol) -> Bool {
        protocols?.contains(choice.rawValue) ?? (choice == .vless)
    }

    func label(language: AppLanguage) -> String {
        Locale(identifier: language.rawValue).localizedString(forRegionCode: code) ?? name
    }
}

struct VoxUsage: Decodable {
    let devicesUsed: Int
    let deviceLimit: Int
    let monthlyBytes: Int64
    let email: String?
    let expiresAt: String?
    let subscriptionStatus: String?

    enum CodingKeys: String, CodingKey {
        case devicesUsed = "devices_used"
        case deviceLimit = "device_limit"
        case monthlyBytes = "monthly_bytes"
        case email
        case expiresAt = "expires_at"
        case subscriptionStatus = "subscription_status"
    }
}

private final class VoxNoRedirects: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}

final class VoxSubscription {
    struct TemporaryError: LocalizedError {
        let retryAfter: UInt64
        var errorDescription: String? { "Сервер подписки Vox недоступен. Повторите попытку." }
    }

    private struct Locations: Decodable {
        let countries: [VoxCountry]
        let protocol_countries: [VoxCountry]?
    }

    private struct Configuration: Decodable {
        let protocolName: VoxProtocol?
        let link: String?
        let config: String?

        enum CodingKeys: String, CodingKey {
            case protocolName = "protocol"
            case link, config
        }
    }
    private struct Rejection: Decodable { let error: String }
    private struct Device: Encodable {
        let country: String
        let device_id: UUID
        let protocolName: VoxProtocol

        enum CodingKeys: String, CodingKey {
            case country, device_id
            case protocolName = "protocol"
        }
    }

    private let origin: URL
    private let session: URLSession

    init?(url: String) {
        guard let components = URLComponents(string: url),
              let host = components.host, !host.isEmpty,
              components.scheme == "https" || (components.scheme == "http" && host == "127.0.0.1"),
              components.user == nil, components.password == nil,
              components.query == nil, components.fragment == nil,
              let origin = components.url else { return nil }
        self.origin = origin
        let config = URLSessionConfiguration.ephemeral
        config.urlCache = nil
        config.httpCookieStorage = nil
        config.timeoutIntervalForRequest = 30
        config.timeoutIntervalForResource = 45
        session = URLSession(configuration: config, delegate: VoxNoRedirects(), delegateQueue: nil)
    }

    func countries(token: String) async throws -> [VoxCountry] {
        let locations: Locations = try await request("locations", token: token)
        let countries = AppBuild.isVezde ? locations.protocol_countries ?? locations.countries : locations.countries
        guard !countries.isEmpty else {
            throw AppError(message: "В подписке Vox пока нет доступных стран.")
        }
        return countries
    }

    func usage(token: String) async throws -> VoxUsage {
        try await request("subscription", token: token)
    }

    func config(token: String, country: String, deviceID: UUID, choice: VoxProtocol) async throws -> String {
        let body = try JSONEncoder().encode(Device(country: country, device_id: deviceID, protocolName: choice))
        let response: Configuration = try await request("config", token: token, body: body)
        let config = choice == .vless ? response.link : response.config
        guard (response.protocolName ?? .vless) == choice,
              let config, config.utf8.count <= 16_384 else {
            throw AppError(message: "Vox вернул некорректный профиль VPN.")
        }
        if choice == .vless {
            guard config.hasPrefix("vless://"), config.rangeOfCharacter(from: .newlines) == nil else {
                throw AppError(message: "Vox вернул некорректный профиль VPN.")
            }
        }
        return config
    }

    private func request<T: Decodable>(_ path: String, token: String, body: Data? = nil) async throws -> T {
        var request = URLRequest(url: origin.appendingPathComponent("v1").appendingPathComponent(path))
        request.setValue("Bearer " + token, forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        if let body {
            request.httpMethod = "POST"
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = body
        }
        let (data, response): (Data, URLResponse)
        do { (data, response) = try await session.data(for: request) }
        catch {
            try Task.checkCancellation()
            if let error = error as? URLError,
               [.timedOut, .cannotFindHost, .cannotConnectToHost, .networkConnectionLost,
                .dnsLookupFailed, .notConnectedToInternet, .resourceUnavailable].contains(error.code) {
                throw TemporaryError(retryAfter: 0)
            }
            throw AppError(message: "Сервер подписки Vox недоступен. Повторите попытку.")
        }
        guard let http = response as? HTTPURLResponse, data.count <= 1_048_576 else {
            throw AppError(message: "Сервер подписки Vox вернул некорректный ответ.")
        }
        if http.statusCode == 401 { throw AppError(message: "Код активации Vox недействителен.") }
        if http.statusCode != 200 {
            let code = (try? JSONDecoder().decode(Rejection.self, from: data))?.error
            let message: String
            switch code {
            case "device_limit": message = "Достигнут лимит устройств подписки Vox."
            case "account_inactive": message = "Доступ по подписке Vox приостановлен."
            case "country_unavailable": message = "Эта страна сейчас недоступна в Vox."
            case "demo_required": message = "Для этой сборки нужен демо-аккаунт Vox."
            default:
                if [408, 429, 500, 502, 503, 504].contains(http.statusCode) {
                    let retryAfter = http.value(forHTTPHeaderField: "Retry-After") ?? "0"
                    if let seconds = UInt64(retryAfter), seconds <= 10 {
                        throw TemporaryError(retryAfter: seconds)
                    }
                }
                message = "Сервер подписки Vox недоступен. Повторите попытку."
            }
            throw AppError(message: message)
        }
        do { return try JSONDecoder().decode(T.self, from: data) }
        catch { throw AppError(message: "Сервер подписки Vox вернул некорректный ответ.") }
    }

    private var keychainQuery: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: (Bundle.main.bundleIdentifier ?? "local.vlessvpn.mac") + ".vox",
         kSecAttrAccount as String: origin.absoluteString]
    }

    func token() -> String? {
        var query = keychainQuery
        query[kSecReturnData as String] = true
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess, let data = item as? Data else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }

    func save(token: String) throws {
        let fields = [kSecValueData as String: Data(token.utf8)]
        var status = SecItemUpdate(keychainQuery as CFDictionary, fields as CFDictionary)
        if status == errSecItemNotFound {
            let query = keychainQuery.merging(fields, uniquingKeysWith: { _, new in new })
            status = SecItemAdd(query as CFDictionary, nil)
        }
        guard status == errSecSuccess else {
            throw AppError(message: "Не удалось сохранить доступ Vox в Связке ключей.")
        }
    }

    func clear() throws {
        let status = SecItemDelete(keychainQuery as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw AppError(message: "Не удалось удалить доступ Vox из Связки ключей.")
        }
    }
}
