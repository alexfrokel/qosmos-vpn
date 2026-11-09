import Darwin
import Foundation
import SystemConfiguration

private let directory = URL(fileURLWithPath: "/Library/Application Support/QosmosVPN", isDirectory: true)
private let ready: UInt8 = 1

private struct NetworkPrefix {
    let bytes: [UInt8]
    let length: Int

    init(bytes: [UInt8], length: Int) {
        self.bytes = bytes
        self.length = length
    }

    init?(_ value: String) {
        let parts = value.split(separator: "/")
        guard parts.count == 2, let length = Int(parts[1]) else { return nil }
        let family = parts[0].contains(":") ? AF_INET6 : AF_INET
        var bytes = [UInt8](repeating: 0, count: family == AF_INET6 ? 16 : 4)
        guard (0...bytes.count * 8).contains(length),
              inet_pton(family, String(parts[0]), &bytes) == 1 else { return nil }
        self.init(bytes: bytes, length: length)
    }

    var cidr: String {
        let family = bytes.count == 16 ? AF_INET6 : AF_INET
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        _ = inet_ntop(family, bytes, &buffer, socklen_t(buffer.count))
        return "\(String(cString: buffer))/\(length)"
    }

    func excluding(_ address: [UInt8]) -> [String] {
        guard address.count == bytes.count, (0..<length).allSatisfy({ bit(in: bytes, at: $0) == bit(in: address, at: $0) }) else {
            return [cidr]
        }
        var network = bytes
        return (length..<bytes.count * 8).map { index in
            let mask = UInt8(0x80 >> (index % 8))
            let byte = index / 8
            if address[byte] & mask == 0 {
                network[byte] |= mask
            }
            let sibling = NetworkPrefix(bytes: network, length: index + 1).cidr
            network[byte] ^= mask
            return sibling
        }
    }

    private func bit(in value: [UInt8], at index: Int) -> Bool {
        value[index / 8] & UInt8(0x80 >> (index % 8)) != 0
    }
}

private enum ServiceError: Error {
    case invalidRequest, invalidTemplate, cannotCreateConfig, cannotConfigureDNS
}

private func readBytes(_ count: Int, from peer: Int32) throws -> [UInt8] {
    var frame = [UInt8](repeating: 0, count: count)
    var offset = 0
    let deadline = ProcessInfo.processInfo.systemUptime + 3
    while offset < frame.count {
        let remaining = deadline - ProcessInfo.processInfo.systemUptime
        guard remaining > 0 else { throw ServiceError.invalidRequest }
        var event = pollfd(fd: peer, events: Int16(POLLIN), revents: 0)
        guard poll(&event, 1, Int32(remaining * 1000)) > 0 else { throw ServiceError.invalidRequest }
        let count = frame.withUnsafeMutableBufferPointer { buffer in
            read(peer, buffer.baseAddress!.advanced(by: offset), buffer.count - offset)
        }
        guard count > 0 else { throw ServiceError.invalidRequest }
        offset += count
    }

    return frame
}

private struct TunnelRequest {
    let address: [UInt8]
    let proxyPort: Int
    let serverPort: Int
    let protected: Bool

    init(peer: Int32) throws {
        let frame = try readBytes(22, from: peer)
        proxyPort = Int(frame[17]) * 256 + Int(frame[18])
        serverPort = Int(frame[19]) * 256 + Int(frame[20])
        guard proxyPort > 0, serverPort > 0, frame[21] <= 1 else { throw ServiceError.invalidRequest }
        protected = frame[21] == 1
        switch frame[0] {
        case 4 where frame[5..<17].allSatisfy({ $0 == 0 }): address = Array(frame[1..<5])
        case 6: address = Array(frame[1..<17])
        default: throw ServiceError.invalidRequest
        }
    }

    var endpoint: String {
        NetworkPrefix(bytes: address, length: address.count * 8).cidr.split(separator: "/").first.map(String.init) ?? ""
    }
}

private func tunnelInterface() -> String? {
    var interfaces: UnsafeMutablePointer<ifaddrs>?
    guard getifaddrs(&interfaces) == 0, let interfaces else { return nil }
    defer { freeifaddrs(interfaces) }
    var entry: UnsafeMutablePointer<ifaddrs>? = interfaces
    while let current = entry {
        let interface = current.pointee
        entry = interface.ifa_next
        guard let address = interface.ifa_addr, address.pointee.sa_family == AF_INET else { continue }
        let ipv4 = UnsafeRawPointer(address).assumingMemoryBound(to: sockaddr_in.self).pointee.sin_addr
        let name = String(cString: interface.ifa_name)
        if ipv4.s_addr == inet_addr("198.18.10.1"),
           name.range(of: #"^utun[0-9]+$"#, options: .regularExpression) != nil { return name }
    }
    return nil
}

private func installTunnelDNS() throws -> SCDynamicStore {
    guard let store = SCDynamicStoreCreate(nil, "Qosmos VPN DNS" as CFString, nil, nil) else {
        throw ServiceError.cannotConfigureDNS
    }
    let key = "State:/Network/Service/\(UUID().uuidString)/DNS" as CFString
    let settings: [String: Any] = [
        "ServerAddresses": ["198.18.10.2"],
        "SupplementalMatchDomains": [""],
        "SupplementalMatchOrders": [1],
        "SupplementalMatchDomainsNoSearch": 1
    ]
    // The dynamic store removes this resolver when the session closes, including after a crash.
    guard SCDynamicStoreAddTemporaryValue(store, key, settings as CFDictionary) else {
        throw ServiceError.cannotConfigureDNS
    }
    return store
}

private func tunnelConfig(address: [UInt8], port: Int, split: SplitTunnel?, cloudflare: Bool) throws -> Data {
    // Only the root-owned template controls the engine's other settings.
    let template = try Data(contentsOf: directory.appendingPathComponent("tun-template.json"))
    guard var config = try JSONSerialization.jsonObject(with: template) as? [String: Any],
          var inbounds = config["inbounds"] as? [[String: Any]], inbounds.count == 1,
          var outbounds = config["outbounds"] as? [[String: Any]], outbounds.count == 1,
          let prefixes = inbounds[0]["route_address"] as? [String] else { throw ServiceError.invalidTemplate }

    if !cloudflare {
        inbounds[0]["route_address"] = try prefixes.flatMap { value in
            guard let prefix = NetworkPrefix(value) else { throw ServiceError.invalidTemplate }
            return prefix.excluding(address)
        }
    }
    outbounds[0]["server_port"] = port
    config["inbounds"] = inbounds
    config["outbounds"] = outbounds
    try split?.configure(&config)
    return try JSONSerialization.data(withJSONObject: config)
}

private func trustedUID(_ peer: Int32) -> uid_t? {
    var peerUID: uid_t = 0
    var peerGID: gid_t = 0
    var consoleUID: uid_t = 0
    guard getpeereid(peer, &peerUID, &peerGID) == 0,
          let consoleUser = SCDynamicStoreCopyConsoleUser(nil, &consoleUID, nil) as String?,
          !["loginwindow", "_mbsetupuser"].contains(consoleUser),
          peerUID >= 501 && peerUID == consoleUID else { return nil }
    return peerUID
}

private func send(_ value: UInt8, to peer: Int32) -> Bool {
    var reply = value
    return write(peer, &reply, 1) == 1
}

private func serve(_ peer: Int32, uid: uid_t) throws {
    let opcode = try readBytes(1, from: peer)[0]
    switch opcode {
    case 1:
        _ = try send(KillSwitch.isBlocking() ? 2 : 1, to: peer)
        return
    case 2:
        try KillSwitch.clear()
        _ = send(ready, to: peer)
        return
    case 3, 4, 5, 6:
        break
    default:
        throw ServiceError.invalidRequest
    }
    let request = try TunnelRequest(peer: peer)
    let cloudflare = opcode == 6
    let split: SplitTunnel?
    do {
        if opcode == 4 || opcode == 5 || cloudflare {
            var directRu = opcode == 5
            if cloudflare {
                let flag = try readBytes(1, from: peer)[0]
                guard flag <= 1, request.address.count == 4, request.serverPort == 443 else { throw ServiceError.invalidRequest }
                directRu = flag == 1
            }
            let length = try readBytes(2, from: peer)
            let count = Int(length[0]) * 256 + Int(length[1])
            guard (1...16_384).contains(count) else { throw ServiceError.invalidRequest }
            let sites = try JSONDecoder().decode([DirectSite].self, from: Data(readBytes(count, from: peer)))
            guard !sites.flatMap(\.addresses).contains(request.endpoint) else { throw ServiceError.invalidRequest }
            split = try SplitTunnel(sites: sites, directRuSites: directRu, cloudflareEdge: cloudflare ? request.endpoint : nil)
        } else {
            split = nil
        }
    } catch {
        _ = send(4, to: peer)
        throw error
    }
    let keepProtection = try request.protected || KillSwitch.isBlocking()
    let blockedRules = KillSwitch.rules(endpoint: request.endpoint, port: request.serverPort, uid: uid, tunnel: nil)
    guard tunnelInterface() == nil else { throw ServiceError.invalidRequest }
    var template = Array("/private/var/run/qosmos-vpn.XXXXXXXX".utf8CString)
    guard mkdtemp(&template) != nil else { throw ServiceError.cannotCreateConfig }
    let working = URL(fileURLWithPath: String(cString: template), isDirectory: true)
    defer { try? FileManager.default.removeItem(at: working) }
    let path = working.appendingPathComponent("tun.json")
    try tunnelConfig(address: request.address, port: request.proxyPort, split: split, cloudflare: cloudflare).write(to: path)
    if keepProtection { try KillSwitch.arm(blockedRules) }
    defer {
        if keepProtection {
            do {
                try KillSwitch.replace(blockedRules)
                if let split { try KillSwitch.clearDirectStates(split) }
            }
            catch { NSLog("Qosmos VPN could not change Kill Switch rules") }
        }
    }

    let engine = Process()
    engine.executableURL = directory.appendingPathComponent("sing-box")
    engine.arguments = ["run", "-c", path.path]
    engine.currentDirectoryURL = working
    engine.standardInput = FileHandle.nullDevice
    engine.standardOutput = FileHandle.nullDevice
    engine.standardError = FileHandle.nullDevice
    try engine.run()
    defer {
        if engine.isRunning { engine.terminate() }
        for _ in 0..<20 where engine.isRunning { usleep(50_000) }
        if engine.isRunning { kill(engine.processIdentifier, SIGKILL) }
        engine.waitUntilExit()
    }
    var device: String?
    for _ in 0..<50 where engine.isRunning {
        if let name = tunnelInterface() { device = name; break }
        usleep(100_000)
    }
    guard let device else { throw ServiceError.invalidRequest }
    let addedRoutes: [String]
    do {
        addedRoutes = try split?.installRoutes(tunnel: device, endpoint: request.endpoint) ?? []
    } catch {
        _ = send(4, to: peer)
        throw error
    }
    defer { split?.removeRoutes(addedRoutes) }
    if keepProtection {
        try KillSwitch.replace(KillSwitch.rules(endpoint: request.endpoint, port: request.serverPort, uid: uid, tunnel: device, split: split))
    }
    let dns: SCDynamicStore
    do {
        dns = try installTunnelDNS()
    } catch {
        _ = send(3, to: peer)
        throw error
    }
    withExtendedLifetime(dns) {
        guard send(ready, to: peer) else { return }
        var event = pollfd(fd: peer, events: Int16(POLLIN), revents: 0)
        while engine.isRunning && poll(&event, 1, 500) == 0 {}
    }
}

private func runService() {
    guard geteuid() == 0 else { return }
    umask(0o077)
    signal(SIGPIPE, SIG_IGN)
    var unused: Int32 = -1
    let listener = withUnsafeMutablePointer(to: &unused) { placeholder -> Int32 in
        var sockets = placeholder
        var count = 0
        guard launch_activate_socket("Tunnel", &sockets, &count) == 0 else { return -1 }
        defer { free(sockets) }
        return count == 1 ? sockets[0] : -1
    }
    guard listener >= 0 else { return }
    defer { close(listener) }
    guard fcntl(listener, F_SETFD, FD_CLOEXEC) != -1 else { return }
    var event = pollfd(fd: listener, events: Int16(POLLIN), revents: 0)
    while poll(&event, 1, 30_000) > 0 {
        let peer = accept(listener, nil, nil)
        guard peer >= 0 else { return }
        if fcntl(peer, F_SETFD, FD_CLOEXEC) != -1, let uid = trustedUID(peer) {
            do { try serve(peer, uid: uid) } catch { NSLog("Qosmos VPN tunnel request failed") }
        }
        close(peer)
    }
}

@main
struct TunnelServiceMain {
    static func main() { runService() }
}
