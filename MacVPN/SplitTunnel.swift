import Foundation
import SystemConfiguration

struct DirectSite: Decodable {
    let host: String
    let addresses: [String]
}

struct SplitTunnel {
    private enum SplitError: Error { case invalidSites, noPhysicalInterface, invalidTemplate, invalidRoute }
    private let sites: [DirectSite]
    private let gateway: String
    private let cloudflareEdge: String?
    let interface: String
    let directRuSites: Bool

    static let nonPublicIPv4 = [
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
        "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
        "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
        "203.0.113.0/24", "224.0.0.0/3"
    ]

    var addresses: [String] { Array(Set(sites.flatMap(\.addresses))).sorted() }

    init(sites: [DirectSite], directRuSites: Bool, cloudflareEdge: String? = nil) throws {
        guard (directRuSites || !sites.isEmpty || cloudflareEdge != nil),
              cloudflareEdge.map(Self.publicIPv4) ?? true,
              sites.count <= 8, Set(sites.map(\.host)).count == sites.count,
              sites.allSatisfy(Self.valid) else { throw SplitError.invalidSites }
        let key = "State:/Network/Global/IPv4" as CFString
        guard let state = SCDynamicStoreCopyValue(nil, key) as? [String: Any],
              let name = state["PrimaryInterface"] as? String,
              name.range(of: #"^en[0-9]+$"#, options: .regularExpression) != nil,
              let router = state["Router"] as? String, Self.ipv4(router) != nil,
              if_nametoindex(name) != 0 else { throw SplitError.noPhysicalInterface }
        self.sites = sites
        self.directRuSites = directRuSites
        self.cloudflareEdge = cloudflareEdge
        gateway = router
        interface = name
    }

    private static func valid(_ site: DirectSite) -> Bool {
        let labels = site.host.split(separator: ".", omittingEmptySubsequences: false)
        return site.host.utf8.count <= 253 && labels.count >= 2
            && labels.allSatisfy { $0.range(of: #"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$"#, options: .regularExpression) != nil }
            && !site.addresses.isEmpty && site.addresses.count <= 8 && site.addresses.allSatisfy(publicIPv4)
    }

    private static func ipv4(_ value: String) -> UInt32? {
        var address = in_addr()
        guard inet_pton(AF_INET, value, &address) == 1 else { return nil }
        return UInt32(bigEndian: address.s_addr)
    }

    private static func publicIPv4(_ value: String) -> Bool {
        guard let ip = ipv4(value) else { return false }
        let a = ip >> 24
        let b = (ip >> 16) & 255
        return a > 0 && a < 224 && a != 10 && a != 127
            && !(a == 100 && (64...127).contains(b))
            && !(a == 169 && b == 254) && !(a == 172 && (16...31).contains(b))
            && !(a == 192 && b == 168) && !(a == 198 && (18...19).contains(b))
    }

    func installRoutes(tunnel: String, endpoint: String) throws -> [String] {
        var added: [String] = []
        do {
            if directRuSites {
                let scopedDefault = try? Self.route(["get", "-ifscope", interface, "default"])
                if routeField("flags", in: scopedDefault)?.contains("IFSCOPE") != true {
                    _ = try Self.route(["add", "-net", "-ifscope", interface, "default", gateway])
                    added.append("default")
                }
                // The physical default must be usable by bound sockets while
                // normal sockets still select the tunnel's more specific routes.
                let probe = endpoint == "1.1.1.1" ? "9.9.9.9" : "1.1.1.1"
                guard routeField("interface", in: try Self.route(["get", "-ifscope", interface, probe])) == interface,
                      routeField("interface", in: try Self.route(["get", probe])) == tunnel else {
                    throw SplitError.invalidRoute
                }
            }
            for address in addresses + (cloudflareEdge.map { [$0] } ?? []) {
                let lookup = ["get", "-ifscope", interface, address]
                if routeField("interface", in: try? Self.route(lookup)) != interface {
                    // Darwin cannot use the unscoped physical default for this
                    // bound socket when the destination also has a TUN route.
                    _ = try Self.route(["add", "-host", "-ifscope", interface, address, gateway])
                    added.append(address)
                }
                guard routeField("interface", in: try Self.route(lookup)) == interface,
                      routeField("interface", in: try Self.route(["get", address])) == tunnel else {
                    throw SplitError.invalidRoute
                }
            }
            return added
        } catch {
            removeRoutes(added)
            throw error
        }
    }

    func removeRoutes(_ added: [String]) {
        for address in added {
            let current = try? Self.route(["get", "-ifscope", interface, address])
            let isDefault = address == "default"
            guard routeField("destination", in: current) == address,
                  routeField("gateway", in: current) == gateway,
                  routeField("interface", in: current) == interface,
                  let flags = routeField("flags", in: current),
                  flags.contains("IFSCOPE"), isDefault || flags.contains("HOST") else { continue }
            do { _ = try Self.route(["delete", isDefault ? "-net" : "-host", "-ifscope", interface, address, gateway]) }
            catch { NSLog("Qosmos VPN could not remove a scoped route") }
        }
    }

    private func routeField(_ key: String, in output: String?) -> String? {
        output?.split(separator: "\n").lazy.map { $0.trimmingCharacters(in: .whitespaces) }
            .first { $0.hasPrefix(key + ":") }?
            .dropFirst(key.count + 1).trimmingCharacters(in: .whitespaces)
    }

    private static func route(_ args: [String]) throws -> String {
        let process = Process()
        let output = Pipe()
        process.executableURL = URL(fileURLWithPath: "/sbin/route")
        process.arguments = ["-n"] + args
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        try process.run()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else { throw SplitError.invalidRoute }
        return String(decoding: data, as: UTF8.self)
    }

    func configure(_ config: inout [String: Any]) throws {
        guard !sites.isEmpty || directRuSites else { return }
        guard var outbounds = config["outbounds"] as? [[String: Any]],
              var route = config["route"] as? [String: Any],
              let defaultRules = route["rules"] as? [[String: Any]],
              var dns = config["dns"] as? [String: Any] else { throw SplitError.invalidTemplate }

        outbounds.append(["type": "direct", "tag": "qosmos-direct", "bind_interface": interface])
        config["outbounds"] = outbounds

        var sniff: [String: Any] = [
            "network": "tcp", "port": [80, 443],
            "action": "sniff", "sniffer": ["http", "tls"]
        ]
        if !directRuSites { sniff["ip_cidr"] = addresses.map { $0 + "/32" } }
        var directRules: [[String: Any]] = sites.map { site in
            [
                "type": "logical", "mode": "and",
                "rules": [
                    ["domain": [site.host], "network": "tcp", "port": [80, 443], "protocol": ["http", "tls"]],
                    ["ip_cidr": site.addresses.map { $0 + "/32" }]
                ],
                "action": "route", "outbound": "qosmos-direct"
            ]
        }
        if directRuSites {
            directRules.append([
                "type": "logical", "mode": "and",
                "rules": [
                    ["domain_suffix": [".ru"], "network": "tcp", "port": [80, 443], "protocol": ["http", "tls"]],
                    ["ip_cidr": ["0.0.0.0/0"]],
                    ["ip_cidr": Self.nonPublicIPv4, "invert": true]
                ],
                "action": "route", "outbound": "qosmos-direct"
            ])
        }
        route["rules"] = [sniff] + directRules + defaultRules
        config["route"] = route

        // Resolve these names to the same addresses the firewall allows for this session.
        let pinned: [[String: Any]] = sites.map { site in
            [
                "domain": [site.host], "query_type": ["A"], "action": "predefined",
                "answer": site.addresses.map { "\(site.host). 60 IN A \($0)" }
            ]
        }
        var dnsRules = pinned
        let noAlternative: [String: Any] = ["query_type": ["AAAA", "HTTPS"], "action": "predefined", "rcode": "NOERROR"]
        if !sites.isEmpty {
            dnsRules.append(noAlternative.merging(["domain": sites.map(\.host)]) { _, new in new })
        }
        if directRuSites {
            dnsRules.append(noAlternative.merging(["domain_suffix": [".ru"]]) { _, new in new })
        }
        dns["rules"] = dnsRules + (dns["rules"] as? [[String: Any]] ?? [])
        config["dns"] = dns
    }
}
