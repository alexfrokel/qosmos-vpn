import Foundation

struct KillSwitch {
    private static let anchor = "com.apple/000.QosmosVPN"
    private static let tokenFile = URL(fileURLWithPath: "/private/var/run/qosmos-vpn-pf-token")

    static func isBlocking() throws -> Bool {
        try !pf(["-a", anchor, "-sr"]).trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    static func rules(endpoint: String, port: Int, uid: uid_t, tunnel: String?) -> String {
        let family = endpoint.contains(":") ? "inet6" : "inet"
        var lines = ["pass quick on lo0 all no state"]
        if let tunnel { lines.append("pass quick on \(tunnel) all no state") }
        lines += [
            "pass out quick \(family) proto tcp from any to \(endpoint) port = \(port) flags any user \(uid) keep state (if-bound)",
            "pass out quick inet proto udp from any port 68 to any port 67 no state",
            "pass in quick inet proto udp from any port 67 to any port 68 no state",
            "pass quick inet6 proto ipv6-icmp all icmp6-type { 133, 134, 135, 136 } no state",
            "block drop quick all"
        ]
        return lines.joined(separator: "\n") + "\n"
    }

    static func arm(_ rules: String) throws {
        let main = try pf(["-sr"]).split(separator: "\n").filter { !$0.hasPrefix("scrub-anchor ") }
        guard main.count == 1, main[0] == #"anchor "com.apple/*" all"# || main[0] == #"anchor "com.apple/*""# else {
            throw FirewallError.operationFailed
        }
        let wasBlocking = try isBlocking()
        do {
            if !wasBlocking {
                try clear()
                let result = try pf(["-E"])
                guard let token = result.split(separator: "\n")
                    .first(where: { $0.trimmingCharacters(in: .whitespaces).hasPrefix("Token") })?
                    .split(whereSeparator: { $0 == " " || $0 == "\t" || $0 == ":" }).last,
                    UInt64(token) != nil else { throw FirewallError.operationFailed }
                do { try Data(token.utf8).write(to: tokenFile, options: .atomic) }
                catch { _ = try? pf(["-X", String(token)]); throw error }
            }
            try replace(rules)
            // Pre-existing floating states can bypass a new filter rule.
            _ = try pf(["-F", "states"])
        } catch {
            if !wasBlocking { try? clear() }
            throw error
        }
    }

    static func replace(_ rules: String) throws {
        _ = try pf(["-a", anchor, "-f", "-"], input: rules)
    }

    static func clear() throws {
        if try isBlocking() { try replace("") }
        if let token = try? String(contentsOf: tokenFile, encoding: .utf8), UInt64(token) != nil {
            _ = try? pf(["-X", token])
            try FileManager.default.removeItem(at: tokenFile)
        }
    }

    private enum FirewallError: Error { case operationFailed }

    private static func pf(_ args: [String], input: String? = nil) throws -> String {
        let process = Process()
        let output = Pipe()
        let stdin = input.map { _ in Pipe() }
        process.executableURL = URL(fileURLWithPath: "/sbin/pfctl")
        process.arguments = args
        process.standardInput = stdin.map { $0 as Any } ?? FileHandle.nullDevice
        process.standardOutput = output
        process.standardError = output
        try process.run()
        if let input, let handle = stdin?.fileHandleForWriting {
            try handle.write(contentsOf: Data(input.utf8))
            try handle.close()
        }
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else { throw FirewallError.operationFailed }
        let result = String(decoding: data, as: UTF8.self)
        if args.last == "-sr" {
            return result.split(separator: "\n")
                .filter { !$0.hasPrefix("No ALTQ support") && !$0.hasPrefix("ALTQ related functions disabled") }
                .joined(separator: "\n")
        }
        return result
    }
}
