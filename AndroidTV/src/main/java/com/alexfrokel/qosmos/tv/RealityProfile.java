package com.alexfrokel.qosmos.tv;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

final class RealityProfile {
    static final int MAX_BYTES = 256 * 1024;
    static final String V4 = "198.18.10.1";
    static final String V6 = "fd70:149:118::1";

    private static final Set<String> FIELDS = set(
        "security", "type", "encryption", "headerType", "flow", "sni", "pbk", "sid", "fp", "spx");
    private static final Set<String> FINGERPRINTS = set(
        "chrome", "firefox", "safari", "ios", "edge", "android", "360", "qq", "random", "randomized");

    final String link;
    final String name;
    final String host;
    final int port;
    private final String id;
    private final String sni;
    private final String publicKey;
    private final String shortId;
    private final String fingerprint;
    private final String flow;

    private RealityProfile(String link) {
        URI uri = URI.create(link);
        if (!"vless".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null
                || uri.getUserInfo() == null || (uri.getPort() != -1 && (uri.getPort() < 1 || uri.getPort() > 65535))
                || (uri.getPath() != null && !uri.getPath().isEmpty() && !"/".equals(uri.getPath()))) {
            throw invalid();
        }

        this.link = link;
        String parsedHost = uri.getHost();
        host = parsedHost.startsWith("[") ? parsedHost.substring(1, parsedHost.length() - 1) : parsedHost;
        port = uri.getPort() == -1 ? 443 : uri.getPort();
        id = UUID.fromString(uri.getUserInfo()).toString();
        if (!id.equalsIgnoreCase(uri.getUserInfo())) throw invalid();

        Map<String, String> query = new LinkedHashMap<>();
        if (uri.getRawQuery() == null) throw invalid();
        for (String item : uri.getRawQuery().split("&")) {
            String[] fields = item.split("=", 2);
            if (fields.length != 2) throw invalid();
            String key = decode(fields[0]);
            if (!FIELDS.contains(key) || query.putIfAbsent(key, decode(fields[1])) != null) throw invalid();
        }
        String type = query.getOrDefault("type", "tcp");
        flow = query.getOrDefault("flow", "");
        if (!"reality".equals(query.get("security")) || !set("tcp", "raw").contains(type)
                || !"none".equals(query.getOrDefault("encryption", "none"))
                || !"none".equals(query.getOrDefault("headerType", "none"))
                || !set("", "/").contains(query.getOrDefault("spx", ""))
                || !set("", "xtls-rprx-vision").contains(flow)) throw invalid();

        sni = query.getOrDefault("sni", "");
        publicKey = query.getOrDefault("pbk", "");
        shortId = query.getOrDefault("sid", "");
        fingerprint = query.getOrDefault("fp", "chrome");
        if (!sni.matches("[A-Za-z0-9.-]{1,253}") || !publicKey.matches("[A-Za-z0-9_-]{43}")
                || Base64.getUrlDecoder().decode(publicKey).length != 32
                || !shortId.matches("(?:[0-9a-fA-F]{2}){0,8}") || !FINGERPRINTS.contains(fingerprint)) throw invalid();

        String title = uri.getFragment();
        if (title != null) title = title.replaceAll("[\\p{Cntrl}\\p{Cf}]", " ").trim();
        name = title == null || title.isEmpty() ? host : title.substring(0, Math.min(80, title.length()));
    }

    static List<RealityProfile> parseList(String text) {
        try {
            String source = text.replaceFirst("^\uFEFF", "").trim();
            if (!source.regionMatches(true, 0, "vless://", 0, 8) && !source.startsWith("#")) {
                String encoded = source.replaceAll("\\s+", "");
                Base64.Decoder decoder = encoded.matches(".*[-_].*") ? Base64.getUrlDecoder() : Base64.getDecoder();
                source = new String(decoder.decode(encoded), StandardCharsets.UTF_8).trim();
            }
            List<RealityProfile> profiles = new ArrayList<>();
            for (String line : source.split("\\r?\\n")) {
                String link = line.trim();
                if (link.isEmpty() || link.startsWith("#")) continue;
                if (profiles.size() == 50) throw invalid();
                profiles.add(new RealityProfile(link));
            }
            if (profiles.isEmpty()) throw invalid();
            return profiles;
        } catch (IllegalArgumentException e) {
            // URI and decoder exceptions may contain the original credentials.
            throw invalid();
        }
    }

    String endpoint() {
        return (host.contains(":") ? "[" + host + "]" : host) + ":" + port;
    }

    boolean sameEndpointAndCredentials(RealityProfile other) {
        return host.equalsIgnoreCase(other.host) && port == other.port && id.equals(other.id)
            && sni.equalsIgnoreCase(other.sni) && publicKey.equals(other.publicKey)
            && shortId.equalsIgnoreCase(other.shortId) && fingerprint.equals(other.fingerprint) && flow.equals(other.flow);
    }

    String config() throws JSONException {
        JSONObject vpn = json("type", "vless", "tag", "vpn", "server", host, "server_port", port,
            "uuid", id, "flow", flow, "tls", json("enabled", true, "server_name", sni,
                "utls", json("enabled", true, "fingerprint", fingerprint),
                "reality", json("enabled", true, "public_key", publicKey, "short_id", shortId)));
        JSONObject tls = json("enabled", true, "server_name", "cloudflare-dns.com");
        JSONArray resolvers = array(json("type", "https", "tag", "vpn-dns", "server", "1.1.1.1",
            "tls", tls, "detour", "vpn"));
        if (!host.contains(":") && !host.matches("[0-9.]+")) {
            vpn.put("domain_resolver", "bootstrap");
            resolvers.put(json("type", "https", "tag", "bootstrap", "server", "1.1.1.1", "tls", tls));
        }
        return json("log", json("disabled", true),
            "inbounds", array(json("type", "tun", "address", array(V4 + "/30", V6 + "/126"),
                "mtu", 1400, "auto_route", true, "dns_mode", "hijack", "stack", "gvisor")),
            "outbounds", array(vpn),
            "dns", json("servers", resolvers, "final", "vpn-dns", "strategy", "prefer_ipv4"),
            "route", json("rules", array(json("port", 53, "action", "hijack-dns"),
                json("network", "udp", "port", 443, "action", "reject", "no_drop", true)), "final", "vpn")
        ).toString();
    }

    private static JSONObject json(Object... values) throws JSONException {
        JSONObject object = new JSONObject();
        for (int i = 0; i < values.length; i += 2) object.put((String) values[i], values[i + 1]);
        return object;
    }

    private static JSONArray array(Object... values) {
        JSONArray array = new JSONArray();
        for (Object value : values) array.put(value);
        return array;
    }

    private static Set<String> set(String... values) {
        return new HashSet<>(Arrays.asList(values));
    }

    private static String decode(String field) {
        try {
            return URLDecoder.decode(field, "UTF-8");
        } catch (java.io.UnsupportedEncodingException e) {
            throw new AssertionError(e);
        }
    }

    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("Нужны прямые ссылки VLESS + REALITY по TCP.");
    }
}
