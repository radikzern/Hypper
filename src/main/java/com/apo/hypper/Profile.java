package com.apo.hypper;

import com.apo.hypper.net.wg.WgConfig;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.LinkedHashMap;
import java.util.Map;

/** Один сервер: VLESS или WireGuard/AmneziaWG. Хранится как ссылка vless:// или wireguard://. */
public class Profile {
    public static final String PROTO_VLESS = "vless";
    public static final String PROTO_WG = "wireguard";
    public static final String SEC_NONE = "none";
    public static final String SEC_TLS = "tls";
    public static final String SEC_REALITY = "reality";
    public static final String NET_TCP = "tcp";
    public static final String NET_WS = "ws";
    /** Единственный поддерживаемый flow — XTLS Vision. */
    public static final String FLOW_VISION = "xtls-rprx-vision";

    public String protocol = PROTO_VLESS;
    /** Конфигурация для WireGuard/AmneziaWG, null для VLESS. */
    public WgConfig wg;

    public String name = "";
    public String address = "";
    public int port = 443;
    public String uuid = "";
    public String security = SEC_NONE;
    public String sni = "";
    public boolean insecure = false;
    public String network = NET_TCP;
    public String path = "/";
    public String wsHost = "";
    /** Не поддерживается, но сохраняем, чтобы показать предупреждение и не терять при экспорте. */
    public String flow = "";

    /** REALITY: публичный ключ сервера (pbk), base64url 32 байта. */
    public String publicKey = "";
    /** REALITY: короткий идентификатор (sid), hex, 0..8 байт. */
    public String shortId = "";
    /** REALITY: отпечаток браузера (fp). Не влияет на работу, сохраняем для экспорта. */
    public String fingerprint = "";
    /** REALITY: путь «паука» (spx). Не используется, сохраняем для экспорта. */
    public String spiderX = "";

    /** id подписки, из которой пришёл сервер; пусто — добавлен вручную. Не входит в ссылку. */
    public String sub = "";

    public static final int DELAY_UNKNOWN = 0;
    public static final int DELAY_TESTING = -1;
    public static final int DELAY_FAILED = -2;
    /** Результат проверки задержки, мс (не сохраняется). */
    public transient volatile int delay = DELAY_UNKNOWN;

    /** Уникальный ключ сервера для выбора и сравнения. */
    public String key() {
        return toUri();
    }

    public String title() {
        return name.length() > 0 ? name : address + ":" + port;
    }

    public boolean isWg() {
        return PROTO_WG.equals(protocol);
    }

    public String protocolName() {
        if (!isWg()) return "VLESS";
        return wg.isAmnezia() ? "AmneziaWG" : "WireGuard";
    }

    public String describe() {
        if (isWg()) return address + ":" + port + " · " + protocolName();
        StringBuilder sb = new StringBuilder();
        sb.append(address).append(':').append(port).append(" · ").append(network);
        if (SEC_TLS.equals(security)) sb.append("+tls");
        else if (SEC_REALITY.equals(security)) sb.append("+reality");
        return sb.toString();
    }

    /** Строка с причиной, по которой профиль работать не будет, либо null. */
    public String unsupportedReason() {
        if (isWg()) return null;
        if (flow.length() > 0) {
            if (!FLOW_VISION.equals(flow))
                return "flow=" + flow + " не поддерживается (поддерживается только " + FLOW_VISION + ")";
            if (!NET_TCP.equals(network))
                return "flow=" + flow + " работает только с type=tcp";
            if (!SEC_TLS.equals(security) && !SEC_REALITY.equals(security))
                return "flow=" + flow + " требует security=tls или reality";
        }
        if (!SEC_NONE.equals(security) && !SEC_TLS.equals(security) && !SEC_REALITY.equals(security))
            return "security=" + security + " не поддерживается";
        if (SEC_REALITY.equals(security) && com.apo.hypper.net.wg.B64.decode(publicKey) == null)
            return "reality: неверный публичный ключ (pbk)";
        if (!NET_TCP.equals(network) && !NET_WS.equals(network))
            return "type=" + network + " не поддерживается";
        return null;
    }

    public static boolean isLink(String s) {
        return s.regionMatches(true, 0, "vless://", 0, 8) || s.regionMatches(true, 0, "wireguard://", 0, 12)
                || s.regionMatches(true, 0, "wg://", 0, 5) || s.regionMatches(true, 0, "vpn://", 0, 6);
    }

    /** Сервер WireGuard/AmneziaWG из конфигурации. */
    public static Profile fromWg(WgConfig c, String name) {
        Profile p = new Profile();
        p.protocol = PROTO_WG;
        p.wg = c;
        p.name = name == null ? "" : name;
        p.address = c.host;
        p.port = c.port;
        return p;
    }

    public static Profile parse(String uri) throws IllegalArgumentException {
        String s = uri.trim();
        if (s.regionMatches(true, 0, "wireguard://", 0, 12) || s.regionMatches(true, 0, "wg://", 0, 5)) {
            int hash = s.indexOf('#');
            return fromWg(WgConfig.parseUri(s), hash >= 0 ? decode(s.substring(hash + 1)) : "");
        }
        if (s.regionMatches(true, 0, "vpn://", 0, 6)) {
            WgConfig.Named n = WgConfig.parseAmnezia(s);
            return fromWg(n.config, n.name);
        }
        if (!s.regionMatches(true, 0, "vless://", 0, 8))
            throw new IllegalArgumentException("Поддерживаются ссылки vless://, wireguard:// и vpn:// (Amnezia)");
        s = s.substring(8);
        Profile p = new Profile();

        int hash = s.indexOf('#');
        if (hash >= 0) {
            p.name = decode(s.substring(hash + 1));
            s = s.substring(0, hash);
        }
        Map<String, String> q = new LinkedHashMap<String, String>();
        int qm = s.indexOf('?');
        if (qm >= 0) {
            for (String kv : s.substring(qm + 1).split("&")) {
                if (kv.length() == 0) continue;
                int eq = kv.indexOf('=');
                if (eq < 0) q.put(decode(kv), "");
                else q.put(decode(kv.substring(0, eq)), decode(kv.substring(eq + 1)));
            }
            s = s.substring(0, qm);
        }
        if (s.endsWith("/")) s = s.substring(0, s.length() - 1);

        int at = s.lastIndexOf('@');
        if (at <= 0) throw new IllegalArgumentException("Нет UUID в ссылке");
        p.uuid = decode(s.substring(0, at));
        String hostPort = s.substring(at + 1);
        String portStr;
        if (hostPort.startsWith("[")) {
            int close = hostPort.indexOf(']');
            if (close < 0) throw new IllegalArgumentException("Неверный IPv6-адрес");
            p.address = hostPort.substring(1, close);
            portStr = hostPort.substring(close + 1);
            if (portStr.startsWith(":")) portStr = portStr.substring(1);
        } else {
            int colon = hostPort.lastIndexOf(':');
            if (colon < 0) throw new IllegalArgumentException("Нет порта в ссылке");
            p.address = hostPort.substring(0, colon);
            portStr = hostPort.substring(colon + 1);
        }
        try {
            p.port = Integer.parseInt(portStr);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Неверный порт: " + portStr);
        }

        p.security = lower(q, "security", SEC_NONE);
        p.network = lower(q, "type", NET_TCP);
        p.sni = get(q, "sni", get(q, "peer", ""));
        String ins = get(q, "allowInsecure", get(q, "insecure", "0"));
        p.insecure = "1".equals(ins) || "true".equalsIgnoreCase(ins);
        p.path = get(q, "path", "/");
        p.wsHost = get(q, "host", "");
        p.flow = get(q, "flow", "");
        p.publicKey = get(q, "pbk", "");
        p.shortId = get(q, "sid", "");
        p.fingerprint = get(q, "fp", "");
        p.spiderX = get(q, "spx", "");
        p.validate();
        return p;
    }

    public void validate() throws IllegalArgumentException {
        if (isWg()) {
            wg.validate();
            return;
        }
        if (address.length() == 0) throw new IllegalArgumentException("Не указан адрес");
        if (port < 1 || port > 65535) throw new IllegalArgumentException("Порт вне диапазона");
        uuidBytes(uuid);
        if (SEC_REALITY.equals(security)) {
            byte[] pk = com.apo.hypper.net.wg.B64.decode(publicKey);
            if (pk == null || pk.length != 32)
                throw new IllegalArgumentException("REALITY: pbk должен быть 32 байта в base64url");
        }
    }

    public String toUri() {
        if (isWg()) return wg.toUri(name);
        StringBuilder sb = new StringBuilder("vless://");
        sb.append(encode(uuid)).append('@');
        if (address.indexOf(':') >= 0) sb.append('[').append(address).append(']');
        else sb.append(address);
        sb.append(':').append(port);
        sb.append("?encryption=none&security=").append(security).append("&type=").append(network);
        if (sni.length() > 0) sb.append("&sni=").append(encode(sni));
        if (SEC_REALITY.equals(security)) {
            if (publicKey.length() > 0) sb.append("&pbk=").append(encode(publicKey));
            if (shortId.length() > 0) sb.append("&sid=").append(encode(shortId));
            if (fingerprint.length() > 0) sb.append("&fp=").append(encode(fingerprint));
            if (spiderX.length() > 0) sb.append("&spx=").append(encode(spiderX));
        }
        if (insecure) sb.append("&allowInsecure=1");
        if (NET_WS.equals(network)) {
            sb.append("&path=").append(encode(path));
            if (wsHost.length() > 0) sb.append("&host=").append(encode(wsHost));
        }
        if (flow.length() > 0) sb.append("&flow=").append(encode(flow));
        if (name.length() > 0) sb.append('#').append(encode(name));
        return sb.toString();
    }

    public static byte[] uuidBytes(String uuid) throws IllegalArgumentException {
        String hex = uuid.replace("-", "").trim();
        if (hex.length() != 32) throw new IllegalArgumentException("UUID должен быть вида xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx");
        byte[] out = new byte[16];
        for (int i = 0; i < 16; i++) {
            int hi = Character.digit(hex.charAt(i * 2), 16);
            int lo = Character.digit(hex.charAt(i * 2 + 1), 16);
            if (hi < 0 || lo < 0) throw new IllegalArgumentException("UUID содержит не-hex символы");
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    private static String get(Map<String, String> q, String k, String def) {
        String v = q.get(k);
        return v == null || v.length() == 0 ? def : v;
    }

    private static String lower(Map<String, String> q, String k, String def) {
        return get(q, k, def).toLowerCase();
    }

    private static String decode(String s) {
        try {
            // URLDecoder превращает '+' в пробел, в ссылках vless '+' обычно буквальный
            return URLDecoder.decode(s.replace("+", "%2B"), "UTF-8");
        } catch (UnsupportedEncodingException e) {
            return s;
        } catch (IllegalArgumentException e) {
            return s;
        }
    }

    private static String encode(String s) {
        try {
            return URLEncoder.encode(s, "UTF-8").replace("+", "%20");
        } catch (UnsupportedEncodingException e) {
            return s;
        }
    }
}
