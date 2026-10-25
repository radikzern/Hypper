package com.apo.hypper.net.wg;

import java.io.ByteArrayOutputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.zip.Inflater;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/** Конфигурация WireGuard / AmneziaWG: .conf, wireguard:// и vpn:// (Amnezia). */
public class WgConfig {
    static final Charset UTF8 = Charset.forName("UTF-8");
    /** Параметры AmneziaWG в каноническом написании. */
    public static final String[] AWG_KEYS = {"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4",
            "H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "I5"};

    public String privateKey = "";
    public final List<String> address = new ArrayList<String>();
    public final List<String> dns = new ArrayList<String>();
    public int mtu = 0;
    public String publicKey = "";
    public String presharedKey = "";
    public String host = "";
    public int port = 51820;
    public final List<String> allowedIps = new ArrayList<String>();
    public int keepalive = 0;
    /** 3 байта reserved в заголовке (Cloudflare WARP), пусто — нули. */
    public String reserved = "";
    public final Map<String, String> awg = new LinkedHashMap<String, String>();

    public boolean isAmnezia() {
        for (String k : AWG_KEYS) {
            String v = awg.get(k);
            if (v == null || v.length() == 0) continue;
            if (k.startsWith("H") && v.equals(String.valueOf(k.charAt(1) - '0'))) continue;
            if (v.equals("0")) continue;
            return true;
        }
        return false;
    }

    public int mtuOrDefault() {
        return mtu > 0 ? mtu : 1420;
    }

    public void validate() throws IllegalArgumentException {
        if (key(privateKey) == null) throw new IllegalArgumentException("Неверный PrivateKey");
        if (key(publicKey) == null) throw new IllegalArgumentException("Неверный PublicKey пира");
        if (presharedKey.length() > 0 && key(presharedKey) == null)
            throw new IllegalArgumentException("Неверный PresharedKey");
        if (host.length() == 0) throw new IllegalArgumentException("Нет Endpoint");
        if (port < 1 || port > 65535) throw new IllegalArgumentException("Неверный порт Endpoint");
        if (address.isEmpty()) throw new IllegalArgumentException("Нет Address в [Interface]");
    }

    /** Новая пара ключей: {private, public} в base64. */
    public static String[] generateKeyPair() {
        byte[] priv = X25519.generatePrivate();
        return new String[]{B64.encode(priv), B64.encode(X25519.publicKey(priv))};
    }

    /** Публичный ключ для приватного, либо null. */
    public static String publicFor(String privB64) {
        byte[] k = key(privB64);
        return k == null ? null : B64.encode(X25519.publicKey(k));
    }

    /** 32-байтный ключ из base64, либо null. */
    public static byte[] key(String b64) {
        byte[] k = B64.decode(b64.trim());
        return k != null && k.length == 32 ? k : null;
    }

    // ---------------------------------------------------------------- .conf

    public static boolean looksLikeConf(String text) {
        return text.contains("[Interface]") || text.contains("[interface]");
    }

    public static WgConfig parseConf(String text) throws IllegalArgumentException {
        WgConfig c = new WgConfig();
        String section = "";
        boolean peerSeen = false;
        for (String raw : text.split("\\r?\\n")) {
            String line = raw.trim();
            int hash = line.indexOf('#');
            if (hash == 0) continue;
            if (line.length() == 0 || line.startsWith(";")) continue;
            if (line.startsWith("[")) {
                section = line.toLowerCase(Locale.US);
                if (section.equals("[peer]")) {
                    // поддерживаем только одного пира — берём первого
                    if (peerSeen) section = "[skip]";
                    peerSeen = true;
                }
                continue;
            }
            int eq = line.indexOf('=');
            if (eq < 0) continue;
            String k = line.substring(0, eq).trim();
            String v = line.substring(eq + 1).trim();
            String kl = k.toLowerCase(Locale.US);
            if (section.equals("[interface]")) {
                if (kl.equals("privatekey")) c.privateKey = v;
                else if (kl.equals("address")) addAll(c.address, v);
                else if (kl.equals("dns")) addAll(c.dns, v);
                else if (kl.equals("mtu")) c.mtu = toInt(v, 0);
                else {
                    String canon = awgKey(k);
                    if (canon != null) c.awg.put(canon, v);
                }
            } else if (section.equals("[peer]")) {
                if (kl.equals("publickey")) c.publicKey = v;
                else if (kl.equals("presharedkey")) c.presharedKey = v;
                else if (kl.equals("endpoint")) c.setEndpoint(v);
                else if (kl.equals("allowedips")) addAll(c.allowedIps, v);
                else if (kl.equals("persistentkeepalive")) c.keepalive = toInt(v, 0);
            }
        }
        if (c.allowedIps.isEmpty()) c.allowedIps.add("0.0.0.0/0");
        c.validate();
        return c;
    }

    public String toConf() {
        StringBuilder sb = new StringBuilder("[Interface]\n");
        sb.append("PrivateKey = ").append(privateKey).append('\n');
        sb.append("Address = ").append(join(address)).append('\n');
        if (!dns.isEmpty()) sb.append("DNS = ").append(join(dns)).append('\n');
        if (mtu > 0) sb.append("MTU = ").append(mtu).append('\n');
        for (Map.Entry<String, String> e : awg.entrySet()) {
            sb.append(e.getKey()).append(" = ").append(e.getValue()).append('\n');
        }
        sb.append("\n[Peer]\n");
        sb.append("PublicKey = ").append(publicKey).append('\n');
        if (presharedKey.length() > 0) sb.append("PresharedKey = ").append(presharedKey).append('\n');
        sb.append("Endpoint = ").append(endpoint()).append('\n');
        sb.append("AllowedIPs = ").append(join(allowedIps)).append('\n');
        if (keepalive > 0) sb.append("PersistentKeepalive = ").append(keepalive).append('\n');
        return sb.toString();
    }

    public String endpoint() {
        return (host.indexOf(':') >= 0 ? "[" + host + "]" : host) + ":" + port;
    }

    void setEndpoint(String v) {
        if (v.startsWith("[")) {
            int close = v.indexOf(']');
            host = v.substring(1, close);
            port = toInt(v.substring(close + 2), 51820);
        } else {
            int colon = v.lastIndexOf(':');
            if (colon < 0) {
                host = v;
            } else {
                host = v.substring(0, colon);
                port = toInt(v.substring(colon + 1), 51820);
            }
        }
    }

    // ---------------------------------------------------------------- wireguard://

    public static WgConfig parseUri(String uri) throws IllegalArgumentException {
        String s = uri.trim();
        int scheme = s.indexOf("://");
        s = s.substring(scheme + 3);
        int hash = s.indexOf('#');
        if (hash >= 0) s = s.substring(0, hash);
        Map<String, String> q = new LinkedHashMap<String, String>();
        int qm = s.indexOf('?');
        if (qm >= 0) {
            for (String kv : s.substring(qm + 1).split("&")) {
                int eq = kv.indexOf('=');
                if (eq > 0) q.put(decode(kv.substring(0, eq)).toLowerCase(Locale.US), decode(kv.substring(eq + 1)));
            }
            s = s.substring(0, qm);
        }
        if (s.endsWith("/")) s = s.substring(0, s.length() - 1);
        WgConfig c = new WgConfig();
        int at = s.lastIndexOf('@');
        if (at <= 0) throw new IllegalArgumentException("Нет приватного ключа в ссылке");
        c.privateKey = decode(s.substring(0, at));
        c.setEndpoint(s.substring(at + 1));
        c.publicKey = first(q, "publickey", "public_key", "peer_public_key", "pbk");
        c.presharedKey = first(q, "presharedkey", "pre_shared_key", "psk");
        addAll(c.address, first(q, "address", "ip", "local_address", "addresses"));
        addAll(c.dns, first(q, "dns"));
        addAll(c.allowedIps, first(q, "allowedips", "allowed_ips"));
        if (c.allowedIps.isEmpty()) c.allowedIps.add("0.0.0.0/0");
        c.mtu = toInt(first(q, "mtu"), 0);
        c.keepalive = toInt(first(q, "keepalive", "persistentkeepalive"), 0);
        c.reserved = first(q, "reserved");
        for (String k : AWG_KEYS) {
            String v = q.get(k.toLowerCase(Locale.US));
            if (v != null && v.length() > 0) c.awg.put(k, v);
        }
        c.validate();
        return c;
    }

    public String toUri(String name) {
        StringBuilder sb = new StringBuilder("wireguard://");
        sb.append(encode(privateKey)).append('@').append(endpoint());
        sb.append("?publickey=").append(encode(publicKey));
        if (presharedKey.length() > 0) sb.append("&presharedkey=").append(encode(presharedKey));
        sb.append("&address=").append(encode(join(address)));
        if (!dns.isEmpty()) sb.append("&dns=").append(encode(join(dns)));
        sb.append("&allowedips=").append(encode(join(allowedIps)));
        if (mtu > 0) sb.append("&mtu=").append(mtu);
        if (keepalive > 0) sb.append("&keepalive=").append(keepalive);
        if (reserved.length() > 0) sb.append("&reserved=").append(encode(reserved));
        for (Map.Entry<String, String> e : awg.entrySet()) {
            sb.append('&').append(e.getKey().toLowerCase(Locale.US)).append('=').append(encode(e.getValue()));
        }
        if (name.length() > 0) sb.append('#').append(encode(name));
        return sb.toString();
    }

    // ---------------------------------------------------------------- vpn:// (Amnezia)

    /** Результат разбора ключа Amnezia: конфиг и имя. */
    public static class Named {
        public final WgConfig config;
        public final String name;

        Named(WgConfig config, String name) {
            this.config = config;
            this.name = name;
        }
    }

    /** Ключ vpn:// из приложения Amnezia: base64url(qCompress(JSON)). */
    public static Named parseAmnezia(String uri) throws IllegalArgumentException {
        byte[] packed = B64.decode(uri.trim().substring(6));
        if (packed == null || packed.length < 5) throw new IllegalArgumentException("Повреждённый ключ vpn://");
        String json;
        try {
            Inflater inf = new Inflater();
            inf.setInput(packed, 4, packed.length - 4); // первые 4 байта — длина (qCompress)
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            while (!inf.finished()) {
                int n = inf.inflate(buf);
                if (n == 0 && (inf.needsInput() || inf.needsDictionary())) break;
                out.write(buf, 0, n);
            }
            inf.end();
            json = new String(out.toByteArray(), UTF8);
        } catch (Exception e) {
            // некоторые версии кладут JSON без сжатия
            json = new String(packed, UTF8);
        }
        try {
            JSONObject root = new JSONObject(json);
            String dns1 = root.optString("dns1", "1.1.1.1");
            String dns2 = root.optString("dns2", "1.0.0.1");
            String name = root.optString("description", "");
            JSONArray containers = root.optJSONArray("containers");
            if (containers == null) throw new IllegalArgumentException("В ключе нет контейнеров");
            String unsupported = null;
            for (int i = 0; i < containers.length(); i++) {
                JSONObject cont = containers.getJSONObject(i);
                for (String proto : new String[]{"awg", "wireguard"}) {
                    JSONObject p = cont.optJSONObject(proto);
                    if (p == null) continue;
                    String last = p.optString("last_config", "");
                    String conf = last.length() > 0 ? new JSONObject(last).optString("config", "") : "";
                    if (conf.length() == 0) continue;
                    conf = conf.replace("$PRIMARY_DNS", dns1).replace("$SECONDARY_DNS", dns2);
                    return new Named(parseConf(conf), name);
                }
                if (unsupported == null) unsupported = cont.optString("container");
            }
            throw new IllegalArgumentException(unsupported != null
                    ? "Протокол «" + unsupported + "» из ключа Amnezia не поддерживается, нужен AmneziaWG или WireGuard"
                    : "В ключе нет конфигурации WireGuard");
        } catch (JSONException e) {
            throw new IllegalArgumentException("Не удалось разобрать ключ vpn://");
        }
    }

    // ---------------------------------------------------------------- утилиты

    private static String awgKey(String k) {
        for (String a : AWG_KEYS) if (a.equalsIgnoreCase(k)) return a;
        return null;
    }

    private static String first(Map<String, String> q, String... keys) {
        for (String k : keys) {
            String v = q.get(k);
            if (v != null && v.length() > 0) return v;
        }
        return "";
    }

    private static void addAll(List<String> list, String v) {
        for (String part : v.split(",")) {
            String t = part.trim();
            if (t.length() > 0) list.add(t);
        }
    }

    private static String join(List<String> l) {
        StringBuilder sb = new StringBuilder();
        for (String s : l) sb.append(sb.length() == 0 ? "" : ", ").append(s);
        return sb.toString();
    }

    static int toInt(String s, int def) {
        try {
            return Integer.parseInt(s.trim());
        } catch (NumberFormatException e) {
            return def;
        }
    }

    private static String decode(String s) {
        try {
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
