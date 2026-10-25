package com.apo.hypper.net;

import com.apo.hypper.Profile;
import com.apo.hypper.net.tls.Https;
import com.apo.hypper.net.tls.Reality;
import com.apo.hypper.net.tls.Tls13;
import com.apo.hypper.net.tls.Trust;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/** Открывает VLESS-соединения к серверу из профиля (TCP / TLS / WebSocket). */
public class VlessClient {
    public static final int CMD_TCP = 1;
    public static final int CMD_UDP = 2;

    static final Charset UTF8 = Charset.forName("UTF-8");
    private static final int CONNECT_TIMEOUT = 10000;
    private static final SecureRandom RANDOM = new SecureRandom();

    public interface Protector {
        /** VpnService.protect: сокет к серверу не должен попасть в собственный туннель. */
        boolean protect(Socket s);
    }

    private final Profile profile;
    private final byte[] uuid;
    private final InetAddress server;
    private final Protector protector;
    private SSLSocketFactory sslFactory;
    /** Сервер не принял системный TLS — используем встроенный TLS 1.3. */
    private volatile boolean builtinTls;

    /** server — заранее разрешённый адрес (DNS резолвим до поднятия VPN). */
    public VlessClient(Profile profile, InetAddress server, Protector protector) {
        this.profile = profile;
        this.uuid = Profile.uuidBytes(profile.uuid);
        this.server = server;
        this.protector = protector;
    }

    public static class Conn {
        public final InputStream in;
        public final OutputStream out;
        private final Socket socket;

        Conn(Socket socket, InputStream in, OutputStream out) {
            this.socket = socket;
            this.in = in;
            this.out = out;
        }

        public void setTimeout(int ms) {
            try {
                socket.setSoTimeout(ms);
            } catch (IOException ignored) {
            }
        }

        public void close() {
            try {
                socket.close();
            } catch (IOException ignored) {
            }
        }
    }

    /**
     * @param host домен или IP-литерал
     * @param ip   IP-адрес (4 или 16 байт) или null, тогда используется host
     */
    private Socket openRaw() throws IOException {
        Socket raw = new Socket();
        if (protector != null) {
            // на Android 4.x дескриптор создаётся лениво — bind() создаёт его до protect()
            raw.bind(null);
            if (!protector.protect(raw)) {
                raw.close();
                throw new IOException("protect() не удался");
            }
        }
        try {
            raw.setTcpNoDelay(true);
            raw.setKeepAlive(true);
            raw.connect(new InetSocketAddress(server, profile.port), CONNECT_TIMEOUT);
            raw.setSoTimeout(15000);
        } catch (IOException e) {
            raw.close();
            throw e;
        }
        return raw;
    }

    public Conn connect(int cmd, String host, byte[] ip, int port) throws IOException {
        Socket raw = openRaw();
        try {
            InputStream in;
            OutputStream out;
            if (Profile.SEC_REALITY.equals(profile.security)) {
                // REALITY можно сделать только встроенным TLS 1.3: нужен контроль над session_id.
                boolean ws = Profile.NET_WS.equals(profile.network);
                Tls13 t = Tls13.connect(raw, sniHost(), ws ? new String[]{"http/1.1"} : null,
                        Reality.fromProfile(profile));
                in = t.getInputStream();
                out = t.getOutputStream();
            } else if (Profile.SEC_TLS.equals(profile.security)) {
                boolean ws = Profile.NET_WS.equals(profile.network);
                if (!builtinTls) {
                    try {
                        SSLSocket ss = tls(raw);
                        in = ss.getInputStream();
                        out = ss.getOutputStream();
                        return finish(raw, in, out, cmd, host, ip, port);
                    } catch (SSLException e) {
                        // старый OpenSSL не договорился с сервером — переходим на встроенный TLS 1.3
                        com.apo.hypper.AppLog.i(sniHost() + ": системный TLS не подошёл, включаю встроенный TLS 1.3");
                        raw.close();
                        raw = openRaw();
                        builtinTls = true;
                    }
                }
                Tls13 t = Tls13.connect(raw, sniHost(), ws ? new String[]{"http/1.1"} : null, profile.insecure);
                in = t.getInputStream();
                out = t.getOutputStream();
            } else {
                in = raw.getInputStream();
                out = raw.getOutputStream();
            }
            return finish(raw, in, out, cmd, host, ip, port);
        } catch (IOException e) {
            try {
                raw.close();
            } catch (IOException ignored) {
            }
            throw e;
        }
    }

    private Conn finish(Socket raw, InputStream in, OutputStream out, int cmd, String host, byte[] ip, int port)
            throws IOException {
        in = new BufferedInputStream(in, 16384);
        if (Profile.NET_WS.equals(profile.network)) {
            WebSocket ws = new WebSocket(in, out);
            ws.handshake(wsHost(), wsPath());
            in = ws.input();
            out = ws.output();
        }
        raw.setSoTimeout(0);
        // Vision применяется только к TCP: у UDP (в т.ч. DNS) своя обёртка пакетов,
        // padding-кадры её сломали бы — поэтому UDP идёт как обычный VLESS, без flow.
        boolean vision = cmd == CMD_TCP && visionEnabled();
        out.write(header(cmd, host, ip, port, vision));
        out.flush();
        InputStream cin = new ResponseStripper(in);
        if (vision) {
            Vision v = new Vision(uuid);
            // сразу шлём кадр-камуфляж, чтобы скрыть VLESS-заголовок (как при пустой первой посылке в xray)
            out.write(v.firstPadding());
            out.flush();
            out = v.wrap(out);
            cin = v.wrap(cin);
        }
        return new Conn(raw, cin, out);
    }

    /** XTLS Vision возможен только по raw-TCP под TLS или REALITY. */
    private boolean visionEnabled() {
        return Profile.FLOW_VISION.equals(profile.flow)
                && Profile.NET_TCP.equals(profile.network)
                && (Profile.SEC_TLS.equals(profile.security) || Profile.SEC_REALITY.equals(profile.security));
    }

    byte[] header(int cmd, String host, byte[] ip, int port) {
        return header(cmd, host, ip, port, false);
    }

    byte[] header(int cmd, String host, byte[] ip, int port, boolean vision) {
        ByteArrayOutputStream b = new ByteArrayOutputStream(64);
        b.write(0); // версия
        b.write(uuid, 0, 16);
        if (vision) {
            // addons: protobuf Addons{ Flow=1: "xtls-rprx-vision" } = 0x0a 0x10 <16 байт>
            byte[] flow = Vision.FLOW.getBytes(UTF8);
            b.write(2 + flow.length); // длина addons
            b.write(0x0a);            // поле 1, wire-type 2 (string)
            b.write(flow.length);     // длина строки (0x10 = 16)
            b.write(flow, 0, flow.length);
        } else {
            b.write(0); // длина addons
        }
        b.write(cmd);
        b.write(port >> 8);
        b.write(port & 0xff);
        if (ip == null) ip = parseIpv4(host);
        if (ip != null && ip.length == 4) {
            b.write(1);
            b.write(ip, 0, 4);
        } else if (ip != null && ip.length == 16) {
            b.write(3);
            b.write(ip, 0, 16);
        } else {
            byte[] d = host.getBytes(UTF8);
            b.write(2);
            b.write(d.length);
            b.write(d, 0, d.length);
        }
        return b.toByteArray();
    }

    public static boolean isIpLiteral(String s) {
        return parseIpv4(s.trim()) != null || s.indexOf(':') >= 0;
    }

    static byte[] parseIpv4(String s) {
        String[] parts = s.split("\\.");
        if (parts.length != 4) return null;
        byte[] r = new byte[4];
        for (int i = 0; i < 4; i++) {
            if (parts[i].length() == 0 || parts[i].length() > 3) return null;
            int v = 0;
            for (int j = 0; j < parts[i].length(); j++) {
                char c = parts[i].charAt(j);
                if (c < '0' || c > '9') return null;
                v = v * 10 + (c - '0');
            }
            if (v > 255) return null;
            r[i] = (byte) v;
        }
        return r;
    }

    private String sniHost() {
        if (profile.sni.length() > 0) return profile.sni;
        if (Profile.NET_WS.equals(profile.network) && profile.wsHost.length() > 0) return profile.wsHost;
        return profile.address;
    }

    private String wsHost() {
        if (profile.wsHost.length() > 0) return profile.wsHost;
        if (profile.sni.length() > 0) return profile.sni;
        return profile.address;
    }

    private String wsPath() {
        String p = profile.path.length() == 0 ? "/" : profile.path;
        if (!p.startsWith("/")) p = "/" + p;
        // ?ed=2048 — инструкция клиенту про early data, серверу её передавать нельзя
        int q = p.indexOf('?');
        if (q >= 0) {
            StringBuilder rest = new StringBuilder();
            for (String kv : p.substring(q + 1).split("&")) {
                if (kv.length() == 0 || kv.startsWith("ed=")) continue;
                rest.append(rest.length() == 0 ? "" : "&").append(kv);
            }
            p = p.substring(0, q) + (rest.length() > 0 ? "?" + rest : "");
        }
        return p;
    }

    private SSLSocket tls(Socket raw) throws IOException {
        String sni = sniHost();
        SSLSocket ss = (SSLSocket) factory().createSocket(raw, sni, profile.port, true);
        Https.enableModern(ss, sni);
        ss.startHandshake();
        if (!profile.insecure) {
            java.security.cert.Certificate[] chain = ss.getSession().getPeerCertificates();
            if (chain.length == 0 || !Trust.matchesHost((X509Certificate) chain[0], sni)) {
                ss.close();
                throw new IOException("Сертификат не соответствует имени " + sni);
            }
        }
        return ss;
    }

    private synchronized SSLSocketFactory factory() throws IOException {
        if (sslFactory != null) return sslFactory;
        if (!profile.insecure) {
            sslFactory = Trust.systemFactory();
        } else {
            try {
                SSLContext ctx = SSLContext.getInstance("TLS");
                ctx.init(null, new TrustManager[]{new X509TrustManager() {
                    public void checkClientTrusted(X509Certificate[] c, String a) {
                    }

                    public void checkServerTrusted(X509Certificate[] c, String a) {
                    }

                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                }}, RANDOM);
                sslFactory = ctx.getSocketFactory();
            } catch (Exception e) {
                throw new IOException("SSLContext: " + e);
            }
        }
        return sslFactory;
    }

    static byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        RANDOM.nextBytes(b);
        return b;
    }

    /** Срезает заголовок ответа VLESS (версия, addons) перед первыми данными. */
    static class ResponseStripper extends FilterInputStream {
        private boolean stripped;

        ResponseStripper(InputStream in) {
            super(in);
        }

        private void strip() throws IOException {
            if (stripped) return;
            stripped = true;
            int ver = in.read();
            int len = in.read();
            if (ver < 0 || len < 0) throw new EOFException("Сервер закрыл соединение (неверный UUID?)");
            while (len-- > 0) if (in.read() < 0) throw new EOFException();
        }

        @Override
        public int read() throws IOException {
            strip();
            return in.read();
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            strip();
            return in.read(b, off, len);
        }
    }
}
