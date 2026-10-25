package com.apo.hypper.net.tls;

import com.apo.hypper.AppLog;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * Простой HTTP/1.1-клиент для подписок. TLS: сначала системный (с расширенным набором корней),
 * если сервер его отверг — встроенный TLS 1.3.
 */
public final class Https {
    private static final Charset UTF8 = Charset.forName("UTF-8");
    /** Хосты, которым системный TLS не подошёл — сразу идём через свой. */
    private static final Set<String> NEED_BUILTIN = Collections.synchronizedSet(new HashSet<String>());

    private Https() {
    }

    public static class Response {
        public int code;
        public final Map<String, String> headers = new HashMap<String, String>();
        public byte[] body;

        public String header(String name) {
            return headers.get(name.toLowerCase(Locale.US));
        }
    }

    public static Response get(URL url, String userAgent, boolean insecure) throws IOException {
        for (int redirects = 0; ; redirects++) {
            Response r = once(url, userAgent, insecure);
            if (r.code >= 300 && r.code < 400 && redirects < 5) {
                String loc = r.header("location");
                if (loc == null) throw new IOException("Перенаправление без адреса");
                url = new URL(url, loc);
                continue;
            }
            return r;
        }
    }

    private static Response once(URL url, String ua, boolean insecure) throws IOException {
        String host = url.getHost();
        boolean https = "https".equalsIgnoreCase(url.getProtocol());
        int port = url.getPort() > 0 ? url.getPort() : https ? 443 : 80;
        InputStream in;
        OutputStream out;
        Socket raw = open(host, port);
        try {
            if (!https) {
                in = raw.getInputStream();
                out = raw.getOutputStream();
            } else if (NEED_BUILTIN.contains(host)) {
                Tls13 t = Tls13.connect(raw, host, new String[]{"http/1.1"}, insecure);
                in = t.getInputStream();
                out = t.getOutputStream();
            } else {
                try {
                    SSLSocket s = systemTls(raw, host, port, insecure);
                    in = s.getInputStream();
                    out = s.getOutputStream();
                } catch (SSLException e) {
                    // старый OpenSSL не договорился с сервером — пробуем свой TLS 1.3
                    AppLog.i(host + ": системный TLS не подошёл (" + e.getMessage() + "), пробую встроенный TLS 1.3");
                    raw.close();
                    raw = open(host, port);
                    Tls13 t = Tls13.connect(raw, host, new String[]{"http/1.1"}, insecure);
                    NEED_BUILTIN.add(host);
                    in = t.getInputStream();
                    out = t.getOutputStream();
                }
            }
            String path = url.getFile().length() == 0 ? "/" : url.getFile();
            String req = "GET " + path + " HTTP/1.1\r\n"
                    + "Host: " + host + (url.getPort() > 0 ? ":" + url.getPort() : "") + "\r\n"
                    + "User-Agent: " + ua + "\r\n"
                    + "Accept: */*\r\n"
                    + "Accept-Encoding: identity\r\n"
                    + "Connection: close\r\n\r\n";
            out.write(req.getBytes(UTF8));
            out.flush();
            return readResponse(new BufferedInputStream(in, 16384));
        } finally {
            raw.close();
        }
    }

    private static Socket open(String host, int port) throws IOException {
        Socket s = new Socket();
        s.connect(new InetSocketAddress(host, port), 15000);
        s.setSoTimeout(20000);
        return s;
    }

    private static SSLSocket systemTls(Socket raw, String host, int port, boolean insecure) throws IOException {
        SSLSocketFactory f;
        if (insecure) {
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
                }}, null);
                f = ctx.getSocketFactory();
            } catch (Exception e) {
                throw new IOException("TLS: " + e);
            }
        } else {
            f = Trust.systemFactory();
        }
        SSLSocket s = (SSLSocket) f.createSocket(raw, host, port, true);
        enableModern(s, host);
        s.startHandshake();
        if (!insecure) {
            java.security.cert.Certificate[] chain = s.getSession().getPeerCertificates();
            if (chain.length == 0 || !Trust.matchesHost((X509Certificate) chain[0], host)) {
                s.close();
                throw new IOException("Сертификат не соответствует имени " + host);
            }
        }
        return s;
    }

    /** Включает TLS 1.1/1.2 (на API 16–19 они выключены по умолчанию) и SNI. */
    public static void enableModern(SSLSocket s, String host) {
        List<String> want = new ArrayList<String>();
        List<String> sup = Arrays.asList(s.getSupportedProtocols());
        for (String p : new String[]{"TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1"}) if (sup.contains(p)) want.add(p);
        s.setEnabledProtocols(want.toArray(new String[0]));
        if (!host.matches("[0-9.]+") && host.indexOf(':') < 0) {
            try {
                Method m = s.getClass().getMethod("setHostname", String.class);
                m.invoke(s, host);
            } catch (Exception ignored) {
            }
        }
    }

    private static Response readResponse(InputStream in) throws IOException {
        Response r = new Response();
        String status = line(in);
        if (status == null || !status.startsWith("HTTP/")) throw new IOException("Неверный ответ сервера");
        String[] parts = status.split(" ");
        r.code = parts.length > 1 ? Integer.parseInt(parts[1]) : 0;
        String l;
        while ((l = line(in)) != null && l.length() > 0) {
            int colon = l.indexOf(':');
            if (colon > 0) r.headers.put(l.substring(0, colon).trim().toLowerCase(Locale.US), l.substring(colon + 1).trim());
        }
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        String te = r.header("transfer-encoding");
        String cl = r.header("content-length");
        if (te != null && te.toLowerCase(Locale.US).contains("chunked")) {
            while (true) {
                String size = line(in);
                if (size == null) break;
                int semi = size.indexOf(';');
                int n = Integer.parseInt((semi >= 0 ? size.substring(0, semi) : size).trim(), 16);
                if (n == 0) break;
                copy(in, body, n);
                line(in);
            }
        } else if (cl != null) {
            copy(in, body, Integer.parseInt(cl.trim()));
        } else {
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) {
                body.write(buf, 0, n);
                if (body.size() > 8 << 20) throw new IOException("Слишком большой ответ");
            }
        }
        r.body = body.toByteArray();
        return r;
    }

    private static void copy(InputStream in, ByteArrayOutputStream out, int n) throws IOException {
        if (n > 8 << 20) throw new IOException("Слишком большой ответ");
        byte[] buf = new byte[8192];
        while (n > 0) {
            int r = in.read(buf, 0, Math.min(buf.length, n));
            if (r < 0) throw new IOException("Соединение оборвалось");
            out.write(buf, 0, r);
            n -= r;
        }
    }

    private static String line(InputStream in) throws IOException {
        StringBuilder sb = new StringBuilder();
        int c;
        while ((c = in.read()) >= 0) {
            if (c == '\n') break;
            if (c != '\r') sb.append((char) c);
            if (sb.length() > 65536) throw new IOException("Слишком длинная строка");
        }
        if (c < 0 && sb.length() == 0) return null;
        return sb.toString();
    }
}
