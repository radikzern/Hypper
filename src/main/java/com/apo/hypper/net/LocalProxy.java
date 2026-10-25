package com.apo.hypper.net;

import com.apo.hypper.AppLog;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Locale;

/**
 * Локальный прокси на 127.0.0.1: SOCKS5 и HTTP (CONNECT и обычные запросы) на одном порту.
 * Протокол определяется по первому байту.
 */
public class LocalProxy {
    private volatile VlessClient client;
    private final int port;
    private final boolean listenAll;
    private ServerSocket server;
    private volatile boolean running;

    public LocalProxy(VlessClient client, int port, boolean listenAll) {
        this.client = client;
        this.port = port;
        this.listenAll = listenAll;
    }

    public void start() throws IOException {
        server = new ServerSocket();
        server.setReuseAddress(true);
        InetAddress bind = listenAll ? null : InetAddress.getByName("127.0.0.1");
        server.bind(new InetSocketAddress(bind, port), 64);
        running = true;
        Thread t = new Thread(new Runnable() {
            public void run() {
                acceptLoop();
            }
        }, "proxy-accept");
        t.setDaemon(true);
        t.start();
        AppLog.i("Прокси SOCKS5/HTTP: " + (listenAll ? "0.0.0.0" : "127.0.0.1") + ":" + port);
    }

    public void setClient(VlessClient c) {
        client = c;
    }

    public void stop() {
        running = false;
        try {
            if (server != null) server.close();
        } catch (IOException ignored) {
        }
    }

    private void acceptLoop() {
        while (running) {
            try {
                final Socket s = server.accept();
                Thread t = new Thread(new Runnable() {
                    public void run() {
                        handle(s);
                    }
                }, "proxy-conn");
                t.setDaemon(true);
                t.start();
            } catch (IOException e) {
                if (running) AppLog.e("accept: " + e.getMessage());
            }
        }
    }

    private void handle(Socket s) {
        VlessClient.Conn remote = null;
        try {
            s.setTcpNoDelay(true);
            s.setSoTimeout(30000);
            InputStream in = new BufferedInputStream(s.getInputStream(), 8192);
            OutputStream out = s.getOutputStream();
            in.mark(1);
            int first = in.read();
            if (first < 0) return;
            in.reset();
            byte[] pending;
            if (first == 5) {
                remote = socks5(in, out);
                pending = null;
            } else {
                Object[] r = http(in, out);
                remote = (VlessClient.Conn) r[0];
                pending = (byte[]) r[1];
            }
            if (remote == null) return;
            s.setSoTimeout(0);
            if (pending != null && pending.length > 0) {
                remote.out.write(pending);
                remote.out.flush();
            }
            Relay.pipe(s, in, out, remote);
        } catch (IOException e) {
            AppLog.d("proxy: " + e.getMessage());
        } finally {
            if (remote != null) remote.close();
            try {
                s.close();
            } catch (IOException ignored) {
            }
        }
    }

    private VlessClient.Conn socks5(InputStream in, OutputStream out) throws IOException {
        in.read(); // версия
        int nm = readN(in);
        for (int i = 0; i < nm; i++) readN(in);
        out.write(new byte[]{5, 0});
        out.flush();

        if (readN(in) != 5) throw new IOException("SOCKS: неверная версия");
        int cmd = readN(in);
        readN(in);
        int atyp = readN(in);
        String host;
        byte[] ip = null;
        if (atyp == 1) {
            ip = readBytes(in, 4);
            host = (ip[0] & 0xff) + "." + (ip[1] & 0xff) + "." + (ip[2] & 0xff) + "." + (ip[3] & 0xff);
        } else if (atyp == 3) {
            host = new String(readBytes(in, readN(in)), VlessClient.UTF8);
        } else if (atyp == 4) {
            ip = readBytes(in, 16);
            host = InetAddress.getByAddress(ip).getHostAddress();
        } else {
            throw new IOException("SOCKS: тип адреса " + atyp);
        }
        int port = (readN(in) << 8) | readN(in);
        if (cmd != 1) {
            // UDP ASSOCIATE и BIND не поддерживаются
            out.write(new byte[]{5, 7, 0, 1, 0, 0, 0, 0, 0, 0});
            out.flush();
            return null;
        }
        VlessClient.Conn c;
        try {
            c = client.connect(VlessClient.CMD_TCP, host, ip, port);
        } catch (IOException e) {
            out.write(new byte[]{5, 5, 0, 1, 0, 0, 0, 0, 0, 0});
            out.flush();
            throw e;
        }
        out.write(new byte[]{5, 0, 0, 1, 0, 0, 0, 0, 0, 0});
        out.flush();
        AppLog.d("SOCKS " + host + ":" + port);
        return c;
    }

    /** @return {Conn, байты для отправки на сервер} */
    private Object[] http(InputStream in, OutputStream out) throws IOException {
        String requestLine = readLine(in);
        if (requestLine == null) return new Object[]{null, null};
        ByteArrayOutputStream headers = new ByteArrayOutputStream();
        String hostHeader = null;
        String line;
        while ((line = readLine(in)) != null && line.length() > 0) {
            String lower = line.toLowerCase(Locale.US);
            if (lower.startsWith("proxy-")) continue;
            if (lower.startsWith("connection:") || lower.startsWith("keep-alive:")) continue;
            if (lower.startsWith("host:")) hostHeader = line.substring(5).trim();
            headers.write((line + "\r\n").getBytes(VlessClient.UTF8));
        }
        String[] parts = requestLine.split(" ");
        if (parts.length < 3) throw new IOException("HTTP: неверный запрос");
        String method = parts[0];

        if ("CONNECT".equalsIgnoreCase(method)) {
            String[] hp = splitHostPort(parts[1], 443);
            VlessClient.Conn c;
            try {
                c = client.connect(VlessClient.CMD_TCP, hp[0], null, Integer.parseInt(hp[1]));
            } catch (IOException e) {
                out.write("HTTP/1.1 502 Bad Gateway\r\n\r\n".getBytes(VlessClient.UTF8));
                out.flush();
                throw e;
            }
            out.write("HTTP/1.1 200 Connection established\r\n\r\n".getBytes(VlessClient.UTF8));
            out.flush();
            AppLog.d("CONNECT " + parts[1]);
            return new Object[]{c, null};
        }

        // Обычный запрос: http://host[:port]/path -> /path, соединение одноразовое
        String url = parts[1];
        String hostPort = hostHeader;
        String path = url;
        if (url.regionMatches(true, 0, "http://", 0, 7)) {
            int slash = url.indexOf('/', 7);
            hostPort = slash < 0 ? url.substring(7) : url.substring(7, slash);
            path = slash < 0 ? "/" : url.substring(slash);
        }
        if (hostPort == null) throw new IOException("HTTP: нет хоста");
        String[] hp = splitHostPort(hostPort, 80);
        VlessClient.Conn c;
        try {
            c = client.connect(VlessClient.CMD_TCP, hp[0], null, Integer.parseInt(hp[1]));
        } catch (IOException e) {
            out.write("HTTP/1.1 502 Bad Gateway\r\n\r\n".getBytes(VlessClient.UTF8));
            out.flush();
            throw e;
        }
        ByteArrayOutputStream req = new ByteArrayOutputStream();
        req.write((method + " " + path + " " + parts[2] + "\r\n").getBytes(VlessClient.UTF8));
        headers.writeTo(req);
        req.write("Connection: close\r\n\r\n".getBytes(VlessClient.UTF8));
        AppLog.d("HTTP " + method + " " + hostPort);
        return new Object[]{c, req.toByteArray()};
    }

    private static String[] splitHostPort(String s, int def) {
        if (s.startsWith("[")) {
            int close = s.indexOf(']');
            String host = s.substring(1, close);
            String port = close + 2 <= s.length() && s.charAt(close + 1) == ':' ? s.substring(close + 2) : String.valueOf(def);
            return new String[]{host, port};
        }
        int colon = s.lastIndexOf(':');
        if (colon < 0) return new String[]{s, String.valueOf(def)};
        return new String[]{s.substring(0, colon), s.substring(colon + 1)};
    }

    private static String readLine(InputStream in) throws IOException {
        StringBuilder sb = new StringBuilder();
        int c;
        while ((c = in.read()) >= 0) {
            if (c == '\n') {
                int n = sb.length();
                if (n > 0 && sb.charAt(n - 1) == '\r') sb.setLength(n - 1);
                return sb.toString();
            }
            sb.append((char) c);
            if (sb.length() > 65536) throw new IOException("HTTP: слишком длинная строка");
        }
        return sb.length() > 0 ? sb.toString() : null;
    }

    private static int readN(InputStream in) throws IOException {
        int b = in.read();
        if (b < 0) throw new IOException("Неожиданный конец потока");
        return b;
    }

    private static byte[] readBytes(InputStream in, int n) throws IOException {
        byte[] b = new byte[n];
        int off = 0;
        while (off < n) {
            int r = in.read(b, off, n - off);
            if (r < 0) throw new IOException("Неожиданный конец потока");
            off += r;
        }
        return b;
    }
}
