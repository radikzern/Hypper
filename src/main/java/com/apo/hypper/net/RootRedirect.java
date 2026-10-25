package com.apo.hypper.net;

import com.apo.hypper.AppLog;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * Прозрачный прокси через root и iptables — для Android до 4.3, где VpnService капризничает.
 * Весь исходящий TCP перенаправляется (REDIRECT) на локальный порт, DNS (UDP 53) — на локальный
 * DNS-порт. Исходный адрес назначения берём из таблицы conntrack: SO_ORIGINAL_DST из Java недоступен.
 * Трафик самого приложения (соединения с сервером VLESS) исключён правилом по uid.
 */
public class RootRedirect {
    private static final String CHAIN = "HYPPER";
    private static final String[] LAN = {"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16",
            "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "255.255.255.255/32"};
    private static final long DNS_IDLE_MS = 30000;

    private volatile VlessClient client;
    private final String dns;
    private final boolean bypassLan;
    private final int uid;

    private RootShell shell;
    private String conntrack;
    private ServerSocket tcp;
    private DatagramSocket udp;
    private volatile boolean running;
    private final ConcurrentHashMap<String, DnsSession> dnsSessions = new ConcurrentHashMap<String, DnsSession>();

    public RootRedirect(VlessClient client, String dns, boolean bypassLan, int uid) {
        this.client = client;
        this.dns = dns;
        this.bypassLan = bypassLan;
        this.uid = uid;
    }

    public void setClient(VlessClient c) {
        client = c;
    }

    public void start() throws IOException {
        shell = new RootShell();
        try {
            conntrack = shell.run("test -r /proc/net/nf_conntrack").code == 0
                    ? "/proc/net/nf_conntrack" : "/proc/net/ip_conntrack";

            InetAddress lo = InetAddress.getByName("127.0.0.1");
            tcp = new ServerSocket();
            tcp.setReuseAddress(true);
            tcp.bind(new InetSocketAddress(lo, 0), 128);
            udp = new DatagramSocket(new InetSocketAddress(lo, 0));
            running = true;

            removeRules(shell);
            applyRules(tcp.getLocalPort(), udp.getLocalPort());
        } catch (IOException e) {
            stop();
            throw e;
        }
        daemon(new Runnable() {
            public void run() {
                acceptLoop();
            }
        }, "root-accept");
        daemon(new Runnable() {
            public void run() {
                dnsLoop();
            }
        }, "root-dns");
        AppLog.i("Root-перехват: TCP → 127.0.0.1:" + tcp.getLocalPort() + ", DNS → " + dns + " через сервер");
    }

    public void stop() {
        running = false;
        if (shell != null) {
            try {
                removeRules(shell);
            } catch (IOException e) {
                AppLog.e("Не удалось снять правила iptables: " + e.getMessage());
            }
            shell.close();
            shell = null;
        }
        try {
            if (tcp != null) tcp.close();
        } catch (IOException ignored) {
        }
        if (udp != null) udp.close();
        for (DnsSession s : dnsSessions.values()) s.close();
    }

    /** Снимает правила, оставшиеся после аварийного завершения (нужен root). */
    public static void cleanup() {
        try {
            RootShell sh = new RootShell();
            try {
                removeRules(sh);
            } finally {
                sh.close();
            }
        } catch (IOException e) {
            AppLog.e("Очистка iptables: " + e.getMessage());
        }
    }

    // ---------------------------------------------------------------- iptables

    private void applyRules(int tcpPort, int dnsPort) throws IOException {
        StringBuilder s = new StringBuilder();
        s.append("iptables -t nat -N ").append(CHAIN).append(" && ");
        s.append(rule("-o lo -j RETURN")).append(" && ");
        s.append(rule("-d 127.0.0.0/8 -j RETURN")).append(" && ");
        s.append(rule("-m owner --uid-owner " + uid + " -j RETURN")).append(" && ");
        // DNS заворачиваем раньше исключения LAN: резолвер роутера тоже идёт через сервер
        s.append(rule("-p udp --dport 53 -j REDIRECT --to-ports " + dnsPort)).append(" && ");
        if (bypassLan) for (String net : LAN) s.append(rule("-d " + net + " -j RETURN")).append(" && ");
        s.append(rule("-p tcp -j REDIRECT --to-ports " + tcpPort)).append(" && ");
        s.append("iptables -t nat -I OUTPUT -j ").append(CHAIN);
        RootShell.Result r = shell.run(s.toString());
        if (r.code != 0) {
            removeRules(shell);
            throw new IOException("iptables: " + r.output());
        }
    }

    private static String rule(String r) {
        return "iptables -t nat -A " + CHAIN + " " + r;
    }

    private static void removeRules(RootShell sh) throws IOException {
        // правило в OUTPUT могло задвоиться — снимаем, пока снимается
        sh.run("while iptables -t nat -D OUTPUT -j " + CHAIN + " 2>/dev/null; do :; done; "
                + "iptables -t nat -F " + CHAIN + " 2>/dev/null; iptables -t nat -X " + CHAIN + " 2>/dev/null; true");
    }

    // ---------------------------------------------------------------- TCP

    private void acceptLoop() {
        while (running) {
            try {
                final Socket s = tcp.accept();
                daemon(new Runnable() {
                    public void run() {
                        handle(s);
                    }
                }, "root-conn");
            } catch (IOException e) {
                if (running) AppLog.e("accept: " + e.getMessage());
            }
        }
    }

    private void handle(Socket s) {
        VlessClient.Conn remote = null;
        try {
            s.setTcpNoDelay(true);
            String[] dst = originalDst(s.getPort());
            if (dst == null) {
                AppLog.e("Root: не нашёл адрес назначения для порта " + s.getPort());
                return;
            }
            int port = Integer.parseInt(dst[1]);
            byte[] ip = VlessClient.parseIpv4(dst[0]);
            remote = client.connect(VlessClient.CMD_TCP, dst[0], ip, port);
            AppLog.d("TCP " + dst[0] + ":" + port);
            Relay.pipe(s, s.getInputStream(), s.getOutputStream(), remote);
        } catch (IOException e) {
            AppLog.d("Root TCP: " + e.getMessage());
        } finally {
            if (remote != null) remote.close();
            try {
                s.close();
            } catch (IOException ignored) {
            }
        }
    }

    private String[] originalDst(int srcPort) throws IOException {
        int listen = tcp.getLocalPort();
        // запись conntrack появляется по SYN, но на всякий случай пробуем ещё раз
        for (int attempt = 0; attempt < 2; attempt++) {
            RootShell sh = shell;
            if (sh == null) return null;
            RootShell.Result r = sh.run("grep 'sport=" + srcPort + " ' " + conntrack + " || cat " + conntrack);
            String[] d = findOriginal(r.lines, srcPort, listen);
            if (d != null) return d;
        }
        return null;
    }

    /**
     * Ищет в строках conntrack TCP-соединение, перенаправленное на наш порт:
     * исходный кортеж (src, dst, sport, dport), затем ответный (src=127.0.0.1, sport=listenPort, dport=srcPort).
     * @return {dst, dport} исходного соединения или null
     */
    static String[] findOriginal(List<String> lines, int srcPort, int listenPort) {
        String[] best = null;
        for (String line : lines) {
            if (line.indexOf(" tcp ") < 0 && !line.startsWith("tcp ")) continue;
            String[] origDst = new String[1], origDport = new String[1];
            int[] ports = new int[4]; // orig sport, orig dport, reply sport, reply dport
            int dstSeen = 0, sportSeen = 0, dportSeen = 0;
            for (String tok : line.trim().split("\\s+")) {
                if (tok.startsWith("dst=")) {
                    if (dstSeen++ == 0) origDst[0] = tok.substring(4);
                } else if (tok.startsWith("sport=")) {
                    if (sportSeen < 2) ports[sportSeen == 0 ? 0 : 2] = parse(tok.substring(6));
                    sportSeen++;
                } else if (tok.startsWith("dport=")) {
                    if (dportSeen == 0) origDport[0] = tok.substring(6);
                    if (dportSeen < 2) ports[dportSeen == 0 ? 1 : 3] = parse(tok.substring(6));
                    dportSeen++;
                }
            }
            if (origDst[0] == null || ports[0] != srcPort || ports[2] != listenPort || ports[3] != srcPort) continue;
            boolean closing = line.indexOf("TIME_WAIT") >= 0 || line.indexOf(" CLOSE ") >= 0;
            best = new String[]{origDst[0], origDport[0]};
            if (!closing) return best;
        }
        return best;
    }

    private static int parse(String s) {
        try {
            return Integer.parseInt(s);
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    // ---------------------------------------------------------------- DNS

    private void dnsLoop() {
        byte[] buf = new byte[4096];
        while (running) {
            try {
                DatagramPacket p = new DatagramPacket(buf, buf.length);
                udp.receive(p);
                byte[] q = new byte[p.getLength()];
                System.arraycopy(p.getData(), p.getOffset(), q, 0, q.length);
                String key = p.getAddress().getHostAddress() + ":" + p.getPort();
                DnsSession s = dnsSessions.get(key);
                if (s == null || s.closed) {
                    s = new DnsSession(key, p.getAddress(), p.getPort());
                    dnsSessions.put(key, s);
                    s.start();
                }
                s.queue.offer(q);
            } catch (IOException e) {
                if (running) AppLog.e("DNS: " + e.getMessage());
            }
        }
    }

    /** Один UDP-«сеанс» VLESS до DNS-сервера на каждый адрес:порт клиента. */
    private class DnsSession {
        final String key;
        final InetAddress addr;
        final int port;
        final LinkedBlockingQueue<byte[]> queue = new LinkedBlockingQueue<byte[]>(64);
        volatile boolean closed;
        volatile VlessClient.Conn conn;
        volatile long lastActive = System.currentTimeMillis();

        DnsSession(String key, InetAddress addr, int port) {
            this.key = key;
            this.addr = addr;
            this.port = port;
        }

        void start() {
            daemon(new Runnable() {
                public void run() {
                    loop();
                }
            }, "root-dns-s");
        }

        private void loop() {
            final VlessClient.Conn c;
            try {
                c = client.connect(VlessClient.CMD_UDP, dns, VlessClient.parseIpv4(dns), 53);
            } catch (IOException e) {
                AppLog.e("DNS " + dns + ": " + e.getMessage());
                close();
                return;
            }
            conn = c;
            daemon(new Runnable() {
                public void run() {
                    try {
                        OutputStream out = c.out;
                        while (!closed) {
                            byte[] d = queue.poll(5, TimeUnit.SECONDS);
                            if (d == null) {
                                if (System.currentTimeMillis() - lastActive > DNS_IDLE_MS) break;
                                continue;
                            }
                            lastActive = System.currentTimeMillis();
                            byte[] framed = new byte[d.length + 2];
                            Packets.put16(framed, 0, d.length);
                            System.arraycopy(d, 0, framed, 2, d.length);
                            out.write(framed);
                            out.flush();
                        }
                    } catch (Exception ignored) {
                    }
                    close();
                }
            }, "root-dns-w");
            byte[] buf = new byte[65535];
            try {
                InputStream in = c.in;
                while (!closed) {
                    int hi = in.read(), lo = in.read();
                    if (hi < 0 || lo < 0) break;
                    int n = (hi << 8) | lo;
                    int got = 0;
                    while (got < n) {
                        int r = in.read(buf, got, n - got);
                        if (r < 0) throw new IOException("EOF");
                        got += r;
                    }
                    lastActive = System.currentTimeMillis();
                    udp.send(new DatagramPacket(buf, n, addr, port));
                }
            } catch (IOException ignored) {
            }
            close();
        }

        void close() {
            closed = true;
            dnsSessions.remove(key, this);
            VlessClient.Conn c = conn;
            if (c != null) c.close();
        }
    }

    private static void daemon(Runnable r, String name) {
        Thread t = new Thread(r, name);
        t.setDaemon(true);
        t.start();
    }
}
