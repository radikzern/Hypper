package com.apo.hypper.net.wg;

import com.apo.hypper.AppLog;
import com.apo.hypper.net.Dns;

import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.security.SecureRandom;
import java.util.ArrayDeque;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicLong;

/** Клиент WireGuard / AmneziaWG: tun ↔ зашифрованный UDP к одному пиру. */
public class WgTunnel {
    private static final byte[] CONSTRUCTION = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".getBytes(WgConfig.UTF8);
    private static final byte[] IDENTIFIER = "WireGuard v1 zx2c4 Jason@zx2c4.com".getBytes(WgConfig.UTF8);
    private static final byte[] LABEL_MAC1 = "mac1----".getBytes(WgConfig.UTF8);
    private static final byte[] C0 = Blake2s.hash(CONSTRUCTION);
    private static final byte[] H0 = Blake2s.hash(C0, IDENTIFIER);

    private static final long REKEY_AFTER = 120000;
    private static final long REJECT_AFTER = 180000;
    private static final long REKEY_TIMEOUT = 5000;
    private static final long KEEPALIVE_TIMEOUT = 10000;
    private static final long REKEY_ATTEMPT_TIME = 90000;
    private static final int INIT_LEN = 148, RESP_LEN = 92, COOKIE_LEN = 64;
    private static final SecureRandom RANDOM = new SecureRandom();

    private final Params p;
    private final InetAddress endpoint;
    private final int port;
    private final FileDescriptor tunFd;
    private final Dns.DatagramProtector protector;

    private DatagramSocket sock;
    private FileOutputStream tunOut;
    private volatile boolean running;

    // всё ниже защищено монитором this
    private Handshake handshake;
    private long handshakeStarted;
    private Keypair current, previous;
    private final ArrayDeque<byte[]> pending = new ArrayDeque<byte[]>();
    private long lastSent, lastRecvData, lastHandshake;
    private boolean passiveKeepalive;
    private static long lastTimestamp;

    private final AtomicLong rx = new AtomicLong(), tx = new AtomicLong();

    public WgTunnel(WgConfig c, InetAddress endpoint, FileDescriptor tunFd, Dns.DatagramProtector protector) {
        this.p = new Params(c);
        this.endpoint = endpoint;
        this.port = c.port;
        this.tunFd = tunFd;
        this.protector = protector;
    }

    // ---------------------------------------------------------------- параметры

    /** Ключи и параметры обфускации в готовом к работе виде. */
    static final class Params {
        final byte[] priv, pub, peerPub, psk, mac1Key, mac1KeyOwn, staticDh;
        final int jc, jmin, jmax, s1, s2, s3, s4;
        final long[] h1, h2, h3, h4;
        final String[] specials = new String[5];
        final byte[] reserved;
        final boolean amnezia;
        final int keepalive;

        Params(WgConfig c) {
            priv = WgConfig.key(c.privateKey);
            pub = X25519.publicKey(priv);
            peerPub = WgConfig.key(c.publicKey);
            psk = c.presharedKey.length() > 0 ? WgConfig.key(c.presharedKey) : new byte[32];
            mac1Key = Blake2s.hash(LABEL_MAC1, peerPub);
            mac1KeyOwn = Blake2s.hash(LABEL_MAC1, pub);
            staticDh = X25519.scalarMult(priv, peerPub);
            jc = num(c, "Jc", 0);
            jmin = num(c, "Jmin", 0);
            jmax = Math.max(jmin, num(c, "Jmax", 0));
            s1 = num(c, "S1", 0);
            s2 = num(c, "S2", 0);
            s3 = num(c, "S3", 0);
            s4 = num(c, "S4", 0);
            h1 = range(c, "H1", 1);
            h2 = range(c, "H2", 2);
            h3 = range(c, "H3", 3);
            h4 = range(c, "H4", 4);
            for (int i = 0; i < 5; i++) {
                String v = c.awg.get("I" + (i + 1));
                specials[i] = v == null || v.trim().length() == 0 ? null : v.trim();
            }
            amnezia = c.isAmnezia();
            keepalive = c.keepalive;
            reserved = new byte[3];
            if (c.reserved.length() > 0) {
                String[] parts = c.reserved.split(",");
                for (int i = 0; i < 3 && i < parts.length; i++) reserved[i] = (byte) WgConfig.toInt(parts[i], 0);
            }
        }

        private static int num(WgConfig c, String k, int def) {
            String v = c.awg.get(k);
            return v == null ? def : Math.max(0, WgConfig.toInt(v, def));
        }

        /** H может быть числом или диапазоном «a-b» (AmneziaWG 2.0). */
        private static long[] range(WgConfig c, String k, long def) {
            String v = c.awg.get(k);
            if (v == null || v.trim().length() == 0) return new long[]{def, def};
            String t = v.trim();
            int dash = t.indexOf('-', 1);
            try {
                if (dash > 0) {
                    long a = Long.parseLong(t.substring(0, dash).trim()), b = Long.parseLong(t.substring(dash + 1).trim());
                    return new long[]{Math.min(a, b), Math.max(a, b)};
                }
                long a = Long.parseLong(t);
                return new long[]{a, a};
            } catch (NumberFormatException e) {
                return new long[]{def, def};
            }
        }

        static int pick(long[] r) {
            if (r[0] == r[1]) return (int) r[0];
            return (int) (r[0] + (long) (RANDOM.nextDouble() * (r[1] - r[0] + 1)));
        }

        static boolean in(long[] r, int v) {
            long u = v & 0xffffffffL;
            return u >= r[0] && u <= r[1];
        }

        /** Тип сообщения: в обычном WG — первый байт (дальше могут быть reserved от WARP). */
        int type(byte[] b, int off) {
            return amnezia ? ChaChaPoly.le32(b, off) : b[off] & 0xff;
        }
    }

    // ---------------------------------------------------------------- рукопожатие (Noise IKpsk2)

    static final class Handshake {
        byte[] ePriv, ck, h;
        int localIndex;
    }

    static final class Keypair {
        final ChaChaPoly send, recv;
        final int localIndex, remoteIndex;
        final long created = System.currentTimeMillis();
        final AtomicLong sendCounter = new AtomicLong();
        long recvMax = -1, recvWindow;

        Keypair(byte[] sendKey, byte[] recvKey, int localIndex, int remoteIndex) {
            send = new ChaChaPoly(sendKey);
            recv = new ChaChaPoly(recvKey);
            this.localIndex = localIndex;
            this.remoteIndex = remoteIndex;
        }

        /** Защита от повторов: окно 64 пакета. */
        synchronized boolean accept(long n) {
            if (n > recvMax) {
                long shift = n - recvMax;
                recvWindow = shift >= 64 ? 0 : recvWindow << shift;
                recvWindow |= 1;
                recvMax = n;
                return true;
            }
            long back = recvMax - n;
            if (back >= 64) return false;
            long bit = 1L << back;
            if ((recvWindow & bit) != 0) return false;
            recvWindow |= bit;
            return true;
        }
    }

    /** Сервер отвергает рукопожатия со старой меткой — делаем её строго возрастающей. */
    static byte[] tai64n() {
        long now = System.currentTimeMillis() * 1000000L;
        synchronized (WgTunnel.class) {
            if (now <= lastTimestamp) now = lastTimestamp + 1;
            lastTimestamp = now;
        }
        long sec = now / 1000000000L, nano = now % 1000000000L;
        byte[] t = new byte[12];
        long tai = 0x400000000000000aL + sec;
        for (int i = 0; i < 8; i++) t[i] = (byte) (tai >>> (56 - 8 * i));
        for (int i = 0; i < 4; i++) t[8 + i] = (byte) (nano >>> (24 - 8 * i));
        return t;
    }

    static byte[] createInitiation(Params p, Handshake hs, byte[] timestamp) {
        hs.localIndex = RANDOM.nextInt();
        hs.ck = C0;
        hs.h = Blake2s.hash(H0, p.peerPub);
        hs.ePriv = X25519.generatePrivate();
        byte[] ePub = X25519.publicKey(hs.ePriv);
        hs.ck = Blake2s.kdf(hs.ck, ePub, 1)[0];
        hs.h = Blake2s.hash(hs.h, ePub);
        byte[][] kk = Blake2s.kdf(hs.ck, X25519.scalarMult(hs.ePriv, p.peerPub), 2);
        hs.ck = kk[0];
        byte[] encStatic = ChaChaPoly.seal(kk[1], 0, hs.h, p.pub);
        hs.h = Blake2s.hash(hs.h, encStatic);
        kk = Blake2s.kdf(hs.ck, p.staticDh, 2);
        hs.ck = kk[0];
        byte[] encTs = ChaChaPoly.seal(kk[1], 0, hs.h, timestamp);
        hs.h = Blake2s.hash(hs.h, encTs);

        byte[] m = new byte[INIT_LEN];
        ChaChaPoly.put32(m, 0, Params.pick(p.h1));
        if (!p.amnezia) System.arraycopy(p.reserved, 0, m, 1, 3);
        ChaChaPoly.put32(m, 4, hs.localIndex);
        System.arraycopy(ePub, 0, m, 8, 32);
        System.arraycopy(encStatic, 0, m, 40, 48);
        System.arraycopy(encTs, 0, m, 88, 28);
        System.arraycopy(Blake2s.mac(p.mac1Key, m, 116), 0, m, 116, 16);
        return m;
    }

    /** off — начало сообщения (после S2). Возвращает пару ключей или null. */
    static Keypair consumeResponse(Params p, Handshake hs, byte[] m, int off) {
        if (hs == null || ChaChaPoly.le32(m, off + 8) != hs.localIndex) return null;
        byte[] mac1 = Blake2s.mac(p.mac1KeyOwn, copy(m, off, 60), 60);
        int diff = 0;
        for (int i = 0; i < 16; i++) diff |= mac1[i] ^ m[off + 60 + i];
        if (diff != 0) return null;
        int remoteIndex = ChaChaPoly.le32(m, off + 4);
        byte[] ePubR = copy(m, off + 12, 32);
        byte[] empty = copy(m, off + 44, 16);
        byte[] ck = Blake2s.kdf(hs.ck, ePubR, 1)[0];
        byte[] h = Blake2s.hash(hs.h, ePubR);
        ck = Blake2s.kdf(ck, X25519.scalarMult(hs.ePriv, ePubR), 1)[0];
        ck = Blake2s.kdf(ck, X25519.scalarMult(p.priv, ePubR), 1)[0];
        byte[][] kk = Blake2s.kdf(ck, p.psk, 3);
        ck = kk[0];
        h = Blake2s.hash(h, kk[1]);
        if (ChaChaPoly.open(kk[2], 0, h, empty) == null) return null;
        kk = Blake2s.kdf(ck, new byte[0], 2);
        return new Keypair(kk[0], kk[1], hs.localIndex, remoteIndex);
    }

    private static byte[] copy(byte[] b, int off, int len) {
        byte[] r = new byte[len];
        System.arraycopy(b, off, r, 0, len);
        return r;
    }

    // ---------------------------------------------------------------- обфускация AmneziaWG

    /** Пакеты I1..I5 и Jc случайных «мусорных» пакетов перед рукопожатием. */
    static void sendJunk(DatagramSocket s, Params p, InetAddress addr, int port) throws IOException {
        for (String spec : p.specials) {
            if (spec == null) continue;
            byte[] b = special(spec);
            if (b.length > 0) s.send(new DatagramPacket(b, b.length, addr, port));
        }
        for (int i = 0; i < p.jc; i++) {
            int n = p.jmin + (p.jmax > p.jmin ? RANDOM.nextInt(p.jmax - p.jmin + 1) : 0);
            if (n <= 0) continue;
            byte[] b = new byte[n];
            RANDOM.nextBytes(b);
            s.send(new DatagramPacket(b, b.length, addr, port));
        }
    }

    /** Теги I-пакетов: &lt;b 0xHEX&gt; &lt;r N&gt; &lt;rc N&gt; &lt;rd N&gt; &lt;t&gt; &lt;c&gt;. */
    static byte[] special(String spec) {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        int i = 0;
        while (i < spec.length()) {
            int open = spec.indexOf('<', i);
            if (open < 0) break;
            int close = spec.indexOf('>', open);
            if (close < 0) break;
            String[] parts = spec.substring(open + 1, close).trim().split("\\s+");
            String tag = parts[0].toLowerCase(Locale.US);
            String arg = parts.length > 1 ? parts[1] : "";
            if (tag.equals("b")) {
                String hex = arg.startsWith("0x") || arg.startsWith("0X") ? arg.substring(2) : arg;
                for (int k = 0; k + 1 < hex.length(); k += 2) {
                    out.write(Integer.parseInt(hex.substring(k, k + 2), 16));
                }
            } else if (tag.equals("r") || tag.equals("rc") || tag.equals("rd")) {
                int n = Math.min(WgConfig.toInt(arg, 0), 2000);
                String alphabet = tag.equals("rc") ? "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                        : "0123456789";
                for (int k = 0; k < n; k++) {
                    out.write(tag.equals("r") ? RANDOM.nextInt(256) : alphabet.charAt(RANDOM.nextInt(alphabet.length())));
                }
            } else if (tag.equals("t")) {
                long t = System.currentTimeMillis() / 1000;
                for (int k = 0; k < 4; k++) out.write((int) (t >>> (24 - 8 * k)));
            } else if (tag.equals("c")) {
                for (int k = 0; k < 4; k++) out.write(0);
            }
            i = close + 1;
        }
        return out.toByteArray();
    }

    private static byte[] withPrefix(int prefix, byte[] m) {
        if (prefix == 0) return m;
        byte[] r = new byte[prefix + m.length];
        byte[] junk = new byte[prefix];
        RANDOM.nextBytes(junk);
        System.arraycopy(junk, 0, r, 0, prefix);
        System.arraycopy(m, 0, r, prefix, m.length);
        return r;
    }

    // ---------------------------------------------------------------- работа

    public void start() throws IOException {
        sock = new DatagramSocket();
        if (protector != null && !protector.protect(sock)) {
            sock.close();
            throw new IOException("protect() не удался");
        }
        sock.connect(endpoint, port);
        tunOut = new FileOutputStream(tunFd);
        running = true;
        thread(new Runnable() {
            public void run() {
                tunLoop();
            }
        }, "wg-tun");
        thread(new Runnable() {
            public void run() {
                udpLoop();
            }
        }, "wg-udp");
        thread(new Runnable() {
            public void run() {
                timerLoop();
            }
        }, "wg-timer");
        synchronized (this) {
            initiate();
        }
    }

    public void stop() {
        running = false;
        if (sock != null) sock.close();
    }

    public String status() {
        long last;
        synchronized (this) {
            last = lastHandshake;
        }
        String traffic = "↓" + size(rx.get()) + " ↑" + size(tx.get());
        if (last == 0) return "Ожидание рукопожатия… " + traffic;
        return "рукопожатие " + (System.currentTimeMillis() - last) / 1000 + " с назад · " + traffic;
    }

    private static String size(long b) {
        if (b >= 1 << 20) return String.format(Locale.US, "%.1f МБ", b / 1048576.0);
        return (b >> 10) + " КБ";
    }

    private static void thread(Runnable r, String name) {
        Thread t = new Thread(r, name);
        t.setDaemon(true);
        t.start();
    }

    private void send(byte[] b) {
        try {
            sock.send(new DatagramPacket(b, b.length));
            tx.addAndGet(b.length);
        } catch (IOException e) {
            if (running) AppLog.d("wg send: " + e.getMessage());
        }
    }

    /** Новая попытка рукопожатия. Вызывать под монитором. */
    private void initiate() {
        long now = System.currentTimeMillis();
        if (handshake == null) handshakeStarted = now;
        Handshake hs = new Handshake();
        byte[] m = createInitiation(p, hs, tai64n());
        handshake = hs;
        lastSent = now;
        try {
            sendJunk(sock, p, endpoint, port);
        } catch (IOException e) {
            if (running) AppLog.d("wg junk: " + e.getMessage());
        }
        send(withPrefix(p.s1, m));
        AppLog.d("WG: отправлено рукопожатие");
    }

    private void tunLoop() {
        FileInputStream in = new FileInputStream(tunFd);
        byte[] buf = new byte[65535];
        while (running) {
            int n;
            try {
                n = in.read(buf);
            } catch (IOException e) {
                if (running) AppLog.e("tun read: " + e.getMessage());
                break;
            }
            if (n <= 0) continue;
            byte[] pkt = new byte[n];
            System.arraycopy(buf, 0, pkt, 0, n);
            Keypair kp;
            synchronized (this) {
                kp = current;
                long now = System.currentTimeMillis();
                if (kp == null || now - kp.created > REJECT_AFTER) {
                    if (pending.size() >= 64) pending.removeFirst();
                    pending.addLast(pkt);
                    if (handshake == null) initiate();
                    continue;
                }
                if (now - kp.created > REKEY_AFTER && handshake == null) initiate();
            }
            sendData(kp, pkt, 0, pkt.length);
        }
    }

    private void sendData(Keypair kp, byte[] pkt, int off, int len) {
        int padded = (len + 15) & ~15;
        byte[] plain = pkt;
        if (padded != len || off != 0) {
            plain = new byte[padded];
            System.arraycopy(pkt, off, plain, 0, len);
        }
        int pre = p.s4;
        byte[] out = new byte[pre + 16 + padded + 16];
        if (pre > 0) {
            byte[] junk = new byte[pre];
            RANDOM.nextBytes(junk);
            System.arraycopy(junk, 0, out, 0, pre);
        }
        ChaChaPoly.put32(out, pre, Params.pick(p.h4));
        if (!p.amnezia) System.arraycopy(p.reserved, 0, out, pre + 1, 3);
        ChaChaPoly.put32(out, pre + 4, kp.remoteIndex);
        long counter = kp.sendCounter.getAndIncrement();
        for (int i = 0; i < 8; i++) out[pre + 8 + i] = (byte) (counter >>> (8 * i));
        kp.send.seal(counter, null, plain, 0, padded, out, pre + 16);
        synchronized (this) {
            lastSent = System.currentTimeMillis();
            passiveKeepalive = false;
        }
        send(out);
    }

    private void udpLoop() {
        byte[] buf = new byte[65535];
        DatagramPacket dp = new DatagramPacket(buf, buf.length);
        while (running) {
            try {
                dp.setLength(buf.length);
                sock.receive(dp);
            } catch (IOException e) {
                if (running) AppLog.e("wg recv: " + e.getMessage());
                break;
            }
            int len = dp.getLength();
            rx.addAndGet(len);
            try {
                handleUdp(buf, len);
            } catch (RuntimeException e) {
                AppLog.e("wg: " + e);
            }
        }
    }

    private void handleUdp(byte[] b, int len) {
        if (len == p.s2 + RESP_LEN && Params.in(p.h2, p.type(b, p.s2))) {
            Keypair kp;
            synchronized (this) {
                kp = consumeResponse(p, handshake, b, p.s2);
                if (kp == null) return;
                handshake = null;
                previous = current;
                current = kp;
                lastHandshake = System.currentTimeMillis();
            }
            AppLog.i("WG: рукопожатие выполнено");
            flushPending(kp);
            return;
        }
        if (len == p.s3 + COOKIE_LEN && Params.in(p.h3, p.type(b, p.s3))) {
            AppLog.d("WG: сервер перегружен (cookie reply), повторим позже");
            return;
        }
        int off = p.s4;
        if (len < off + 32 || !Params.in(p.h4, p.type(b, off))) return;
        int receiver = ChaChaPoly.le32(b, off + 4);
        Keypair kp;
        synchronized (this) {
            kp = current != null && current.localIndex == receiver ? current
                    : previous != null && previous.localIndex == receiver ? previous : null;
        }
        if (kp == null || System.currentTimeMillis() - kp.created > REJECT_AFTER) return;
        long counter = 0;
        for (int i = 7; i >= 0; i--) counter = (counter << 8) | (b[off + 8 + i] & 0xff);
        int ctLen = len - off - 16;
        byte[] plain = new byte[ctLen - 16];
        if (!kp.recv.open(counter, null, b, off + 16, ctLen, plain, 0)) return;
        if (!kp.accept(counter)) return;
        if (plain.length == 0) return; // keepalive
        int ipLen = ipLength(plain);
        if (ipLen <= 0 || ipLen > plain.length) return;
        synchronized (this) {
            lastRecvData = System.currentTimeMillis();
            passiveKeepalive = true;
        }
        try {
            synchronized (tunOut) {
                tunOut.write(plain, 0, ipLen);
            }
        } catch (IOException e) {
            if (running) AppLog.d("tun write: " + e.getMessage());
        }
    }

    private static int ipLength(byte[] b) {
        if (b.length < 20) return -1;
        int v = (b[0] >> 4) & 0xf;
        if (v == 4) return ((b[2] & 0xff) << 8) | (b[3] & 0xff);
        if (v == 6 && b.length >= 40) return 40 + (((b[4] & 0xff) << 8) | (b[5] & 0xff));
        return -1;
    }

    private void flushPending(Keypair kp) {
        while (true) {
            byte[] pkt;
            synchronized (this) {
                pkt = pending.pollFirst();
            }
            if (pkt == null) break;
            sendData(kp, pkt, 0, pkt.length);
        }
        // инициатор обязан что-то отправить, чтобы сервер начал использовать новые ключи
        sendData(kp, new byte[0], 0, 0);
    }

    private void timerLoop() {
        while (running) {
            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                return;
            }
            Keypair keepalive = null;
            synchronized (this) {
                long now = System.currentTimeMillis();
                if (current != null && now - current.created > REJECT_AFTER) {
                    current = null;
                    previous = null;
                }
                if (handshake != null) {
                    if (now - handshakeStarted > REKEY_ATTEMPT_TIME && pending.isEmpty() && p.keepalive == 0) {
                        handshake = null; // сдаёмся до следующего исходящего пакета
                        AppLog.e("WG: сервер не отвечает на рукопожатие");
                    } else if (now - lastSent > REKEY_TIMEOUT) {
                        initiate();
                    }
                    continue;
                }
                Keypair kp = current;
                if (kp == null) {
                    if (p.keepalive > 0) initiate();
                    continue;
                }
                if (now - kp.created > REKEY_AFTER && now - lastSent < REJECT_AFTER) {
                    initiate();
                    continue;
                }
                if (p.keepalive > 0 && now - lastSent >= p.keepalive * 1000L) keepalive = kp;
                else if (passiveKeepalive && now - lastRecvData >= KEEPALIVE_TIMEOUT && now - lastSent >= KEEPALIVE_TIMEOUT)
                    keepalive = kp;
            }
            if (keepalive != null) sendData(keepalive, new byte[0], 0, 0);
        }
    }

    // ---------------------------------------------------------------- проверка задержки

    /** Время рукопожатия в мс (заодно проверяет ключи), либо -1. */
    public static int ping(WgConfig c, InetAddress addr, Dns.DatagramProtector protector) {
        DatagramSocket s = null;
        try {
            Params p = new Params(c);
            s = new DatagramSocket();
            if (protector != null && !protector.protect(s)) return -1;
            s.setSoTimeout(2500);
            byte[] buf = new byte[2048];
            for (int attempt = 0; attempt < 2; attempt++) {
                Handshake hs = new Handshake();
                byte[] m = createInitiation(p, hs, tai64n());
                long start = System.currentTimeMillis();
                sendJunk(s, p, addr, c.port);
                byte[] pkt = withPrefix(p.s1, m);
                s.send(new DatagramPacket(pkt, pkt.length, addr, c.port));
                long deadline = start + 2500;
                while (System.currentTimeMillis() < deadline) {
                    DatagramPacket dp = new DatagramPacket(buf, buf.length);
                    try {
                        s.receive(dp);
                    } catch (SocketTimeoutException e) {
                        break;
                    }
                    if (dp.getLength() == p.s2 + RESP_LEN && consumeResponse(p, hs, buf, p.s2) != null) {
                        return (int) Math.max(1, System.currentTimeMillis() - start);
                    }
                }
            }
            return -1;
        } catch (Exception e) {
            return -1;
        } finally {
            if (s != null) s.close();
        }
    }
}
