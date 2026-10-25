package com.apo.hypper.net;

import com.apo.hypper.AppLog;

import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import static com.apo.hypper.net.Packets.ACK;
import static com.apo.hypper.net.Packets.FIN;
import static com.apo.hypper.net.Packets.PSH;
import static com.apo.hypper.net.Packets.RST;
import static com.apo.hypper.net.Packets.SYN;

/**
 * Минимальный TCP/UDP-стек поверх tun: каждое TCP-соединение и каждый UDP-«поток»
 * приложения превращается в отдельное VLESS-соединение к серверу.
 */
public class TunStack {
    private static final int OUR_MSS = 1400;
    private static final int RCV_WINDOW = 65535;
    private static final long UDP_IDLE_MS = 60000;
    private static final long DNS_IDLE_MS = 15000;
    private static final long FIN_WAIT_MS = 120000;
    private static final byte[] EOF = new byte[0];

    private final FileInputStream tunIn;
    private final FileOutputStream tunOut;
    private volatile VlessClient client;
    private final ConcurrentHashMap<Long, TcpSession> tcp = new ConcurrentHashMap<Long, TcpSession>();
    private final ConcurrentHashMap<Long, UdpSession> udp = new ConcurrentHashMap<Long, UdpSession>();
    private final Random random = new Random();
    private volatile boolean running;

    public TunStack(FileDescriptor fd, VlessClient client) {
        this.tunIn = new FileInputStream(fd);
        this.tunOut = new FileOutputStream(fd);
        this.client = client;
    }

    public void start() {
        running = true;
        daemon(new Runnable() {
            public void run() {
                readLoop();
            }
        }, "tun-read");
        daemon(new Runnable() {
            public void run() {
                tickLoop();
            }
        }, "tun-tick");
    }

    public void stop() {
        running = false;
        for (TcpSession s : new ArrayList<TcpSession>(tcp.values())) s.abort(false);
        for (UdpSession s : new ArrayList<UdpSession>(udp.values())) s.close();
    }

    /** Смена сервера без пересоздания tun: старые соединения рвём, новые идут через новый сервер. */
    public void setClient(VlessClient c) {
        client = c;
        for (TcpSession s : new ArrayList<TcpSession>(tcp.values())) s.abort(true);
        for (UdpSession s : new ArrayList<UdpSession>(udp.values())) s.close();
    }

    public int connections() {
        return tcp.size() + udp.size();
    }

    private static Thread daemon(Runnable r, String name) {
        Thread t = new Thread(r, name);
        t.setDaemon(true);
        t.start();
        return t;
    }

    private void write(byte[] packet) {
        synchronized (tunOut) {
            try {
                tunOut.write(packet);
            } catch (IOException e) {
                if (running) AppLog.d("tun write: " + e.getMessage());
            }
        }
    }

    private void readLoop() {
        byte[] buf = new byte[32767];
        while (running) {
            int n;
            try {
                n = tunIn.read(buf);
            } catch (IOException e) {
                if (running) AppLog.e("tun read: " + e.getMessage());
                break;
            }
            if (n < 0) break;
            if (n < 20) continue;
            try {
                handle(buf, n);
            } catch (RuntimeException e) {
                AppLog.e("packet: " + e);
            }
        }
    }

    private void tickLoop() {
        while (running) {
            try {
                Thread.sleep(250);
            } catch (InterruptedException e) {
                return;
            }
            long now = System.currentTimeMillis();
            for (TcpSession s : tcp.values()) s.tick(now);
            for (UdpSession s : udp.values()) {
                if (now - s.lastActive > (s.dstPort == 53 ? DNS_IDLE_MS : UDP_IDLE_MS)) s.close();
            }
        }
    }

    private static long key(int srcPort, int dstIp, int dstPort) {
        return ((long) srcPort << 48) | ((long) dstPort << 32) | (dstIp & 0xffffffffL);
    }

    private void handle(byte[] b, int n) {
        if ((b[0] >> 4 & 0xf) != 4) return; // только IPv4
        int ihl = (b[0] & 0xf) * 4;
        int total = Math.min(Packets.u16(b, 2), n);
        if (ihl < 20 || total < ihl) return;
        int frag = Packets.u16(b, 6);
        if ((frag & 0x3fff) != 0) return; // фрагменты не собираем
        int proto = b[9] & 0xff;
        int src = Packets.i32(b, 12);
        int dst = Packets.i32(b, 16);
        if (proto == Packets.PROTO_TCP) handleTcp(b, ihl, total, src, dst);
        else if (proto == Packets.PROTO_UDP) handleUdp(b, ihl, total, src, dst);
    }

    // ---------------------------------------------------------------- TCP

    private void handleTcp(byte[] b, int off, int total, int src, int dst) {
        if (total - off < 20) return;
        int srcPort = Packets.u16(b, off);
        int dstPort = Packets.u16(b, off + 2);
        int seq = Packets.i32(b, off + 4);
        int ack = Packets.i32(b, off + 8);
        int dataOff = ((b[off + 12] >> 4) & 0xf) * 4;
        int flags = b[off + 13] & 0x3f;
        int window = Packets.u16(b, off + 14);
        int payload = off + dataOff;
        int len = total - payload;
        if (len < 0) return;

        long k = key(srcPort, dst, dstPort);
        TcpSession s = tcp.get(k);

        if ((flags & RST) != 0) {
            if (s != null) s.abort(false);
            return;
        }
        if ((flags & SYN) != 0 && (flags & ACK) == 0) {
            if (s != null) {
                s.onDuplicateSyn();
                return;
            }
            int mss = Packets.parseMss(b, off + 20, payload);
            s = new TcpSession(k, src, srcPort, dst, dstPort, seq, window, mss);
            tcp.put(k, s);
            s.open();
            return;
        }
        if (s == null) {
            // чужой сегмент — сбрасываем, чтобы приложение не висело
            int rseq = (flags & ACK) != 0 ? ack : 0;
            int rflags = (flags & ACK) != 0 ? RST : RST | ACK;
            int rack = seq + len + ((flags & SYN) != 0 ? 1 : 0) + ((flags & FIN) != 0 ? 1 : 0);
            write(Packets.tcp(dst, src, dstPort, srcPort, rseq, rack, rflags, 0, 0, null, 0, 0));
            return;
        }
        s.onSegment(seq, ack, flags, window, b, payload, len);
    }

    private class TcpSession {
        final long key;
        final int localIp, localPort, remoteIp, remotePort;
        final int sendMss;
        final LinkedBlockingQueue<byte[]> toRemote = new LinkedBlockingQueue<byte[]>();

        // все поля ниже защищены монитором this
        int sndUna, sndNxt, rcvNxt, peerWnd;
        boolean synPending = true;
        boolean finSent, finAcked, finRcvd, closed;
        byte[] unacked = new byte[8192];
        int unackedLen;
        int queued;
        int lastAdvertised = RCV_WINDOW;
        long lastProgress = System.currentTimeMillis();
        long finRcvdAt, finAckedAt;
        int retries;
        VlessClient.Conn conn;

        TcpSession(long key, int localIp, int localPort, int remoteIp, int remotePort,
                   int seq, int window, int mss) {
            this.key = key;
            this.localIp = localIp;
            this.localPort = localPort;
            this.remoteIp = remoteIp;
            this.remotePort = remotePort;
            this.rcvNxt = seq + 1;
            this.peerWnd = window;
            this.sendMss = mss > 0 ? Math.min(mss, OUR_MSS) : 536;
            int iss = random.nextInt();
            this.sndUna = iss;
            this.sndNxt = iss + 1;
        }

        String name() {
            return Packets.ipString(remoteIp) + ":" + remotePort;
        }

        void open() {
            synchronized (this) {
                sendSynAck();
            }
            daemon(new Runnable() {
                public void run() {
                    remoteLoop();
                }
            }, "tcp-" + remotePort);
        }

        private void send(int flags, int seq, byte[] data, int off, int len) {
            int wnd = window();
            lastAdvertised = wnd;
            write(Packets.tcp(remoteIp, localIp, remotePort, localPort, seq, rcvNxt, flags, wnd, 0, data, off, len));
        }

        private int window() {
            return Math.max(0, RCV_WINDOW - queued);
        }

        private void sendSynAck() {
            int wnd = window();
            lastAdvertised = wnd;
            write(Packets.tcp(remoteIp, localIp, remotePort, localPort, sndUna, rcvNxt, SYN | ACK, wnd,
                    OUR_MSS, null, 0, 0));
        }

        synchronized void onDuplicateSyn() {
            if (synPending) sendSynAck();
        }

        synchronized void onSegment(int seq, int ack, int flags, int window, byte[] b, int off, int len) {
            if (closed) return;
            if ((flags & ACK) != 0) {
                int acked = ack - sndUna;
                int inflight = sndNxt - sndUna;
                if (acked > 0 && acked <= inflight) {
                    if (synPending) {
                        synPending = false;
                        sndUna++;
                        acked--;
                    }
                    int d = Math.min(acked, unackedLen);
                    if (d > 0) {
                        System.arraycopy(unacked, d, unacked, 0, unackedLen - d);
                        unackedLen -= d;
                        sndUna += d;
                        acked -= d;
                    }
                    if (acked > 0 && finSent) {
                        finAcked = true;
                        finAckedAt = System.currentTimeMillis();
                        sndUna++;
                    }
                    lastProgress = System.currentTimeMillis();
                    retries = 0;
                }
                peerWnd = window;
                notifyAll();
            }

            boolean needAck = false;
            if (len > 0) {
                needAck = true;
                int skip = rcvNxt - seq;
                if (skip >= 0 && skip < len && !finRcvd) {
                    int n = len - skip;
                    byte[] chunk = new byte[n];
                    System.arraycopy(b, off + skip, chunk, 0, n);
                    queued += n;
                    toRemote.offer(chunk);
                    rcvNxt += n;
                }
            }
            if ((flags & FIN) != 0) {
                needAck = true;
                if (!finRcvd && seq + len == rcvNxt) {
                    finRcvd = true;
                    finRcvdAt = System.currentTimeMillis();
                    rcvNxt++;
                    toRemote.offer(EOF);
                }
            }
            if (needAck) send(ACK, sndNxt, null, 0, 0);
            if (finRcvd && finAcked) finish();
        }

        /** Поток: подключение к серверу, затем чтение ответа и отправка приложению. */
        private void remoteLoop() {
            VlessClient.Conn c;
            try {
                c = client.connect(VlessClient.CMD_TCP, Packets.ipString(remoteIp), Packets.ipBytes(remoteIp), remotePort);
            } catch (IOException e) {
                AppLog.e("TCP " + name() + ": " + e.getMessage());
                abort(true);
                return;
            }
            synchronized (this) {
                if (closed) {
                    c.close();
                    return;
                }
                conn = c;
            }
            AppLog.d("TCP " + name());
            daemon(new Runnable() {
                public void run() {
                    writerLoop();
                }
            }, "tcp-w-" + remotePort);

            byte[] buf = new byte[sendMss];
            try {
                InputStream in = c.in;
                int n;
                while ((n = in.read(buf, 0, sendMss)) > 0) {
                    synchronized (this) {
                        while (!closed && (synPending || unackedLen + n > Math.max(peerWnd, 1)) && unackedLen > 0) {
                            wait(500);
                        }
                        while (!closed && synPending) wait(500);
                        if (closed) return;
                        if (unackedLen + n > unacked.length) {
                            byte[] nb = new byte[Math.max(unacked.length * 2, unackedLen + n)];
                            System.arraycopy(unacked, 0, nb, 0, unackedLen);
                            unacked = nb;
                        }
                        System.arraycopy(buf, 0, unacked, unackedLen, n);
                        if (unackedLen == 0) lastProgress = System.currentTimeMillis();
                        unackedLen += n;
                        send(ACK | PSH, sndNxt, buf, 0, n);
                        sndNxt += n;
                    }
                }
                synchronized (this) {
                    if (closed) return;
                    if (unackedLen == 0) lastProgress = System.currentTimeMillis();
                    finSent = true;
                    send(FIN | ACK, sndNxt, null, 0, 0);
                    sndNxt++;
                }
            } catch (IOException e) {
                abort(true);
            } catch (InterruptedException e) {
                abort(true);
            }
        }

        private void writerLoop() {
            try {
                while (true) {
                    byte[] chunk = toRemote.poll(60, TimeUnit.SECONDS);
                    synchronized (this) {
                        if (closed) return;
                    }
                    if (chunk == null) continue;
                    if (chunk == EOF) return; // приложение закрыло запись, ждём ответа сервера
                    conn.out.write(chunk);
                    if (toRemote.isEmpty()) conn.out.flush();
                    synchronized (this) {
                        queued -= chunk.length;
                        // окно было почти закрыто — сообщаем приложению, что место появилось
                        if (lastAdvertised < 16384 && window() >= 16384 && !closed) send(ACK, sndNxt, null, 0, 0);
                    }
                }
            } catch (IOException e) {
                abort(true);
            } catch (InterruptedException e) {
                abort(true);
            }
        }

        synchronized void tick(long now) {
            if (closed) return;
            if ((finRcvd && now - finRcvdAt > FIN_WAIT_MS) || (finAcked && now - finAckedAt > FIN_WAIT_MS)) {
                abort(true);
                return;
            }
            boolean outstanding = synPending || unackedLen > 0 || (finSent && !finAcked);
            if (!outstanding) return;
            long rto = Math.min(1000L << Math.min(retries, 4), 8000);
            if (now - lastProgress < rto) return;
            if (++retries > 10) {
                AppLog.d("TCP " + name() + ": таймаут ретрансляции");
                abort(true);
                return;
            }
            lastProgress = now;
            if (synPending) {
                sendSynAck();
                return;
            }
            // go-back-N: повторяем всё неподтверждённое в пределах окна
            int limit = Math.min(unackedLen, Math.max(peerWnd, sendMss));
            int off = 0;
            while (off < limit) {
                int n = Math.min(sendMss, limit - off);
                send(ACK | PSH, sndUna + off, unacked, off, n);
                off += n;
            }
            if (finSent && !finAcked && limit == unackedLen) send(FIN | ACK, sndNxt - 1, null, 0, 0);
        }

        private void finish() {
            closed = true;
            tcp.remove(key, this);
            if (conn != null) conn.close();
            toRemote.offer(EOF);
            notifyAll();
        }

        synchronized void abort(boolean sendRst) {
            if (closed) return;
            if (sendRst) send(RST | ACK, sndNxt, null, 0, 0);
            finish();
        }
    }

    // ---------------------------------------------------------------- UDP

    private void handleUdp(byte[] b, int off, int total, int src, int dst) {
        if (total - off < 8) return;
        int srcPort = Packets.u16(b, off);
        int dstPort = Packets.u16(b, off + 2);
        int len = Math.min(Packets.u16(b, off + 4), total - off) - 8;
        if (len < 0) return;
        byte[] data = new byte[len];
        System.arraycopy(b, off + 8, data, 0, len);

        long k = key(srcPort, dst, dstPort);
        UdpSession s = udp.get(k);
        if (s == null) {
            s = new UdpSession(k, src, srcPort, dst, dstPort);
            udp.put(k, s);
            s.start();
        }
        s.send(data);
    }

    private class UdpSession {
        final long key;
        final int localIp, localPort, remoteIp, dstPort;
        final LinkedBlockingQueue<byte[]> queue = new LinkedBlockingQueue<byte[]>(128);
        volatile long lastActive = System.currentTimeMillis();
        volatile boolean closed;
        volatile VlessClient.Conn conn;

        UdpSession(long key, int localIp, int localPort, int remoteIp, int dstPort) {
            this.key = key;
            this.localIp = localIp;
            this.localPort = localPort;
            this.remoteIp = remoteIp;
            this.dstPort = dstPort;
        }

        void start() {
            daemon(new Runnable() {
                public void run() {
                    loop();
                }
            }, "udp-" + dstPort);
        }

        void send(byte[] data) {
            lastActive = System.currentTimeMillis();
            queue.offer(data);
        }

        private void loop() {
            final VlessClient.Conn c;
            try {
                c = client.connect(VlessClient.CMD_UDP, Packets.ipString(remoteIp), Packets.ipBytes(remoteIp), dstPort);
            } catch (IOException e) {
                AppLog.e("UDP " + Packets.ipString(remoteIp) + ":" + dstPort + ": " + e.getMessage());
                close();
                return;
            }
            conn = c;
            if (closed) {
                c.close();
                return;
            }
            AppLog.d("UDP " + Packets.ipString(remoteIp) + ":" + dstPort);
            daemon(new Runnable() {
                public void run() {
                    try {
                        while (!closed) {
                            byte[] d = queue.poll(5, TimeUnit.SECONDS);
                            if (d == null) continue;
                            byte[] framed = new byte[d.length + 2];
                            Packets.put16(framed, 0, d.length);
                            System.arraycopy(d, 0, framed, 2, d.length);
                            c.out.write(framed);
                            c.out.flush();
                        }
                    } catch (Exception e) {
                        close();
                    }
                }
            }, "udp-w-" + dstPort);

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
                    write(Packets.udp(remoteIp, localIp, dstPort, localPort, buf, 0, n));
                }
            } catch (IOException ignored) {
            }
            close();
        }

        void close() {
            closed = true;
            udp.remove(key, this);
            VlessClient.Conn c = conn;
            if (c != null) c.close();
        }
    }

    // ---------------------------------------------------------------- маршруты

    /** CIDR-ы, покрывающие весь IPv4, кроме локальных/частных сетей. */
    public static List<int[]> routesExcludingPrivate() {
        int[][] excluded = {
                {0x00000000, 8}, {0x0A000000, 8}, {0x64400000, 10}, {0x7F000000, 8},
                {0xA9FE0000, 16}, {0xAC100000, 12}, {0xC0A80000, 16}, {0xE0000000, 3},
        };
        List<int[]> out = new ArrayList<int[]>();
        split(0, 0, excluded, out);
        return out;
    }

    private static void split(int net, int len, int[][] excluded, List<int[]> out) {
        long start = net & 0xffffffffL;
        long end = start + (1L << (32 - len)) - 1;
        boolean overlap = false;
        for (int[] e : excluded) {
            long es = e[0] & 0xffffffffL;
            long ee = es + (1L << (32 - e[1])) - 1;
            if (es <= start && end <= ee) return; // целиком исключено
            if (es <= end && start <= ee) overlap = true;
        }
        if (!overlap) {
            out.add(new int[]{net, len});
            return;
        }
        split(net, len + 1, excluded, out);
        split((int) (start + (1L << (31 - len))), len + 1, excluded, out);
    }
}
