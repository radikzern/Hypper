package com.apo.hypper.net;

/** Разбор и сборка пакетов IPv4 / TCP / UDP. */
final class Packets {
    static final int PROTO_TCP = 6;
    static final int PROTO_UDP = 17;

    static final int FIN = 0x01;
    static final int SYN = 0x02;
    static final int RST = 0x04;
    static final int PSH = 0x08;
    static final int ACK = 0x10;

    private static int ipId;

    private Packets() {
    }

    static int u16(byte[] b, int off) {
        return ((b[off] & 0xff) << 8) | (b[off + 1] & 0xff);
    }

    static int i32(byte[] b, int off) {
        return ((b[off] & 0xff) << 24) | ((b[off + 1] & 0xff) << 16) | ((b[off + 2] & 0xff) << 8) | (b[off + 3] & 0xff);
    }

    static void put16(byte[] b, int off, int v) {
        b[off] = (byte) (v >> 8);
        b[off + 1] = (byte) v;
    }

    static void put32(byte[] b, int off, int v) {
        b[off] = (byte) (v >> 24);
        b[off + 1] = (byte) (v >> 16);
        b[off + 2] = (byte) (v >> 8);
        b[off + 3] = (byte) v;
    }

    static byte[] ipBytes(int ip) {
        return new byte[]{(byte) (ip >> 24), (byte) (ip >> 16), (byte) (ip >> 8), (byte) ip};
    }

    static String ipString(int ip) {
        return ((ip >>> 24) & 0xff) + "." + ((ip >>> 16) & 0xff) + "." + ((ip >>> 8) & 0xff) + "." + (ip & 0xff);
    }

    private static long sum(byte[] b, int off, int len, long acc) {
        int i = off;
        int end = off + len;
        while (i + 1 < end) {
            acc += ((b[i] & 0xff) << 8) | (b[i + 1] & 0xff);
            i += 2;
        }
        if (i < end) acc += (b[i] & 0xff) << 8;
        return acc;
    }

    private static int fold(long acc) {
        while ((acc >> 16) != 0) acc = (acc & 0xffff) + (acc >> 16);
        return (int) (~acc & 0xffff);
    }

    private static synchronized int nextId() {
        ipId = (ipId + 1) & 0xffff;
        return ipId;
    }

    private static void ipHeader(byte[] p, int total, int proto, int src, int dst) {
        p[0] = 0x45;
        p[1] = 0;
        put16(p, 2, total);
        put16(p, 4, nextId());
        put16(p, 6, 0x4000); // DF
        p[8] = 64;
        p[9] = (byte) proto;
        put16(p, 10, 0);
        put32(p, 12, src);
        put32(p, 16, dst);
        put16(p, 10, fold(sum(p, 0, 20, 0)));
    }

    private static long pseudo(int src, int dst, int proto, int len) {
        long acc = 0;
        acc += (src >>> 16) + (src & 0xffff);
        acc += (dst >>> 16) + (dst & 0xffff);
        acc += proto;
        acc += len;
        return acc;
    }

    static byte[] tcp(int src, int dst, int srcPort, int dstPort, int seq, int ack, int flags, int window,
                      int mssOption, byte[] data, int off, int len) {
        int optLen = mssOption > 0 ? 4 : 0;
        int tcpLen = 20 + optLen + len;
        byte[] p = new byte[20 + tcpLen];
        int t = 20;
        put16(p, t, srcPort);
        put16(p, t + 2, dstPort);
        put32(p, t + 4, seq);
        put32(p, t + 8, ack);
        p[t + 12] = (byte) (((20 + optLen) / 4) << 4);
        p[t + 13] = (byte) flags;
        put16(p, t + 14, window);
        if (optLen > 0) {
            p[t + 20] = 2;
            p[t + 21] = 4;
            put16(p, t + 22, mssOption);
        }
        if (len > 0) System.arraycopy(data, off, p, t + 20 + optLen, len);
        put16(p, t + 16, fold(sum(p, t, tcpLen, pseudo(src, dst, PROTO_TCP, tcpLen))));
        ipHeader(p, p.length, PROTO_TCP, src, dst);
        return p;
    }

    static byte[] udp(int src, int dst, int srcPort, int dstPort, byte[] data, int off, int len) {
        int udpLen = 8 + len;
        byte[] p = new byte[20 + udpLen];
        put16(p, 20, srcPort);
        put16(p, 22, dstPort);
        put16(p, 24, udpLen);
        System.arraycopy(data, off, p, 28, len);
        int c = fold(sum(p, 20, udpLen, pseudo(src, dst, PROTO_UDP, udpLen)));
        put16(p, 26, c == 0 ? 0xffff : c);
        ipHeader(p, p.length, PROTO_UDP, src, dst);
        return p;
    }

    /** MSS из опций SYN, либо -1. */
    static int parseMss(byte[] b, int optOff, int optEnd) {
        int i = optOff;
        while (i < optEnd) {
            int kind = b[i] & 0xff;
            if (kind == 0) break;
            if (kind == 1) {
                i++;
                continue;
            }
            if (i + 1 >= optEnd) break;
            int l = b[i + 1] & 0xff;
            if (l < 2) break;
            if (kind == 2 && l == 4 && i + 3 < optEnd) return u16(b, i + 2);
            i += l;
        }
        return -1;
    }
}
