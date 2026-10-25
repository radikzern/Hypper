package com.apo.hypper.net.wg;

/** ChaCha20-Poly1305 AEAD (RFC 8439) на чистой Java — на Android 4 его нет в системе. */
public final class ChaChaPoly {
    private final int[] key = new int[8];
    private final int[] state = new int[16];
    private final int[] x = new int[16];
    private final byte[] block = new byte[64];

    public ChaChaPoly(byte[] k) {
        for (int i = 0; i < 8; i++) key[i] = le32(k, i * 4);
    }

    static int le32(byte[] b, int o) {
        return (b[o] & 0xff) | (b[o + 1] & 0xff) << 8 | (b[o + 2] & 0xff) << 16 | (b[o + 3] & 0xff) << 24;
    }

    static void put32(byte[] b, int o, int v) {
        b[o] = (byte) v;
        b[o + 1] = (byte) (v >>> 8);
        b[o + 2] = (byte) (v >>> 16);
        b[o + 3] = (byte) (v >>> 24);
    }

    private void keystream(int counter, int n0, int n1, int n2) {
        int[] s = state;
        s[0] = 0x61707865;
        s[1] = 0x3320646e;
        s[2] = 0x79622d32;
        s[3] = 0x6b206574;
        System.arraycopy(key, 0, s, 4, 8);
        s[12] = counter;
        s[13] = n0;
        s[14] = n1;
        s[15] = n2;
        System.arraycopy(s, 0, x, 0, 16);
        for (int i = 0; i < 10; i++) {
            qr(0, 4, 8, 12);
            qr(1, 5, 9, 13);
            qr(2, 6, 10, 14);
            qr(3, 7, 11, 15);
            qr(0, 5, 10, 15);
            qr(1, 6, 11, 12);
            qr(2, 7, 8, 13);
            qr(3, 4, 9, 14);
        }
        for (int i = 0; i < 16; i++) put32(block, i * 4, x[i] + s[i]);
    }

    private void qr(int a, int b, int c, int d) {
        int[] v = x;
        v[a] += v[b];
        v[d] = Integer.rotateLeft(v[d] ^ v[a], 16);
        v[c] += v[d];
        v[b] = Integer.rotateLeft(v[b] ^ v[c], 12);
        v[a] += v[b];
        v[d] = Integer.rotateLeft(v[d] ^ v[a], 8);
        v[c] += v[d];
        v[b] = Integer.rotateLeft(v[b] ^ v[c], 7);
    }

    private void xor(int n0, int n1, int n2, byte[] in, int inOff, byte[] out, int outOff, int len) {
        int counter = 1;
        for (int pos = 0; pos < len; pos += 64) {
            keystream(counter++, n0, n1, n2);
            int n = Math.min(64, len - pos);
            for (int i = 0; i < n; i++) out[outOff + pos + i] = (byte) (in[inOff + pos + i] ^ block[i]);
        }
    }

    private byte[] tag(int n0, int n1, int n2, byte[] aad, byte[] ct, int ctOff, int ctLen) {
        keystream(0, n0, n1, n2);
        Poly1305 p = new Poly1305(block);
        int aadLen = aad == null ? 0 : aad.length;
        if (aadLen > 0) {
            p.update(aad, 0, aadLen);
            p.pad();
        }
        p.update(ct, ctOff, ctLen);
        p.pad();
        byte[] lens = new byte[16];
        put32(lens, 0, aadLen);
        put32(lens, 8, ctLen);
        p.update(lens, 0, 16);
        return p.finish();
    }

    /** nonce WireGuard: 4 нулевых байта + 64-битный счётчик LE. Выход: ct || tag(16). */
    synchronized void seal(long counter, byte[] aad, byte[] in, int inOff, int len, byte[] out, int outOff) {
        int n1 = (int) counter, n2 = (int) (counter >>> 32);
        xor(0, n1, n2, in, inOff, out, outOff, len);
        byte[] t = tag(0, n1, n2, aad, out, outOff, len);
        System.arraycopy(t, 0, out, outOff + len, 16);
    }

    /** len — длина вместе с тегом. Возвращает false, если тег не сошёлся. */
    synchronized boolean open(long counter, byte[] aad, byte[] in, int inOff, int len, byte[] out, int outOff) {
        if (len < 16) return false;
        int n1 = (int) counter, n2 = (int) (counter >>> 32);
        int ctLen = len - 16;
        byte[] t = tag(0, n1, n2, aad, in, inOff, ctLen);
        int diff = 0;
        for (int i = 0; i < 16; i++) diff |= t[i] ^ in[inOff + ctLen + i];
        if (diff != 0) return false;
        xor(0, n1, n2, in, inOff, out, outOff, ctLen);
        return true;
    }

    /** Произвольный 96-битный nonce (TLS). Выход: ct || tag. */
    public synchronized byte[] sealNonce(byte[] nonce, byte[] aad, byte[] in, int off, int len) {
        int n0 = le32(nonce, 0), n1 = le32(nonce, 4), n2 = le32(nonce, 8);
        byte[] out = new byte[len + 16];
        xor(n0, n1, n2, in, off, out, 0, len);
        System.arraycopy(tag(n0, n1, n2, aad, out, 0, len), 0, out, len, 16);
        return out;
    }

    /** null, если тег не сошёлся. len — вместе с тегом. */
    public synchronized byte[] openNonce(byte[] nonce, byte[] aad, byte[] in, int off, int len) {
        if (len < 16) return null;
        int n0 = le32(nonce, 0), n1 = le32(nonce, 4), n2 = le32(nonce, 8);
        int ctLen = len - 16;
        byte[] t = tag(n0, n1, n2, aad, in, off, ctLen);
        int diff = 0;
        for (int i = 0; i < 16; i++) diff |= t[i] ^ in[off + ctLen + i];
        if (diff != 0) return null;
        byte[] out = new byte[ctLen];
        xor(n0, n1, n2, in, off, out, 0, ctLen);
        return out;
    }

    static byte[] seal(byte[] key, long counter, byte[] aad, byte[] plain) {
        byte[] out = new byte[plain.length + 16];
        new ChaChaPoly(key).seal(counter, aad, plain, 0, plain.length, out, 0);
        return out;
    }

    static byte[] open(byte[] key, long counter, byte[] aad, byte[] ct) {
        byte[] out = new byte[Math.max(0, ct.length - 16)];
        return new ChaChaPoly(key).open(counter, aad, ct, 0, ct.length, out, 0) ? out : null;
    }

    /** Poly1305, вариант donna-32 (26-битные лимбы). */
    static final class Poly1305 {
        private final int r0, r1, r2, r3, r4, s1, s2, s3, s4;
        private final int pad0, pad1, pad2, pad3;
        private int h0, h1, h2, h3, h4;
        private final byte[] buf = new byte[16];
        private int bufLen;

        Poly1305(byte[] k) {
            int t0 = le32(k, 0), t1 = le32(k, 4), t2 = le32(k, 8), t3 = le32(k, 12);
            r0 = t0 & 0x3ffffff;
            r1 = ((t0 >>> 26) | (t1 << 6)) & 0x3ffff03;
            r2 = ((t1 >>> 20) | (t2 << 12)) & 0x3ffc0ff;
            r3 = ((t2 >>> 14) | (t3 << 18)) & 0x3f03fff;
            r4 = (t3 >>> 8) & 0x00fffff;
            s1 = r1 * 5;
            s2 = r2 * 5;
            s3 = r3 * 5;
            s4 = r4 * 5;
            pad0 = le32(k, 16);
            pad1 = le32(k, 20);
            pad2 = le32(k, 24);
            pad3 = le32(k, 28);
        }

        void update(byte[] m, int off, int len) {
            while (len > 0) {
                if (bufLen == 0 && len >= 16) {
                    block(m, off, 1 << 24);
                    off += 16;
                    len -= 16;
                    continue;
                }
                int n = Math.min(16 - bufLen, len);
                System.arraycopy(m, off, buf, bufLen, n);
                bufLen += n;
                off += n;
                len -= n;
                if (bufLen == 16) {
                    block(buf, 0, 1 << 24);
                    bufLen = 0;
                }
            }
        }

        /** Дополнение нулями до границы 16 байт (между AAD и шифротекстом). */
        void pad() {
            if (bufLen == 0) return;
            for (int i = bufLen; i < 16; i++) buf[i] = 0;
            block(buf, 0, 1 << 24);
            bufLen = 0;
        }

        private void block(byte[] m, int o, int hibit) {
            int t0 = le32(m, o), t1 = le32(m, o + 4), t2 = le32(m, o + 8), t3 = le32(m, o + 12);
            h0 += t0 & 0x3ffffff;
            h1 += ((t0 >>> 26) | (t1 << 6)) & 0x3ffffff;
            h2 += ((t1 >>> 20) | (t2 << 12)) & 0x3ffffff;
            h3 += ((t2 >>> 14) | (t3 << 18)) & 0x3ffffff;
            h4 += (t3 >>> 8) | hibit;

            long d0 = (long) h0 * r0 + (long) h1 * s4 + (long) h2 * s3 + (long) h3 * s2 + (long) h4 * s1;
            long d1 = (long) h0 * r1 + (long) h1 * r0 + (long) h2 * s4 + (long) h3 * s3 + (long) h4 * s2;
            long d2 = (long) h0 * r2 + (long) h1 * r1 + (long) h2 * r0 + (long) h3 * s4 + (long) h4 * s3;
            long d3 = (long) h0 * r3 + (long) h1 * r2 + (long) h2 * r1 + (long) h3 * r0 + (long) h4 * s4;
            long d4 = (long) h0 * r4 + (long) h1 * r3 + (long) h2 * r2 + (long) h3 * r1 + (long) h4 * r0;

            long c = d0 >>> 26;
            h0 = (int) d0 & 0x3ffffff;
            d1 += c;
            c = d1 >>> 26;
            h1 = (int) d1 & 0x3ffffff;
            d2 += c;
            c = d2 >>> 26;
            h2 = (int) d2 & 0x3ffffff;
            d3 += c;
            c = d3 >>> 26;
            h3 = (int) d3 & 0x3ffffff;
            d4 += c;
            c = d4 >>> 26;
            h4 = (int) d4 & 0x3ffffff;
            h0 += (int) c * 5;
            int cc = h0 >>> 26;
            h0 &= 0x3ffffff;
            h1 += cc;
        }

        byte[] finish() {
            if (bufLen > 0) {
                buf[bufLen] = 1;
                for (int i = bufLen + 1; i < 16; i++) buf[i] = 0;
                block(buf, 0, 0);
                bufLen = 0;
            }
            int c = h1 >>> 26;
            h1 &= 0x3ffffff;
            h2 += c;
            c = h2 >>> 26;
            h2 &= 0x3ffffff;
            h3 += c;
            c = h3 >>> 26;
            h3 &= 0x3ffffff;
            h4 += c;
            c = h4 >>> 26;
            h4 &= 0x3ffffff;
            h0 += c * 5;
            c = h0 >>> 26;
            h0 &= 0x3ffffff;
            h1 += c;

            int g0 = h0 + 5;
            c = g0 >>> 26;
            g0 &= 0x3ffffff;
            int g1 = h1 + c;
            c = g1 >>> 26;
            g1 &= 0x3ffffff;
            int g2 = h2 + c;
            c = g2 >>> 26;
            g2 &= 0x3ffffff;
            int g3 = h3 + c;
            c = g3 >>> 26;
            g3 &= 0x3ffffff;
            int g4 = h4 + c - (1 << 26);

            int mask = (g4 >>> 31) - 1;
            g0 &= mask;
            g1 &= mask;
            g2 &= mask;
            g3 &= mask;
            g4 &= mask;
            mask = ~mask;
            h0 = (h0 & mask) | g0;
            h1 = (h1 & mask) | g1;
            h2 = (h2 & mask) | g2;
            h3 = (h3 & mask) | g3;
            h4 = (h4 & mask) | g4;

            int f0 = h0 | (h1 << 26);
            int f1 = (h1 >>> 6) | (h2 << 20);
            int f2 = (h2 >>> 12) | (h3 << 14);
            int f3 = (h3 >>> 18) | (h4 << 8);

            long f = (f0 & 0xffffffffL) + (pad0 & 0xffffffffL);
            byte[] out = new byte[16];
            put32(out, 0, (int) f);
            f = (f1 & 0xffffffffL) + (pad1 & 0xffffffffL) + (f >>> 32);
            put32(out, 4, (int) f);
            f = (f2 & 0xffffffffL) + (pad2 & 0xffffffffL) + (f >>> 32);
            put32(out, 8, (int) f);
            f = (f3 & 0xffffffffL) + (pad3 & 0xffffffffL) + (f >>> 32);
            put32(out, 12, (int) f);
            return out;
        }
    }
}
