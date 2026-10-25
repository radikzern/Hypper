package com.apo.hypper.net.wg;

import java.security.SecureRandom;

/** X25519 (RFC 7748), порт TweetNaCl: 16 лимбов по 16 бит в long, без BigInteger. */
public final class X25519 {
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final byte[] BASE = new byte[32];
    private static final long[] A24 = {0xDB41, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    static {
        BASE[0] = 9;
    }

    private X25519() {
    }

    public static byte[] generatePrivate() {
        byte[] k = new byte[32];
        RANDOM.nextBytes(k);
        clamp(k);
        return k;
    }

    static void clamp(byte[] k) {
        k[0] &= (byte) 248;
        k[31] &= 127;
        k[31] |= 64;
    }

    public static byte[] publicKey(byte[] priv) {
        return scalarMult(priv, BASE);
    }

    private static void car(long[] o) {
        for (int i = 0; i < 16; i++) {
            o[i] += 1L << 16;
            long c = o[i] >> 16;
            if (i < 15) o[i + 1] += c - 1;
            else o[0] += 38 * (c - 1);
            o[i] -= c << 16;
        }
    }

    private static void sel(long[] p, long[] q, int b) {
        long c = ~(b - 1);
        for (int i = 0; i < 16; i++) {
            long t = c & (p[i] ^ q[i]);
            p[i] ^= t;
            q[i] ^= t;
        }
    }

    private static void pack(byte[] o, long[] n) {
        long[] m = new long[16], t = n.clone();
        car(t);
        car(t);
        car(t);
        for (int j = 0; j < 2; j++) {
            m[0] = t[0] - 0xffed;
            for (int i = 1; i < 15; i++) {
                m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
                m[i - 1] &= 0xffff;
            }
            m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
            int b = (int) ((m[15] >> 16) & 1);
            m[14] &= 0xffff;
            sel(t, m, 1 - b);
        }
        for (int i = 0; i < 16; i++) {
            o[2 * i] = (byte) t[i];
            o[2 * i + 1] = (byte) (t[i] >> 8);
        }
    }

    private static void add(long[] o, long[] a, long[] b) {
        for (int i = 0; i < 16; i++) o[i] = a[i] + b[i];
    }

    private static void sub(long[] o, long[] a, long[] b) {
        for (int i = 0; i < 16; i++) o[i] = a[i] - b[i];
    }

    private static void mul(long[] o, long[] a, long[] b) {
        long[] t = new long[31];
        for (int i = 0; i < 16; i++) {
            long ai = a[i];
            for (int j = 0; j < 16; j++) t[i + j] += ai * b[j];
        }
        for (int i = 0; i < 15; i++) t[i] += 38 * t[i + 16];
        System.arraycopy(t, 0, o, 0, 16);
        car(o);
        car(o);
    }

    private static void inv(long[] o, long[] in) {
        long[] c = in.clone();
        for (int a = 253; a >= 0; a--) {
            mul(c, c, c);
            if (a != 2 && a != 4) mul(c, c, in);
        }
        System.arraycopy(c, 0, o, 0, 16);
    }

    public static byte[] scalarMult(byte[] n, byte[] p) {
        byte[] z = n.clone();
        clamp(z);
        long[] x = new long[16];
        for (int i = 0; i < 16; i++) x[i] = (p[2 * i] & 0xff) + ((long) (p[2 * i + 1] & 0xff) << 8);
        x[15] &= 0x7fff;
        long[] a = new long[16], b = x.clone(), c = new long[16], d = new long[16];
        long[] e = new long[16], f = new long[16];
        a[0] = d[0] = 1;
        for (int i = 254; i >= 0; i--) {
            int r = (z[i >>> 3] >>> (i & 7)) & 1;
            sel(a, b, r);
            sel(c, d, r);
            add(e, a, c);
            sub(a, a, c);
            add(c, b, d);
            sub(b, b, d);
            mul(d, e, e);
            mul(f, a, a);
            mul(a, c, a);
            mul(c, b, e);
            add(e, a, c);
            sub(a, a, c);
            mul(b, a, a);
            sub(c, d, f);
            mul(a, c, A24);
            add(a, a, d);
            mul(c, c, a);
            mul(a, d, f);
            mul(d, b, x);
            mul(b, e, e);
            sel(a, b, r);
            sel(c, d, r);
        }
        inv(c, c);
        mul(a, a, c);
        byte[] out = new byte[32];
        pack(out, a);
        return out;
    }
}
