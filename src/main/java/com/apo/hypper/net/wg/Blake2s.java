package com.apo.hypper.net.wg;

/** BLAKE2s (RFC 7693) и HMAC/HKDF поверх него — как требует WireGuard. */
final class Blake2s {
    private static final int[] IV = {
            0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
            0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19};
    private static final byte[][] SIGMA = {
            {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
            {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
            {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
            {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
            {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
            {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
            {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
            {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
            {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
            {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0}};

    private final int[] h = new int[8];
    private final byte[] buf = new byte[64];
    private int bufLen;
    private long t;
    private final int outLen;
    private final int[] v = new int[16];
    private final int[] m = new int[16];

    Blake2s(int outLen, byte[] key) {
        this.outLen = outLen;
        System.arraycopy(IV, 0, h, 0, 8);
        int kl = key == null ? 0 : key.length;
        h[0] ^= 0x01010000 ^ (kl << 8) ^ outLen;
        if (kl > 0) {
            System.arraycopy(key, 0, buf, 0, kl);
            bufLen = 64;
        }
    }

    Blake2s update(byte[] in) {
        return update(in, 0, in.length);
    }

    Blake2s update(byte[] in, int off, int len) {
        while (len > 0) {
            if (bufLen == 64) {
                t += 64;
                compress(false);
                bufLen = 0;
            }
            int n = Math.min(64 - bufLen, len);
            System.arraycopy(in, off, buf, bufLen, n);
            bufLen += n;
            off += n;
            len -= n;
        }
        return this;
    }

    byte[] digest() {
        t += bufLen;
        for (int i = bufLen; i < 64; i++) buf[i] = 0;
        compress(true);
        byte[] out = new byte[outLen];
        byte[] full = new byte[32];
        for (int i = 0; i < 8; i++) ChaChaPoly.put32(full, i * 4, h[i]);
        System.arraycopy(full, 0, out, 0, outLen);
        return out;
    }

    private void compress(boolean last) {
        for (int i = 0; i < 16; i++) m[i] = ChaChaPoly.le32(buf, i * 4);
        System.arraycopy(h, 0, v, 0, 8);
        System.arraycopy(IV, 0, v, 8, 8);
        v[12] ^= (int) t;
        v[13] ^= (int) (t >>> 32);
        if (last) v[14] = ~v[14];
        for (int r = 0; r < 10; r++) {
            byte[] s = SIGMA[r];
            g(0, 4, 8, 12, m[s[0]], m[s[1]]);
            g(1, 5, 9, 13, m[s[2]], m[s[3]]);
            g(2, 6, 10, 14, m[s[4]], m[s[5]]);
            g(3, 7, 11, 15, m[s[6]], m[s[7]]);
            g(0, 5, 10, 15, m[s[8]], m[s[9]]);
            g(1, 6, 11, 12, m[s[10]], m[s[11]]);
            g(2, 7, 8, 13, m[s[12]], m[s[13]]);
            g(3, 4, 9, 14, m[s[14]], m[s[15]]);
        }
        for (int i = 0; i < 8; i++) h[i] ^= v[i] ^ v[i + 8];
    }

    private void g(int a, int b, int c, int d, int x, int y) {
        v[a] += v[b] + x;
        v[d] = Integer.rotateRight(v[d] ^ v[a], 16);
        v[c] += v[d];
        v[b] = Integer.rotateRight(v[b] ^ v[c], 12);
        v[a] += v[b] + y;
        v[d] = Integer.rotateRight(v[d] ^ v[a], 8);
        v[c] += v[d];
        v[b] = Integer.rotateRight(v[b] ^ v[c], 7);
    }

    static byte[] hash(byte[]... parts) {
        Blake2s b = new Blake2s(32, null);
        for (byte[] p : parts) b.update(p);
        return b.digest();
    }

    /** Ключевой BLAKE2s-128 — MAC1/MAC2 в WireGuard. */
    static byte[] mac(byte[] key, byte[] data, int len) {
        return new Blake2s(16, key).update(data, 0, len).digest();
    }

    static byte[] hmac(byte[] key, byte[] data) {
        byte[] k = new byte[64];
        byte[] kk = key.length > 64 ? hash(key) : key;
        System.arraycopy(kk, 0, k, 0, kk.length);
        byte[] ipad = new byte[64], opad = new byte[64];
        for (int i = 0; i < 64; i++) {
            ipad[i] = (byte) (k[i] ^ 0x36);
            opad[i] = (byte) (k[i] ^ 0x5c);
        }
        byte[] inner = new Blake2s(32, null).update(ipad).update(data).digest();
        return new Blake2s(32, null).update(opad).update(inner).digest();
    }

    /** HKDF из Noise: возвращает n ключей по 32 байта. */
    static byte[][] kdf(byte[] chainKey, byte[] input, int n) {
        byte[] t0 = hmac(chainKey, input);
        byte[][] out = new byte[n][];
        byte[] prev = new byte[0];
        for (int i = 0; i < n; i++) {
            byte[] in = new byte[prev.length + 1];
            System.arraycopy(prev, 0, in, 0, prev.length);
            in[prev.length] = (byte) (i + 1);
            prev = hmac(t0, in);
            out[i] = prev;
        }
        return out;
    }
}
