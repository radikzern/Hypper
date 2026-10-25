package com.apo.hypper.net.tls;

/**
 * Keccak-f[1600] и губки SHA3-256/SHA3-512/SHAKE128/SHAKE256 (FIPS 202) — для ML-KEM.
 * В старых Android SHA-3 нет, поэтому своя реализация.
 */
final class Keccak {
    private static final long[] RC = {
            0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL, 0x8000000080008000L,
            0x000000000000808bL, 0x0000000080000001L, 0x8000000080008081L, 0x8000000000008009L,
            0x000000000000008aL, 0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
            0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L, 0x8000000000008003L,
            0x8000000000008002L, 0x8000000000000080L, 0x000000000000800aL, 0x800000008000000aL,
            0x8000000080008081L, 0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L};
    private static final int[] ROT = {
            0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14};

    private final long[] s = new long[25];
    private final int rate;      // байт
    private final byte pad;      // 0x06 для SHA3, 0x1f для SHAKE
    private int pos;             // позиция в блоке (поглощение или выжимание)
    private boolean squeezing;

    private Keccak(int rate, byte pad) {
        this.rate = rate;
        this.pad = pad;
    }

    static Keccak shake128() {
        return new Keccak(168, (byte) 0x1f);
    }

    static Keccak shake256() {
        return new Keccak(136, (byte) 0x1f);
    }

    static byte[] sha3_256(byte[]... parts) {
        Keccak k = new Keccak(136, (byte) 0x06);
        for (byte[] p : parts) k.absorb(p, 0, p.length);
        return k.squeeze(32);
    }

    static byte[] sha3_512(byte[]... parts) {
        Keccak k = new Keccak(72, (byte) 0x06);
        for (byte[] p : parts) k.absorb(p, 0, p.length);
        return k.squeeze(64);
    }

    static byte[] shake256(int outLen, byte[]... parts) {
        Keccak k = shake256();
        for (byte[] p : parts) k.absorb(p, 0, p.length);
        return k.squeeze(outLen);
    }

    Keccak absorb(byte[] b, int off, int len) {
        if (squeezing) throw new IllegalStateException("Keccak: уже выжимаем");
        for (int i = 0; i < len; i++) {
            xorByte(pos, b[off + i]);
            if (++pos == rate) {
                permute();
                pos = 0;
            }
        }
        return this;
    }

    byte[] squeeze(int n) {
        byte[] out = new byte[n];
        squeeze(out, 0, n);
        return out;
    }

    void squeeze(byte[] out, int off, int n) {
        if (!squeezing) {
            xorByte(pos, pad);
            xorByte(rate - 1, (byte) 0x80);
            permute();
            pos = 0;
            squeezing = true;
        }
        for (int i = 0; i < n; i++) {
            if (pos == rate) {
                permute();
                pos = 0;
            }
            out[off + i] = (byte) (s[pos >> 3] >>> ((pos & 7) * 8));
            pos++;
        }
    }

    private void xorByte(int i, byte v) {
        s[i >> 3] ^= (long) (v & 0xff) << ((i & 7) * 8);
    }

    private void permute() {
        long[] a = s;
        long[] c = new long[5];
        long[] b = new long[25];
        for (int round = 0; round < 24; round++) {
            for (int x = 0; x < 5; x++) c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
            for (int x = 0; x < 5; x++) {
                long d = c[(x + 4) % 5] ^ Long.rotateLeft(c[(x + 1) % 5], 1);
                for (int y = 0; y < 25; y += 5) a[y + x] ^= d;
            }
            for (int x = 0; x < 5; x++) {
                for (int y = 0; y < 5; y++) {
                    int i = x + 5 * y;
                    b[y + 5 * ((2 * x + 3 * y) % 5)] = Long.rotateLeft(a[i], ROT[i]);
                }
            }
            for (int y = 0; y < 25; y += 5) {
                for (int x = 0; x < 5; x++) a[y + x] = b[y + x] ^ (~b[y + (x + 1) % 5] & b[y + (x + 2) % 5]);
            }
            a[0] ^= RC[round];
        }
    }
}
