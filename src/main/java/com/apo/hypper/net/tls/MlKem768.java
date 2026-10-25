package com.apo.hypper.net.tls;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * ML-KEM-768 (FIPS 203) — постквантовая половина гибридной группы X25519MLKEM768.
 * Современные серверы REALITY без неё не пускают клиента, а настоящие сайты
 * (которые зеркалит REALITY) охотно выбирают именно её.
 */
final class MlKem768 {
    static final int EK_SIZE = 1184;
    static final int DK_SIZE = 2400;
    static final int CT_SIZE = 1088;

    private static final int N = 256, Q = 3329, K = 3, ETA1 = 2, ETA2 = 2, DU = 10, DV = 4;
    private static final int[] ZETAS = new int[128];
    private static final int[] GAMMAS = new int[128];

    static {
        for (int i = 0; i < 128; i++) {
            ZETAS[i] = pow17(bitRev7(i));
            GAMMAS[i] = pow17(2 * bitRev7(i) + 1);
        }
    }

    /** Пара ключей: ek (1184 байта) — в key_share, dk (2400 байт) — для декапсуляции. */
    static final class KeyPair {
        final byte[] ek, dk;

        KeyPair(byte[] ek, byte[] dk) {
            this.ek = ek;
            this.dk = dk;
        }
    }

    static KeyPair generate(SecureRandom rnd) {
        byte[] d = new byte[32], z = new byte[32];
        rnd.nextBytes(d);
        rnd.nextBytes(z);
        return keyGen(d, z);
    }

    static KeyPair keyGen(byte[] d, byte[] z) {
        byte[] g = Keccak.sha3_512(d, new byte[]{K});
        byte[] rho = Arrays.copyOfRange(g, 0, 32), sigma = Arrays.copyOfRange(g, 32, 64);
        int[][][] a = matrix(rho);
        int nonce = 0;
        int[][] s = new int[K][], e = new int[K][];
        for (int i = 0; i < K; i++) s[i] = ntt(cbd(prf(sigma, nonce++, ETA1), ETA1));
        for (int i = 0; i < K; i++) e[i] = ntt(cbd(prf(sigma, nonce++, ETA1), ETA1));
        byte[] ek = new byte[EK_SIZE];
        byte[] dkPke = new byte[384 * K];
        for (int i = 0; i < K; i++) {
            int[] t = e[i].clone();
            for (int j = 0; j < K; j++) addTo(t, mulNtt(a[i][j], s[j]));
            encode(t, 12, ek, 384 * i);
            encode(s[i], 12, dkPke, 384 * i);
        }
        System.arraycopy(rho, 0, ek, 384 * K, 32);

        byte[] dk = new byte[DK_SIZE];
        System.arraycopy(dkPke, 0, dk, 0, dkPke.length);
        System.arraycopy(ek, 0, dk, 384 * K, EK_SIZE);
        System.arraycopy(Keccak.sha3_256(ek), 0, dk, 384 * K + EK_SIZE, 32);
        System.arraycopy(z, 0, dk, 384 * K + EK_SIZE + 32, 32);
        return new KeyPair(ek, dk);
    }

    /** Инкапсуляция: {ciphertext, sharedSecret}. Клиенту TLS не нужна, используется в тестах. */
    static byte[][] encaps(byte[] ek, byte[] m) {
        byte[] g = Keccak.sha3_512(m, Keccak.sha3_256(ek));
        byte[] key = Arrays.copyOfRange(g, 0, 32), r = Arrays.copyOfRange(g, 32, 64);
        return new byte[][]{encrypt(ek, m, r), key};
    }

    /** Декапсуляция (с неявным отказом по FO-преобразованию). */
    static byte[] decaps(byte[] dk, byte[] ct) {
        if (dk.length != DK_SIZE || ct.length != CT_SIZE) throw new IllegalArgumentException("ML-KEM: неверная длина");
        byte[] dkPke = Arrays.copyOfRange(dk, 0, 384 * K);
        byte[] ek = Arrays.copyOfRange(dk, 384 * K, 384 * K + EK_SIZE);
        byte[] h = Arrays.copyOfRange(dk, 384 * K + EK_SIZE, 384 * K + EK_SIZE + 32);
        byte[] z = Arrays.copyOfRange(dk, 384 * K + EK_SIZE + 32, DK_SIZE);

        byte[] m = decrypt(dkPke, ct);
        byte[] g = Keccak.sha3_512(m, h);
        byte[] key = Arrays.copyOfRange(g, 0, 32), r = Arrays.copyOfRange(g, 32, 64);
        byte[] reject = Keccak.shake256(32, z, ct);
        byte[] ct2 = encrypt(ek, m, r);
        return MessageDigest.isEqual(ct, ct2) ? key : reject;
    }

    // ---------------------------------------------------------------- K-PKE

    private static byte[] encrypt(byte[] ek, byte[] m, byte[] r) {
        int[][] t = new int[K][];
        for (int i = 0; i < K; i++) t[i] = decode(ek, 384 * i, 12);
        int[][][] a = matrix(Arrays.copyOfRange(ek, 384 * K, 384 * K + 32));
        int nonce = 0;
        int[][] y = new int[K][];
        for (int i = 0; i < K; i++) y[i] = ntt(cbd(prf(r, nonce++, ETA1), ETA1));
        int[][] e1 = new int[K][];
        for (int i = 0; i < K; i++) e1[i] = cbd(prf(r, nonce++, ETA2), ETA2);
        int[] e2 = cbd(prf(r, nonce, ETA2), ETA2);

        byte[] ct = new byte[CT_SIZE];
        for (int i = 0; i < K; i++) {
            int[] u = new int[N];
            for (int j = 0; j < K; j++) addTo(u, mulNtt(a[j][i], y[j])); // Aᵀ
            u = invNtt(u);
            addTo(u, e1[i]);
            compress(u, DU);
            encode(u, DU, ct, 32 * DU * i);
        }
        int[] v = new int[N];
        for (int j = 0; j < K; j++) addTo(v, mulNtt(t[j], y[j]));
        v = invNtt(v);
        addTo(v, e2);
        int[] mu = decode(m, 0, 1);
        decompress(mu, 1);
        addTo(v, mu);
        compress(v, DV);
        encode(v, DV, ct, 32 * DU * K);
        return ct;
    }

    private static byte[] decrypt(byte[] dkPke, byte[] ct) {
        int[] w = decode(ct, 32 * DU * K, DV);
        decompress(w, DV);
        int[] acc = new int[N];
        for (int i = 0; i < K; i++) {
            int[] u = decode(ct, 32 * DU * i, DU);
            decompress(u, DU);
            addTo(acc, mulNtt(decode(dkPke, 384 * i, 12), ntt(u)));
        }
        acc = invNtt(acc);
        for (int i = 0; i < N; i++) w[i] = mod(w[i] - acc[i]);
        compress(w, 1);
        byte[] m = new byte[32];
        encode(w, 1, m, 0);
        return m;
    }

    // ---------------------------------------------------------------- выборки

    /** Â[i][j] = SampleNTT(ρ ‖ j ‖ i). */
    private static int[][][] matrix(byte[] rho) {
        int[][][] a = new int[K][K][];
        for (int i = 0; i < K; i++) {
            for (int j = 0; j < K; j++) {
                Keccak x = Keccak.shake128().absorb(rho, 0, 32).absorb(new byte[]{(byte) j, (byte) i}, 0, 2);
                int[] p = new int[N];
                byte[] c = new byte[3];
                int n = 0;
                while (n < N) {
                    x.squeeze(c, 0, 3);
                    int d1 = (c[0] & 0xff) | ((c[1] & 0x0f) << 8);
                    int d2 = ((c[1] & 0xff) >> 4) | ((c[2] & 0xff) << 4);
                    if (d1 < Q) p[n++] = d1;
                    if (d2 < Q && n < N) p[n++] = d2;
                }
                a[i][j] = p;
            }
        }
        return a;
    }

    private static byte[] prf(byte[] seed, int nonce, int eta) {
        return Keccak.shake256(64 * eta, seed, new byte[]{(byte) nonce});
    }

    private static int[] cbd(byte[] b, int eta) {
        int[] f = new int[N];
        for (int i = 0; i < N; i++) {
            int x = 0, y = 0;
            for (int j = 0; j < eta; j++) {
                x += bit(b, 2 * i * eta + j);
                y += bit(b, 2 * i * eta + eta + j);
            }
            f[i] = mod(x - y);
        }
        return f;
    }

    private static int bit(byte[] b, int i) {
        return (b[i >> 3] >> (i & 7)) & 1;
    }

    // ---------------------------------------------------------------- NTT

    private static int[] ntt(int[] in) {
        int[] f = in.clone();
        int k = 1;
        for (int len = 128; len >= 2; len >>= 1) {
            for (int start = 0; start < N; start += 2 * len) {
                int zeta = ZETAS[k++];
                for (int j = start; j < start + len; j++) {
                    int t = (int) ((long) zeta * f[j + len] % Q);
                    f[j + len] = mod(f[j] - t);
                    f[j] = mod(f[j] + t);
                }
            }
        }
        return f;
    }

    private static int[] invNtt(int[] in) {
        int[] f = in.clone();
        int k = 127;
        for (int len = 2; len <= 128; len <<= 1) {
            for (int start = 0; start < N; start += 2 * len) {
                int zeta = ZETAS[k--];
                for (int j = start; j < start + len; j++) {
                    int t = f[j];
                    f[j] = mod(t + f[j + len]);
                    f[j + len] = (int) ((long) zeta * mod(f[j + len] - t) % Q);
                }
            }
        }
        for (int i = 0; i < N; i++) f[i] = (int) ((long) f[i] * 3303 % Q);
        return f;
    }

    private static int[] mulNtt(int[] f, int[] g) {
        int[] h = new int[N];
        for (int i = 0; i < 128; i++) {
            long a0 = f[2 * i], a1 = f[2 * i + 1], b0 = g[2 * i], b1 = g[2 * i + 1];
            h[2 * i] = (int) ((a0 * b0 + a1 * b1 % Q * GAMMAS[i]) % Q);
            h[2 * i + 1] = (int) ((a0 * b1 + a1 * b0) % Q);
        }
        return h;
    }

    private static void addTo(int[] a, int[] b) {
        for (int i = 0; i < N; i++) a[i] = mod(a[i] + b[i]);
    }

    // ---------------------------------------------------------------- кодирование

    private static void compress(int[] f, int d) {
        for (int i = 0; i < N; i++) f[i] = (int) ((((long) f[i] << d) + Q / 2) / Q) & ((1 << d) - 1);
    }

    private static void decompress(int[] f, int d) {
        for (int i = 0; i < N; i++) f[i] = (int) (((long) f[i] * Q + (1 << (d - 1))) >> d);
    }

    private static void encode(int[] f, int d, byte[] out, int off) {
        int bitPos = 0;
        for (int i = 0; i < N; i++) {
            int a = f[i];
            for (int j = 0; j < d; j++, bitPos++) {
                if (((a >> j) & 1) != 0) out[off + (bitPos >> 3)] |= (byte) (1 << (bitPos & 7));
            }
        }
    }

    private static int[] decode(byte[] b, int off, int d) {
        int[] f = new int[N];
        int bitPos = 0;
        for (int i = 0; i < N; i++) {
            int a = 0;
            for (int j = 0; j < d; j++, bitPos++) a |= ((b[off + (bitPos >> 3)] >> (bitPos & 7)) & 1) << j;
            f[i] = d == 12 ? a % Q : a;
        }
        return f;
    }

    private static int mod(int x) {
        x %= Q;
        return x < 0 ? x + Q : x;
    }

    private static int bitRev7(int i) {
        int r = 0;
        for (int j = 0; j < 7; j++) r |= ((i >> j) & 1) << (6 - j);
        return r;
    }

    private static int pow17(int e) {
        long r = 1;
        for (int i = 0; i < e; i++) r = r * 17 % Q;
        return (int) r;
    }
}
