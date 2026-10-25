package com.apo.hypper.net.tls;

import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES-GCM (NIST SP 800-38D), только шифрование с 12-байтовым nonce и 16-байтовым тегом.
 * Нужен для пломбы REALITY: сервер расшифровывает её именно AES-GCM.
 * Системный "AES/GCM/NoPadding" есть лишь с API 19, поэтому GCM собран поверх AES/ECB.
 */
final class AesGcm {
    private final Cipher aes;
    private final long hHi, hLo; // H = E_K(0^128)

    AesGcm(byte[] key) {
        try {
            aes = Cipher.getInstance("AES/ECB/NoPadding");
            aes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES недоступен: " + e);
        }
        byte[] h = block(new byte[16]);
        hHi = getLong(h, 0);
        hLo = getLong(h, 8);
    }

    /** Возвращает ciphertext || tag (len + 16 байт). */
    byte[] seal(byte[] nonce, byte[] aad, byte[] plain, int off, int len) {
        if (nonce.length != 12) throw new IllegalArgumentException("GCM: nonce должен быть 12 байт");
        byte[] counter = new byte[16];
        System.arraycopy(nonce, 0, counter, 0, 12);
        counter[15] = 1;
        byte[] tagMask = block(counter); // E_K(J0)

        byte[] out = new byte[len + 16];
        for (int i = 0; i < len; i += 16) {
            inc32(counter);
            byte[] ks = block(counter);
            int n = Math.min(16, len - i);
            for (int j = 0; j < n; j++) out[i + j] = (byte) (plain[off + i + j] ^ ks[j]);
        }

        long[] s = new long[2];
        ghash(s, aad, 0, aad.length);
        ghash(s, out, 0, len);
        long aBits = (long) aad.length * 8, cBits = (long) len * 8;
        s[0] ^= aBits;
        s[1] ^= cBits;
        mulH(s);

        putLong(out, len, s[0] ^ getLong(tagMask, 0));
        putLong(out, len + 8, s[1] ^ getLong(tagMask, 8));
        return out;
    }

    private byte[] block(byte[] in) {
        try {
            return aes.doFinal(in);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Добавляет данные в GHASH, дополняя последний блок нулями. */
    private void ghash(long[] s, byte[] b, int off, int len) {
        byte[] tmp = new byte[16];
        for (int i = 0; i < len; i += 16) {
            int n = Math.min(16, len - i);
            if (n == 16) {
                s[0] ^= getLong(b, off + i);
                s[1] ^= getLong(b, off + i + 8);
            } else {
                java.util.Arrays.fill(tmp, (byte) 0);
                System.arraycopy(b, off + i, tmp, 0, n);
                s[0] ^= getLong(tmp, 0);
                s[1] ^= getLong(tmp, 8);
            }
            mulH(s);
        }
    }

    /** s = s · H в GF(2^128) (битовый порядок GCM, R = 0xE1 || 0^120). */
    private void mulH(long[] s) {
        long zHi = 0, zLo = 0, vHi = hHi, vLo = hLo;
        long xHi = s[0], xLo = s[1];
        for (int i = 0; i < 128; i++) {
            long bit = i < 64 ? (xHi >>> (63 - i)) & 1 : (xLo >>> (127 - i)) & 1;
            if (bit != 0) {
                zHi ^= vHi;
                zLo ^= vLo;
            }
            boolean lsb = (vLo & 1) != 0;
            vLo = (vLo >>> 1) | (vHi << 63);
            vHi = vHi >>> 1;
            if (lsb) vHi ^= 0xE100000000000000L;
        }
        s[0] = zHi;
        s[1] = zLo;
    }

    private static void inc32(byte[] c) {
        for (int i = 15; i >= 12; i--) if (++c[i] != 0) break;
    }

    private static long getLong(byte[] b, int off) {
        long v = 0;
        for (int i = 0; i < 8; i++) v = (v << 8) | (b[off + i] & 0xff);
        return v;
    }

    private static void putLong(byte[] b, int off, long v) {
        for (int i = 7; i >= 0; i--) {
            b[off + i] = (byte) v;
            v >>>= 8;
        }
    }
}
