package com.apo.hypper.net.wg;

import java.io.ByteArrayOutputStream;

/** base64 / base64url без зависимости от android.util (нужно в юнит-тестах). */
public final class B64 {
    private static final char[] ABC =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray();

    private B64() {
    }

    /** Принимает оба алфавита, с паддингом и без, с пробелами. null — не base64. */
    public static byte[] decode(String s) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(s.length() * 3 / 4);
        int buf = 0, bits = 0, count = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\r' || c == '\n' || c == ' ' || c == '\t' || c == '=') continue;
            int v;
            if (c >= 'A' && c <= 'Z') v = c - 'A';
            else if (c >= 'a' && c <= 'z') v = c - 'a' + 26;
            else if (c >= '0' && c <= '9') v = c - '0' + 52;
            else if (c == '+' || c == '-') v = 62;
            else if (c == '/' || c == '_') v = 63;
            else return null;
            buf = (buf << 6) | v;
            bits += 6;
            count++;
            if (bits >= 8) {
                bits -= 8;
                out.write((buf >> bits) & 0xff);
            }
        }
        if (count % 4 == 1) return null;
        return out.toByteArray();
    }

    public static String encode(byte[] d) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < d.length; i += 3) {
            int n = (d[i] & 0xff) << 16;
            if (i + 1 < d.length) n |= (d[i + 1] & 0xff) << 8;
            if (i + 2 < d.length) n |= d[i + 2] & 0xff;
            sb.append(ABC[(n >> 18) & 63]).append(ABC[(n >> 12) & 63]);
            sb.append(i + 1 < d.length ? ABC[(n >> 6) & 63] : '=');
            sb.append(i + 2 < d.length ? ABC[n & 63] : '=');
        }
        return sb.toString();
    }
}
