package com.apo.hypper.net.tls;

import com.apo.hypper.Profile;
import com.apo.hypper.net.wg.B64;

import java.io.IOException;

/**
 * Параметры REALITY (XTLS): публичный ключ сервера и короткий идентификатор.
 * REALITY маскирует соединение под обычный TLS 1.3 к стороннему сайту (sni),
 * пряча аутентификационные данные в поле legacy_session_id ClientHello.
 */
public final class Reality {
    /** Публичный ключ сервера X25519, 32 байта. */
    public final byte[] publicKey;
    /** Короткий идентификатор, 0..8 байт. */
    public final byte[] shortId;

    public Reality(byte[] publicKey, byte[] shortId) {
        this.publicKey = publicKey;
        this.shortId = shortId;
    }

    public static Reality fromProfile(Profile p) throws IOException {
        byte[] pk = B64.decode(p.publicKey);
        if (pk == null || pk.length != 32)
            throw new IOException("REALITY: неверный публичный ключ (pbk)");
        byte[] sid = hex(p.shortId);
        if (sid.length > 8) throw new IOException("REALITY: sid длиннее 8 байт");
        return new Reality(pk, sid);
    }

    private static byte[] hex(String s) throws IOException {
        s = s.trim();
        if ((s.length() & 1) != 0) throw new IOException("REALITY: sid должен быть hex чётной длины");
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(s.charAt(2 * i), 16);
            int lo = Character.digit(s.charAt(2 * i + 1), 16);
            if (hi < 0 || lo < 0) throw new IOException("REALITY: sid содержит не-hex символы");
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }
}
