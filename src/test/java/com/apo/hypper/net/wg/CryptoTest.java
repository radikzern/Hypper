package com.apo.hypper.net.wg;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

public class CryptoTest {
    static byte[] hex(String s) {
        s = s.replaceAll("[^0-9a-fA-F]", "");
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) b[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        return b;
    }

    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    @Test
    public void blake2s() {
        assertEquals("508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982",
                hex(Blake2s.hash("abc".getBytes())));
        assertEquals("69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9",
                hex(Blake2s.hash(new byte[0])));
    }

    @Test
    public void x25519Rfc7748() {
        byte[] alicePriv = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        byte[] bobPriv = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        assertEquals("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", hex(X25519.publicKey(alicePriv)));
        assertEquals("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
                hex(X25519.scalarMult(alicePriv, X25519.publicKey(bobPriv))));
    }

    @Test
    public void chachaPolyRfc8439() {
        byte[] key = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        byte[] aad = hex("50515253c0c1c2c3c4c5c6c7");
        byte[] plain = ("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, "
                + "sunscreen would be it.").getBytes();
        // nonce RFC: 07000000 4041424344454647 — у WireGuard первые 4 байта нулевые, поэтому
        // проверяем через свой nonce: шифруем-расшифровываем и сверяем Poly1305 отдельно
        byte[] ct = ChaChaPoly.seal(key, 0x4746454443424140L, aad, plain);
        assertEquals(plain.length + 16, ct.length);
        assertEquals(new String(plain), new String(ChaChaPoly.open(key, 0x4746454443424140L, aad, ct)));
        ct[3] ^= 1;
        assertNull(ChaChaPoly.open(key, 0x4746454443424140L, aad, ct));
    }

    @Test
    public void poly1305Rfc8439() {
        byte[] key = hex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
        ChaChaPoly.Poly1305 p = new ChaChaPoly.Poly1305(key);
        byte[] msg = "Cryptographic Forum Research Group".getBytes();
        p.update(msg, 0, msg.length);
        assertEquals("a8061dc1305136c6c22b8baf0c0127a9", hex(p.finish()));
    }

    @Test
    public void wireguardAeadVector() {
        // zx2c4 chacha20poly1305 test: пустой текст, нулевой ключ, nonce 0
        byte[] t = ChaChaPoly.seal(new byte[32], 0, null, new byte[0]);
        assertEquals("4eb972c9a8fb3a1b382bb4d36f5ffad1", hex(t));
    }
}
