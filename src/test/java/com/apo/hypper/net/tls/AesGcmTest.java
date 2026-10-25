package com.apo.hypper.net.tls;

import org.junit.Test;

import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import static org.junit.Assert.assertArrayEquals;

/** AesGcm должен давать ровно то же, что эталонный AES/GCM из JDK (так же открывает сервер REALITY). */
public class AesGcmTest {
    @Test
    public void matchesJdkGcm() throws Exception {
        Random rnd = new Random(42);
        int[] aadLens = {0, 1, 15, 16, 17, 200, 517};
        int[] ptLens = {0, 1, 16, 31, 64};
        for (int aadLen : aadLens) {
            for (int ptLen : ptLens) {
                byte[] key = new byte[32], nonce = new byte[12];
                byte[] aad = new byte[aadLen], pt = new byte[ptLen];
                rnd.nextBytes(key);
                rnd.nextBytes(nonce);
                rnd.nextBytes(aad);
                rnd.nextBytes(pt);

                Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
                c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
                c.updateAAD(aad);
                byte[] expected = c.doFinal(pt);

                assertArrayEquals("aad=" + aadLen + " pt=" + ptLen,
                        expected, new AesGcm(key).seal(nonce, aad, pt, 0, ptLen));
            }
        }
    }
}
