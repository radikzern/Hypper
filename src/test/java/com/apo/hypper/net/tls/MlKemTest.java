package com.apo.hypper.net.tls;

import org.junit.Test;

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Random;

import java.lang.reflect.Method;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

/** Сверка Keccak и ML-KEM-768 с эталонными реализациями JDK. */
public class MlKemTest {
    @Test
    public void sha3MatchesJdk() throws Exception {
        Random rnd = new Random(1);
        for (int len : new int[]{0, 1, 71, 72, 73, 135, 136, 137, 300, 1184}) {
            byte[] b = new byte[len];
            rnd.nextBytes(b);
            assertArrayEquals(MessageDigest.getInstance("SHA3-256").digest(b), Keccak.sha3_256(b));
            assertArrayEquals(MessageDigest.getInstance("SHA3-512").digest(b), Keccak.sha3_512(b));
        }
    }

    /** Наши ключи → инкапсуляция в JDK → наша декапсуляция. */
    @Test
    public void ourDecapsOpensJdkEncaps() throws Exception {
        SecureRandom rnd = new SecureRandom();
        for (int i = 0; i < 5; i++) {
            MlKem768.KeyPair kp = MlKem768.generate(rnd);
            PublicKey pub = KeyFactory.getInstance("ML-KEM").generatePublic(new X509EncodedKeySpec(spki(kp.ek)));
            Object e = call(call(kem(), "newEncapsulator", PublicKey.class, pub), "encapsulate");
            byte[] ct = (byte[]) call(e, "encapsulation");
            byte[] key = ((java.security.Key) call(e, "key")).getEncoded();
            assertEquals(MlKem768.CT_SIZE, ct.length);
            assertArrayEquals(key, MlKem768.decaps(kp.dk, ct));
        }
    }

    /** Ключи JDK → наша инкапсуляция → декапсуляция в JDK. */
    @Test
    public void jdkDecapsOpensOurEncaps() throws Exception {
        SecureRandom rnd = new SecureRandom();
        for (int i = 0; i < 5; i++) {
            java.security.KeyPair kp = KeyPairGenerator.getInstance("ML-KEM-768").generateKeyPair();
            byte[] enc = kp.getPublic().getEncoded();
            byte[] ek = Arrays.copyOfRange(enc, enc.length - MlKem768.EK_SIZE, enc.length);
            byte[] m = new byte[32];
            rnd.nextBytes(m);
            byte[][] r = MlKem768.encaps(ek, m);
            Object dec = call(kem(), "newDecapsulator", java.security.PrivateKey.class, kp.getPrivate());
            byte[] theirs = ((java.security.Key) call(dec, "decapsulate", byte[].class, r[0])).getEncoded();
            assertArrayEquals(theirs, r[1]);
        }
    }

    @Test
    public void tamperedCiphertextIsRejectedImplicitly() {
        MlKem768.KeyPair kp = MlKem768.generate(new SecureRandom());
        byte[][] r = MlKem768.encaps(kp.ek, new byte[32]);
        r[0][5] ^= 1;
        assertFalse(Arrays.equals(r[1], MlKem768.decaps(kp.dk, r[0])));
    }

    // javax.crypto.KEM нет в android.jar, но он есть в JDK, на котором идут юнит-тесты
    private static Object kem() throws Exception {
        return Class.forName("javax.crypto.KEM").getMethod("getInstance", String.class).invoke(null, "ML-KEM");
    }

    private static Object call(Object o, String name) throws Exception {
        Method m = o.getClass().getMethod(name);
        m.setAccessible(true);
        return m.invoke(o);
    }

    private static Object call(Object o, String name, Class<?> t, Object arg) throws Exception {
        Method m = o.getClass().getMethod(name, t);
        m.setAccessible(true);
        return m.invoke(o, arg);
    }

    /** SubjectPublicKeyInfo для ML-KEM-768 (OID 2.16.840.1.101.3.4.4.2). */
    private static byte[] spki(byte[] ek) {
        byte[] head = {0x30, (byte) 0x82, 0x04, (byte) 0xb2,
                0x30, 0x0b, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x02,
                0x03, (byte) 0x82, 0x04, (byte) 0xa1, 0x00};
        byte[] out = Arrays.copyOf(head, head.length + ek.length);
        System.arraycopy(ek, 0, out, head.length, ek.length);
        return out;
    }
}
