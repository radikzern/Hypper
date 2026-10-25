package com.apo.hypper.net.tls;

import com.apo.hypper.net.wg.ChaChaPoly;
import com.apo.hypper.net.wg.X25519;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Минимальный клиент TLS 1.3 (RFC 8446): x25519 + TLS_CHACHA20_POLY1305_SHA256.
 * Нужен, потому что OpenSSL в Android 4.x не умеет ни TLS 1.3, ни AEAD-шифров,
 * а современные серверы ничего другого не принимают.
 */
public class Tls13 {
    private static final Charset ASCII = Charset.forName("US-ASCII");
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int CHACHA = 0x1303;
    private static final int GROUP_X25519 = 0x001d;
    /** Гибрид ML-KEM-768 + X25519 (draft-ietf-tls-ecdhe-mlkem). */
    private static final int GROUP_HYBRID = 0x11ec;
    private static final byte[] HRR_RANDOM = hex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c");

    private final Socket socket;
    private final DataInputStream rin;
    private final OutputStream rout;
    private final ByteArrayOutputStream transcript = new ByteArrayOutputStream();
    private final ByteArrayOutputStream hsBuf = new ByteArrayOutputStream();

    private ChaChaPoly readCipher, writeCipher;
    private byte[] readIv, writeIv;
    private long readSeq, writeSeq;
    private byte[] serverAppSecret, clientAppSecret;
    private final Object writeLock = new Object();

    private Reality reality;
    private byte[] authKey;
    private boolean realityVerified;
    // Версия клиента в session_id REALITY. Сервер может отсечь клиента по minClientVer,
    // поэтому держим её равной актуальному релизу Xray.
    private static final byte VERSION_X = 26, VERSION_Y = 3, VERSION_Z = 27;

    private Tls13(Socket socket) throws IOException {
        this.socket = socket;
        this.rin = new DataInputStream(new BufferedInputStream(socket.getInputStream(), 16384 + 512));
        this.rout = socket.getOutputStream();
    }

    /** Рукопожатие поверх уже подключённого сокета. */
    public static Tls13 connect(Socket socket, String sni, String[] alpn, boolean insecure) throws IOException {
        Tls13 t = new Tls13(socket);
        t.handshake(sni, alpn, insecure, null);
        return t;
    }

    /** Рукопожатие REALITY: проверка сервера идёт по общему ключу, системная цепочка не нужна. */
    public static Tls13 connect(Socket socket, String sni, String[] alpn, Reality reality) throws IOException {
        Tls13 t = new Tls13(socket);
        t.reality = reality;
        t.handshake(sni, alpn, true, reality);
        return t;
    }

    public Socket socket() {
        return socket;
    }

    // ---------------------------------------------------------------- рукопожатие

    private void handshake(String sni, String[] alpn, boolean insecure, Reality reality) throws IOException {
        byte[] priv = X25519.generatePrivate();
        byte[] pub = X25519.publicKey(priv);
        byte[] clientRandom = random(32);
        byte[] sessionId = random(32);
        if (reality != null) Arrays.fill(sessionId, (byte) 0); // плейсхолдер: AEAD-пломба заполнит его
        // Свежие серверы REALITY без X25519MLKEM768 в key_share клиента не пускают
        MlKem768.KeyPair pq = reality != null ? MlKem768.generate(RANDOM) : null;
        byte[] hello = clientHello(sni, alpn, pub, pq == null ? null : pq.ek, clientRandom, sessionId, reality != null);
        if (reality != null) authKey = sealReality(hello, priv, clientRandom, reality);
        writeRecord(22, 0x0301, hello, 0, hello.length);
        transcript.write(hello);

        byte[] sh = nextHandshake();
        if (sh[0] != 2) throw new IOException("TLS: ожидался ServerHello");
        byte[] serverKey = parseServerHello(sh);
        transcript.write(sh);

        byte[] shared;
        if (serverKey.length == 32) {
            shared = X25519.scalarMult(priv, serverKey);
        } else if (pq != null && serverKey.length == MlKem768.CT_SIZE + 32) {
            // общий секрет гибрида: ML-KEM ‖ X25519
            byte[] ss = MlKem768.decaps(pq.dk, Arrays.copyOf(serverKey, MlKem768.CT_SIZE));
            byte[] ecdh = X25519.scalarMult(priv, Arrays.copyOfRange(serverKey, MlKem768.CT_SIZE, serverKey.length));
            shared = Arrays.copyOf(ss, 64);
            System.arraycopy(ecdh, 0, shared, 32, 32);
        } else {
            throw new IOException("TLS: неверный key_share сервера");
        }
        byte[] zeros = new byte[32];
        byte[] early = extract(zeros, zeros);
        byte[] hs = extract(deriveSecret(early, "derived", sha256(new byte[0])), shared);
        byte[] thash = sha256(transcript.toByteArray());
        byte[] cHs = deriveSecret(hs, "c hs traffic", thash);
        byte[] sHs = deriveSecret(hs, "s hs traffic", thash);
        setRead(sHs);

        List<X509Certificate> chain = new ArrayList<X509Certificate>();
        boolean verified = false;
        while (true) {
            byte[] m = nextHandshake();
            int type = m[0] & 0xff;
            if (type == 8) { // EncryptedExtensions
                transcript.write(m);
            } else if (type == 13) {
                throw new IOException("TLS: сервер требует клиентский сертификат");
            } else if (type == 11) {
                if (reality != null) realityVerify(m);
                else parseCertificates(m, chain);
                transcript.write(m);
            } else if (type == 15) {
                if (!insecure) {
                    if (chain.isEmpty()) throw new IOException("TLS: сервер не прислал сертификат");
                    verifySignature(m, chain.get(0), sha256(transcript.toByteArray()));
                    Trust.checkChain(chain.toArray(new X509Certificate[0]));
                    if (!Trust.matchesHost(chain.get(0), sni))
                        throw new IOException("Сертификат не соответствует имени " + sni);
                    verified = true;
                }
                transcript.write(m);
            } else if (type == 20) {
                byte[] expected = hmac(expandLabel(sHs, "finished", new byte[0], 32), sha256(transcript.toByteArray()));
                byte[] got = Arrays.copyOfRange(m, 4, m.length);
                if (!MessageDigest.isEqual(expected, got)) throw new IOException("TLS: неверный Finished сервера");
                transcript.write(m);
                break;
            } else {
                throw new IOException("TLS: неожиданное сообщение " + type);
            }
        }
        if (!insecure && !verified) throw new IOException("TLS: сервер не подтвердил ключ");
        if (reality != null && !realityVerified) throw new IOException("REALITY: сервер не прислал сертификат");

        byte[] thFin = sha256(transcript.toByteArray());
        byte[] master = extract(deriveSecret(hs, "derived", sha256(new byte[0])), zeros);
        clientAppSecret = deriveSecret(master, "c ap traffic", thFin);
        serverAppSecret = deriveSecret(master, "s ap traffic", thFin);

        // совместимость с middlebox: фиктивный ChangeCipherSpec, затем наш Finished
        writeRecord(20, 0x0303, new byte[]{1}, 0, 1);
        setWrite(cHs);
        byte[] verify = hmac(expandLabel(cHs, "finished", new byte[0], 32), thFin);
        byte[] fin = new byte[4 + verify.length];
        fin[0] = 20;
        fin[3] = (byte) verify.length;
        System.arraycopy(verify, 0, fin, 4, verify.length);
        writeEncrypted(22, fin, 0, fin.length);

        setRead(serverAppSecret);
        setWrite(clientAppSecret);
        rout.flush();
    }

    private static byte[] clientHello(String sni, String[] alpn, byte[] keyShare, byte[] pqKey,
                                      byte[] clientRandom, byte[] sessionId, boolean ed25519) {
        Buf ext = new Buf();
        if (sni != null && sni.length() > 0 && !isIp(sni)) {
            byte[] name = sni.getBytes(ASCII);
            ext.u16(0).u16(name.length + 5).u16(name.length + 3).u8(0).u16(name.length).put(name);
        }
        if (pqKey != null) ext.u16(10).u16(6).u16(4).u16(GROUP_HYBRID).u16(GROUP_X25519);
        else ext.u16(10).u16(4).u16(2).u16(GROUP_X25519);
        // REALITY-сервер подписывает CertificateVerify ключом ed25519 — заявляем его поддержку,
        // иначе сервер оборвёт рукопожатие (саму подпись мы не проверяем, см. realityVerify).
        int[] sigs = ed25519
                ? new int[]{0x0807, 0x0403, 0x0503, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601}
                : new int[]{0x0403, 0x0503, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601};
        ext.u16(13).u16(2 + sigs.length * 2).u16(sigs.length * 2);
        for (int s : sigs) ext.u16(s);
        ext.u16(43).u16(3).u8(2).u16(0x0304);
        if (pqKey != null) {
            // гибридная доля обязана идти раньше x25519 — так её ищет сервер REALITY
            int pqLen = pqKey.length + keyShare.length;
            int shares = (4 + pqLen) + (4 + 32);
            ext.u16(51).u16(shares + 2).u16(shares);
            ext.u16(GROUP_HYBRID).u16(pqLen).put(pqKey).put(keyShare);
            ext.u16(GROUP_X25519).u16(32).put(keyShare);
        } else {
            ext.u16(51).u16(38).u16(36).u16(GROUP_X25519).u16(32).put(keyShare);
        }
        ext.u16(45).u16(2).u8(1).u8(1); // psk_key_exchange_modes: psk_dhe_ke
        if (alpn != null && alpn.length > 0) {
            Buf list = new Buf();
            for (String a : alpn) {
                byte[] b = a.getBytes(ASCII);
                list.u8(b.length).put(b);
            }
            byte[] l = list.bytes();
            ext.u16(16).u16(l.length + 2).u16(l.length).put(l);
        }
        byte[] exts = ext.bytes();

        Buf body = new Buf();
        body.u16(0x0303).put(clientRandom);
        body.u8(sessionId.length).put(sessionId); // legacy_session_id (у REALITY — пломба)
        body.u16(2).u16(CHACHA);
        body.u8(1).u8(0);
        body.u16(exts.length).put(exts);
        byte[] b = body.bytes();

        Buf msg = new Buf();
        msg.u8(1).u24(b.length).put(b);
        return msg.bytes();
    }

    // ---------------------------------------------------------------- REALITY

    /**
     * Пломбирует session_id: сервер, зная свой приватный ключ, повторит authKey и расшифрует её.
     * Меняет hello на месте (байты 39..70) и возвращает authKey для проверки сертификата.
     * Совместимо с Xray: HKDF-SHA256(общий секрет, salt=random[:20], info="REALITY"),
     * AES-256-GCM над session_id[:16], nonce=random[20:32], AAD=ClientHello с обнулённым session_id.
     */
    private static byte[] sealReality(byte[] hello, byte[] priv, byte[] clientRandom, Reality r) {
        byte[] shared = X25519.scalarMult(priv, r.publicKey);
        byte[] prk = hmac(Arrays.copyOf(clientRandom, 20), shared); // HKDF-Extract
        byte[] info = "REALITY".getBytes(ASCII);
        byte[] expandIn = Arrays.copyOf(info, info.length + 1);
        expandIn[info.length] = 1;
        byte[] authKey = hmac(prk, expandIn); // HKDF-Expand, один блок = 32 байта

        byte[] plain = new byte[16];
        plain[0] = VERSION_X;
        plain[1] = VERSION_Y;
        plain[2] = VERSION_Z; // plain[3] — зарезервировано, 0
        long t = System.currentTimeMillis() / 1000L;
        plain[4] = (byte) (t >>> 24);
        plain[5] = (byte) (t >>> 16);
        plain[6] = (byte) (t >>> 8);
        plain[7] = (byte) t;
        System.arraycopy(r.shortId, 0, plain, 8, Math.min(8, r.shortId.length));

        byte[] nonce = Arrays.copyOfRange(clientRandom, 20, 32);
        // сервер (xtls/reality) открывает пломбу только AES-256-GCM
        byte[] sealed = new AesGcm(authKey).seal(nonce, hello, plain, 0, 16); // 16 + тег 16
        System.arraycopy(sealed, 0, hello, 39, 32);
        return authKey;
    }

    /** Сервер REALITY «подписывает» эфемерный ed25519-сертификат как HMAC-SHA512(authKey, pubkey). */
    private void realityVerify(byte[] certMsg) throws IOException {
        byte[] der = firstCertDer(certMsg);
        byte[] pub = ed25519PublicKey(der);
        byte[] sig = certSignature(der);
        if (!MessageDigest.isEqual(hmacSha512(authKey, pub), sig))
            throw new IOException("REALITY: сервер не распознал клиента (неверная подпись сертификата)");
        realityVerified = true;
    }

    private static byte[] firstCertDer(byte[] m) throws IOException {
        int p = 4;
        p += 1 + (m[p] & 0xff); // request_context
        p += 3;                 // длина certificate_list (u24)
        int cl = u24(m, p);
        p += 3;
        if (cl <= 0 || p + cl > m.length) throw new IOException("REALITY: пустой сертификат");
        return Arrays.copyOfRange(m, p, p + cl);
    }

    // SubjectPublicKeyInfo для ed25519: SEQUENCE { SEQUENCE { OID 1.3.101.112 } BIT STRING(33) 00 ... }
    private static final byte[] ED25519_SPKI =
            {0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00};

    private static byte[] ed25519PublicKey(byte[] der) throws IOException {
        int i = indexOf(der, ED25519_SPKI);
        int off = i + ED25519_SPKI.length;
        if (i < 0 || off + 32 > der.length) throw new IOException("REALITY: сертификат не ed25519");
        return Arrays.copyOfRange(der, off, off + 32);
    }

    /** signatureValue — последняя BIT STRING внешней SEQUENCE сертификата (без байта unused-bits). */
    private static byte[] certSignature(byte[] der) throws IOException {
        int[] pos = {0};
        tlv(der, pos, 0x30);                                 // Certificate SEQUENCE
        int tbsLen = tlv(der, pos, 0x30);
        pos[0] += tbsLen;                                    // пропускаем tbsCertificate
        int algLen = tlv(der, pos, 0x30);
        pos[0] += algLen;                                    // пропускаем signatureAlgorithm
        int sigLen = tlv(der, pos, 0x03);                    // signatureValue BIT STRING
        if (sigLen < 1 || pos[0] + sigLen > der.length) throw new IOException("REALITY: неверная подпись");
        return Arrays.copyOfRange(der, pos[0] + 1, pos[0] + sigLen);
    }

    /** Читает тег и длину DER TLV в pos[0], возвращает длину содержимого; pos[0] → начало содержимого. */
    private static int tlv(byte[] b, int[] pos, int tag) throws IOException {
        int p = pos[0];
        if (p + 2 > b.length || (b[p++] & 0xff) != tag) throw new IOException("REALITY: неверный DER");
        int len = b[p++] & 0xff;
        if (len >= 0x80) {
            int n = len & 0x7f;
            if (n > 4 || p + n > b.length) throw new IOException("REALITY: неверная длина DER");
            len = 0;
            for (int i = 0; i < n; i++) len = (len << 8) | (b[p++] & 0xff);
        }
        pos[0] = p;
        return len;
    }

    private static int indexOf(byte[] hay, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= hay.length; i++) {
            for (int j = 0; j < needle.length; j++) if (hay[i + j] != needle[j]) continue outer;
            return i;
        }
        return -1;
    }

    private static byte[] hmacSha512(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA512");
            mac.init(new SecretKeySpec(key, "HmacSHA512"));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] parseServerHello(byte[] m) throws IOException {
        DataInputStream d = new DataInputStream(new ByteArrayInputStream(m, 4, m.length - 4));
        d.readUnsignedShort();
        byte[] random = new byte[32];
        d.readFully(random);
        if (Arrays.equals(random, HRR_RANDOM))
            throw new IOException("TLS: сервер не поддерживает x25519");
        d.skipBytes(d.readUnsignedByte());
        int cipher = d.readUnsignedShort();
        d.readUnsignedByte();
        if (cipher != CHACHA) throw new IOException("TLS: сервер выбрал шифр 0x" + Integer.toHexString(cipher));
        int extLen = d.readUnsignedShort();
        byte[] key = null;
        boolean tls13 = false;
        while (extLen > 0) {
            int type = d.readUnsignedShort();
            int len = d.readUnsignedShort();
            byte[] data = new byte[len];
            d.readFully(data);
            extLen -= 4 + len;
            if (type == 43 && len == 2 && ((data[0] & 0xff) << 8 | (data[1] & 0xff)) == 0x0304) tls13 = true;
            if (type == 51 && len >= 4) {
                int group = (data[0] & 0xff) << 8 | (data[1] & 0xff);
                int kl = (data[2] & 0xff) << 8 | (data[3] & 0xff);
                boolean ok = group == GROUP_X25519 && kl == 32
                        || group == GROUP_HYBRID && kl == MlKem768.CT_SIZE + 32;
                if (!ok || 4 + kl > len) throw new IOException("TLS: неподдерживаемая группа ключей 0x" + Integer.toHexString(group));
                key = Arrays.copyOfRange(data, 4, 4 + kl);
            }
        }
        if (!tls13) throw new IOException("TLS: сервер не поддерживает TLS 1.3");
        if (key == null) throw new IOException("TLS: нет key_share");
        return key;
    }

    private static void parseCertificates(byte[] m, List<X509Certificate> out) throws IOException {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            int p = 4;
            p += 1 + (m[p] & 0xff); // request_context
            int listEnd = p + 3 + u24(m, p);
            p += 3;
            while (p < listEnd) {
                int cl = u24(m, p);
                p += 3;
                out.add((X509Certificate) cf.generateCertificate(new ByteArrayInputStream(m, p, cl)));
                p += cl;
                p += 2 + ((m[p] & 0xff) << 8 | (m[p + 1] & 0xff));
            }
        } catch (java.security.cert.CertificateException e) {
            throw new IOException("TLS: не удалось разобрать сертификат: " + e.getMessage());
        }
    }

    private static void verifySignature(byte[] m, X509Certificate cert, byte[] thash) throws IOException {
        int alg = (m[4] & 0xff) << 8 | (m[5] & 0xff);
        int len = (m[6] & 0xff) << 8 | (m[7] & 0xff);
        byte[] sig = Arrays.copyOfRange(m, 8, 8 + len);
        ByteArrayOutputStream content = new ByteArrayOutputStream();
        for (int i = 0; i < 64; i++) content.write(0x20);
        byte[] label = "TLS 1.3, server CertificateVerify".getBytes(ASCII);
        content.write(label, 0, label.length);
        content.write(0);
        content.write(thash, 0, thash.length);
        byte[] data = content.toByteArray();
        PublicKey key = cert.getPublicKey();
        boolean ok;
        try {
            if (alg == 0x0403 || alg == 0x0503) {
                Signature s = Signature.getInstance(alg == 0x0403 ? "SHA256withECDSA" : "SHA384withECDSA");
                s.initVerify(key);
                s.update(data);
                ok = s.verify(sig);
            } else if (alg >= 0x0804 && alg <= 0x0806 && key instanceof RSAPublicKey) {
                String h = alg == 0x0804 ? "SHA-256" : alg == 0x0805 ? "SHA-384" : "SHA-512";
                ok = verifyPss((RSAPublicKey) key, sig, data, h);
            } else {
                throw new IOException("TLS: неподдерживаемая подпись 0x" + Integer.toHexString(alg));
            }
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("TLS: проверка подписи: " + e);
        }
        if (!ok) throw new IOException("TLS: неверная подпись сервера");
    }

    /** RSASSA-PSS (RFC 8017) с MGF1 и длиной соли = длине хэша; на Android 4 его нет в провайдерах. */
    static boolean verifyPss(RSAPublicKey key, byte[] sig, byte[] msg, String hashAlg) throws Exception {
        MessageDigest md = MessageDigest.getInstance(hashAlg);
        int hLen = md.getDigestLength();
        BigInteger n = key.getModulus();
        int emBits = n.bitLength() - 1;
        int emLen = (emBits + 7) / 8;
        BigInteger mInt = new BigInteger(1, sig).modPow(key.getPublicExponent(), n);
        byte[] raw = mInt.toByteArray();
        byte[] em = new byte[emLen];
        int copy = Math.min(raw.length, emLen);
        System.arraycopy(raw, raw.length - copy, em, emLen - copy, copy);
        if ((em[emLen - 1] & 0xff) != 0xbc) return false;
        int dbLen = emLen - hLen - 1;
        byte[] h = Arrays.copyOfRange(em, dbLen, dbLen + hLen);
        int topBits = 8 * emLen - emBits;
        if ((em[0] & (0xff << (8 - topBits)) & 0xff) != 0) return false;
        byte[] mask = mgf1(h, dbLen, md);
        byte[] db = new byte[dbLen];
        for (int i = 0; i < dbLen; i++) db[i] = (byte) (em[i] ^ mask[i]);
        db[0] &= (byte) (0xff >>> topBits);
        int sLen = hLen;
        int psEnd = dbLen - sLen - 1;
        if (psEnd < 0) return false;
        for (int i = 0; i < psEnd; i++) if (db[i] != 0) return false;
        if (db[psEnd] != 1) return false;
        byte[] salt = Arrays.copyOfRange(db, dbLen - sLen, dbLen);
        byte[] mHash = MessageDigest.getInstance(hashAlg).digest(msg);
        md.reset();
        md.update(new byte[8]);
        md.update(mHash);
        md.update(salt);
        return MessageDigest.isEqual(md.digest(), h);
    }

    private static byte[] mgf1(byte[] seed, int len, MessageDigest md) {
        byte[] out = new byte[len];
        int off = 0;
        for (int c = 0; off < len; c++) {
            md.reset();
            md.update(seed);
            md.update(new byte[]{(byte) (c >>> 24), (byte) (c >>> 16), (byte) (c >>> 8), (byte) c});
            byte[] d = md.digest();
            int n = Math.min(d.length, len - off);
            System.arraycopy(d, 0, out, off, n);
            off += n;
        }
        return out;
    }

    // ---------------------------------------------------------------- ключи

    private static byte[] hmac(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] extract(byte[] salt, byte[] ikm) {
        return hmac(salt, ikm);
    }

    static byte[] expandLabel(byte[] secret, String label, byte[] ctx, int len) {
        byte[] l = ("tls13 " + label).getBytes(ASCII);
        Buf info = new Buf();
        info.u16(len).u8(l.length).put(l).u8(ctx.length).put(ctx);
        byte[] inf = info.bytes();
        byte[] out = new byte[len];
        byte[] prev = new byte[0];
        int off = 0;
        for (int i = 1; off < len; i++) {
            byte[] in = new byte[prev.length + inf.length + 1];
            System.arraycopy(prev, 0, in, 0, prev.length);
            System.arraycopy(inf, 0, in, prev.length, inf.length);
            in[in.length - 1] = (byte) i;
            prev = hmac(secret, in);
            int n = Math.min(prev.length, len - off);
            System.arraycopy(prev, 0, out, off, n);
            off += n;
        }
        return out;
    }

    private static byte[] deriveSecret(byte[] secret, String label, byte[] thash) {
        return expandLabel(secret, label, thash, 32);
    }

    private void setRead(byte[] secret) {
        readCipher = new ChaChaPoly(expandLabel(secret, "key", new byte[0], 32));
        readIv = expandLabel(secret, "iv", new byte[0], 12);
        readSeq = 0;
    }

    private void setWrite(byte[] secret) {
        writeCipher = new ChaChaPoly(expandLabel(secret, "key", new byte[0], 32));
        writeIv = expandLabel(secret, "iv", new byte[0], 12);
        writeSeq = 0;
    }

    private static byte[] nonce(byte[] iv, long seq) {
        byte[] n = iv.clone();
        for (int i = 0; i < 8; i++) n[11 - i] ^= (byte) (seq >>> (8 * i));
        return n;
    }

    // ---------------------------------------------------------------- записи

    private void writeRecord(int type, int version, byte[] b, int off, int len) throws IOException {
        byte[] r = new byte[5 + len];
        r[0] = (byte) type;
        r[1] = (byte) (version >> 8);
        r[2] = (byte) version;
        r[3] = (byte) (len >> 8);
        r[4] = (byte) len;
        System.arraycopy(b, off, r, 5, len);
        rout.write(r);
    }

    private void writeEncrypted(int type, byte[] b, int off, int len) throws IOException {
        synchronized (writeLock) {
            while (len > 0 || type != 23) {
                int n = Math.min(len, 16384);
                byte[] inner = new byte[n + 1];
                System.arraycopy(b, off, inner, 0, n);
                inner[n] = (byte) type;
                int ctLen = inner.length + 16;
                byte[] header = {23, 3, 3, (byte) (ctLen >> 8), (byte) ctLen};
                byte[] ct = writeCipher.sealNonce(nonce(writeIv, writeSeq++), header, inner, 0, inner.length);
                byte[] rec = new byte[5 + ct.length];
                System.arraycopy(header, 0, rec, 0, 5);
                System.arraycopy(ct, 0, rec, 5, ct.length);
                rout.write(rec);
                off += n;
                len -= n;
                if (type != 23) break;
            }
        }
    }

    /** Следующая запись после расшифровки: {тип, данные}. */
    private Object[] readRecord() throws IOException {
        while (true) {
            int type;
            try {
                type = rin.readUnsignedByte();
            } catch (EOFException e) {
                return null;
            }
            rin.readUnsignedShort();
            int len = rin.readUnsignedShort();
            if (len > 16384 + 256) throw new IOException("TLS: слишком длинная запись");
            byte[] body = new byte[len];
            rin.readFully(body);
            if (type == 20) continue; // ChangeCipherSpec — игнорируем
            if (readCipher == null || type != 23) {
                if (type == 21) throw alert(body);
                return new Object[]{type, body};
            }
            byte[] header = {23, 3, 3, (byte) (len >> 8), (byte) len};
            byte[] plain = readCipher.openNonce(nonce(readIv, readSeq++), header, body, 0, len);
            if (plain == null) throw new IOException("TLS: ошибка расшифровки");
            int end = plain.length - 1;
            while (end >= 0 && plain[end] == 0) end--;
            if (end < 0) throw new IOException("TLS: пустая запись");
            int inner = plain[end] & 0xff;
            byte[] data = Arrays.copyOf(plain, end);
            if (inner == 21) {
                if (data.length >= 2 && data[1] == 0) return null; // close_notify
                throw alert(data);
            }
            return new Object[]{inner, data};
        }
    }

    private static IOException alert(byte[] b) {
        int code = b.length >= 2 ? b[1] & 0xff : -1;
        String name = code == 40 ? "handshake_failure" : code == 42 ? "bad_certificate" : code == 70 ? "protocol_version"
                : code == 71 ? "insufficient_security" : code == 112 ? "unrecognized_name" : String.valueOf(code);
        return new IOException("TLS: сервер ответил alert " + name);
    }

    private byte[] nextHandshake() throws IOException {
        while (true) {
            byte[] buf = hsBuf.toByteArray();
            if (buf.length >= 4) {
                int len = u24(buf, 1);
                if (buf.length >= 4 + len) {
                    byte[] msg = Arrays.copyOf(buf, 4 + len);
                    hsBuf.reset();
                    hsBuf.write(buf, 4 + len, buf.length - 4 - len);
                    return msg;
                }
            }
            Object[] r = readRecord();
            if (r == null) throw new EOFException("TLS: сервер закрыл соединение");
            if ((Integer) r[0] != 22) throw new IOException("TLS: неожиданная запись типа " + r[0]);
            byte[] d = (byte[]) r[1];
            hsBuf.write(d, 0, d.length);
        }
    }

    // ---------------------------------------------------------------- потоки приложения

    private byte[] appBuf = new byte[0];
    private int appPos;
    private boolean eof;

    private boolean fill() throws IOException {
        while (appPos >= appBuf.length) {
            if (eof) return false;
            Object[] r = readRecord();
            if (r == null) {
                eof = true;
                return false;
            }
            int type = (Integer) r[0];
            byte[] d = (byte[]) r[1];
            if (type == 23) {
                appBuf = d;
                appPos = 0;
            } else if (type == 22) {
                postHandshake(d);
            }
        }
        return true;
    }

    private void postHandshake(byte[] d) throws IOException {
        int p = 0;
        while (p + 4 <= d.length) {
            int type = d[p] & 0xff;
            int len = u24(d, p + 1);
            if (type == 24 && len >= 1) { // KeyUpdate
                boolean requested = d[p + 4] == 1;
                serverAppSecret = expandLabel(serverAppSecret, "traffic upd", new byte[0], 32);
                setRead(serverAppSecret);
                if (requested) {
                    synchronized (writeLock) {
                        writeEncrypted(22, new byte[]{24, 0, 0, 1, 0}, 0, 5);
                        clientAppSecret = expandLabel(clientAppSecret, "traffic upd", new byte[0], 32);
                        setWrite(clientAppSecret);
                    }
                }
            }
            // NewSessionTicket (4) и прочее — не нужно
            p += 4 + len;
        }
    }

    public InputStream getInputStream() {
        return new InputStream() {
            @Override
            public int read() throws IOException {
                if (!fill()) return -1;
                return appBuf[appPos++] & 0xff;
            }

            @Override
            public int read(byte[] b, int off, int len) throws IOException {
                if (len == 0) return 0;
                if (!fill()) return -1;
                int n = Math.min(len, appBuf.length - appPos);
                System.arraycopy(appBuf, appPos, b, off, n);
                appPos += n;
                return n;
            }

            @Override
            public int available() {
                return appBuf.length - appPos;
            }

            @Override
            public void close() throws IOException {
                socket.close();
            }
        };
    }

    public OutputStream getOutputStream() {
        return new OutputStream() {
            @Override
            public void write(int b) throws IOException {
                write(new byte[]{(byte) b}, 0, 1);
            }

            @Override
            public void write(byte[] b, int off, int len) throws IOException {
                if (len > 0) writeEncrypted(23, b, off, len);
            }

            @Override
            public void flush() throws IOException {
                rout.flush();
            }

            @Override
            public void close() throws IOException {
                socket.close();
            }
        };
    }

    // ---------------------------------------------------------------- утилиты

    private static byte[] sha256(byte[] d) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(d);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static int u24(byte[] b, int o) {
        return (b[o] & 0xff) << 16 | (b[o + 1] & 0xff) << 8 | (b[o + 2] & 0xff);
    }

    private static byte[] random(int n) {
        byte[] b = new byte[n];
        RANDOM.nextBytes(b);
        return b;
    }

    private static boolean isIp(String s) {
        return s.matches("[0-9.]+") || s.indexOf(':') >= 0;
    }

    static byte[] hex(String s) {
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) b[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        return b;
    }

    static final class Buf {
        private final ByteArrayOutputStream o = new ByteArrayOutputStream();

        Buf u8(int v) {
            o.write(v);
            return this;
        }

        Buf u16(int v) {
            o.write(v >> 8);
            o.write(v);
            return this;
        }

        Buf u24(int v) {
            o.write(v >> 16);
            o.write(v >> 8);
            o.write(v);
            return this;
        }

        Buf put(byte[] b) {
            o.write(b, 0, b.length);
            return this;
        }

        byte[] bytes() {
            return o.toByteArray();
        }
    }
}
