package com.apo.hypper.net.tls;

import com.apo.hypper.AppLog;
import com.apo.hypper.net.wg.B64;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * Хранилище доверия: системные корни + актуальный набор корней, вшитый в приложение.
 * На Android 4 нет, например, ISRG Root X1 (Let's Encrypt) — без этого половина серверов «невалидна».
 */
public final class Trust {
    private static X509TrustManager manager;
    private static SSLSocketFactory factory;

    private Trust() {
    }

    public static synchronized X509TrustManager manager() throws IOException {
        if (manager != null) return manager;
        try {
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, null);
            int n = 0;
            try {
                KeyStore sys = KeyStore.getInstance("AndroidCAStore");
                sys.load(null, null);
                for (Enumeration<String> e = sys.aliases(); e.hasMoreElements(); ) {
                    String a = e.nextElement();
                    java.security.cert.Certificate c = sys.getCertificate(a);
                    if (c != null) ks.setCertificateEntry("sys" + (n++), c);
                }
            } catch (Exception ignored) {
                // не Android (юнит-тесты) — только вшитые корни
            }
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            InputStream in = Trust.class.getResourceAsStream("roots.pem");
            if (in != null) {
                String pem = new String(readAll(in), "US-ASCII");
                int bundled = 0;
                for (String part : pem.split("-----BEGIN CERTIFICATE-----")) {
                    int end = part.indexOf("-----END CERTIFICATE-----");
                    if (end < 0) continue;
                    byte[] der = B64.decode(part.substring(0, end));
                    if (der == null) continue;
                    try {
                        ks.setCertificateEntry("app" + (bundled++), cf.generateCertificate(new ByteArrayInputStream(der)));
                    } catch (CertificateException ignored) {
                        // редкие алгоритмы, которые старый провайдер не разбирает
                    }
                }
                AppLog.d("Корневых сертификатов: системных " + n + ", встроенных " + bundled);
            }
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ks);
            for (TrustManager tm : tmf.getTrustManagers()) {
                if (tm instanceof X509TrustManager) {
                    manager = (X509TrustManager) tm;
                    return manager;
                }
            }
            throw new IOException("Нет X509TrustManager");
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("Хранилище сертификатов: " + e);
        }
    }

    /** Фабрика системного TLS с расширенным набором корней. */
    public static synchronized SSLSocketFactory systemFactory() throws IOException {
        if (factory != null) return factory;
        try {
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, new TrustManager[]{manager()}, null);
            factory = ctx.getSocketFactory();
            return factory;
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("SSLContext: " + e);
        }
    }

    public static void checkChain(X509Certificate[] chain) throws IOException {
        String auth = chain[0].getPublicKey().getAlgorithm().startsWith("EC") ? "ECDHE_ECDSA" : "ECDHE_RSA";
        try {
            manager().checkServerTrusted(chain, auth);
        } catch (CertificateException e) {
            throw new IOException("Сертификат не доверенный: " + e.getMessage());
        }
    }

    /** Проверка имени по SAN (и CN, если SAN нет), с поддержкой *.example.com. */
    public static boolean matchesHost(X509Certificate cert, String host) {
        String h = host.toLowerCase(Locale.US);
        boolean hadDns = false;
        try {
            Collection<List<?>> sans = cert.getSubjectAlternativeNames();
            if (sans != null) {
                for (List<?> san : sans) {
                    int type = (Integer) san.get(0);
                    String v = String.valueOf(san.get(1)).toLowerCase(Locale.US);
                    if (type == 2) {
                        hadDns = true;
                        if (match(v, h)) return true;
                    } else if (type == 7 && v.equals(h)) {
                        return true;
                    }
                }
            }
        } catch (Exception ignored) {
        }
        if (hadDns) return false;
        String dn = cert.getSubjectX500Principal().getName();
        for (String part : dn.split(",")) {
            String t = part.trim();
            if (t.regionMatches(true, 0, "CN=", 0, 3) && match(t.substring(3).toLowerCase(Locale.US), h)) return true;
        }
        return false;
    }

    private static boolean match(String pattern, String host) {
        if (pattern.equals(host)) return true;
        if (pattern.startsWith("*.")) {
            int dot = host.indexOf('.');
            return dot > 0 && host.substring(dot).equals(pattern.substring(1));
        }
        return false;
    }

    private static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[16384];
        int n;
        while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
        in.close();
        return out.toByteArray();
    }
}
