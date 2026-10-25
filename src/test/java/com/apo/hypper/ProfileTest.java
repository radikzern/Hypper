package com.apo.hypper;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class ProfileTest {
    @Test
    public void parsesWsTlsLink() {
        Profile p = Profile.parse("vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443"
                + "?encryption=none&security=tls&sni=cdn.example.com&type=ws&host=cdn.example.com"
                + "&path=%2Fws%3Fed%3D2048&allowInsecure=1#%D0%9C%D0%BE%D0%B9%20%D1%81%D0%B5%D1%80%D0%B2%D0%B5%D1%80");
        assertEquals("example.com", p.address);
        assertEquals(443, p.port);
        assertEquals("tls", p.security);
        assertEquals("ws", p.network);
        assertEquals("/ws?ed=2048", p.path);
        assertEquals("cdn.example.com", p.sni);
        assertTrue(p.insecure);
        assertEquals("Мой сервер", p.name);
        assertNull(p.unsupportedReason());

        Profile q = Profile.parse(p.toUri());
        assertEquals(p.toUri(), q.toUri());
    }

    @Test
    public void parsesIpv6AndFlow() {
        // flow без TLS/REALITY не поддерживается
        Profile p = Profile.parse("vless://b831381d-6324-4d53-ad4f-8cda48b30811@[2001:db8::1]:8443?flow=xtls-rprx-vision");
        assertEquals("2001:db8::1", p.address);
        assertEquals(8443, p.port);
        assertEquals("tcp", p.network);
        assertTrue(p.unsupportedReason() != null);
    }

    @Test
    public void visionOverTlsIsSupported() {
        Profile p = Profile.parse("vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443"
                + "?security=tls&type=tcp&sni=example.com&flow=xtls-rprx-vision");
        assertEquals("xtls-rprx-vision", p.flow);
        assertNull(p.unsupportedReason());
        // flow сохраняется при экспорте и чтении обратно
        Profile q = Profile.parse(p.toUri());
        assertEquals("xtls-rprx-vision", q.flow);
        assertEquals(p.toUri(), q.toUri());
    }

    @Test
    public void visionOverWsIsUnsupported() {
        Profile p = Profile.parse("vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443"
                + "?security=tls&type=ws&sni=example.com&flow=xtls-rprx-vision");
        assertTrue(p.unsupportedReason() != null);
    }

    @Test
    public void unknownFlowIsUnsupported() {
        Profile p = Profile.parse("vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443"
                + "?security=reality&type=tcp&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&flow=xtls-rprx-direct");
        assertTrue(p.unsupportedReason() != null);
    }

    @Test
    public void parsesRealityLink() {
        String pbk = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 43 симв. base64url = 32 байта
        Profile p = Profile.parse("vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443"
                + "?encryption=none&security=reality&sni=www.microsoft.com&type=tcp"
                + "&pbk=" + pbk + "&sid=0123abcd&fp=chrome&spx=%2F#R");
        assertEquals("reality", p.security);
        assertEquals("www.microsoft.com", p.sni);
        assertEquals(pbk, p.publicKey);
        assertEquals("0123abcd", p.shortId);
        assertEquals("chrome", p.fingerprint);
        assertEquals("/", p.spiderX);
        assertNull(p.unsupportedReason());

        Profile q = Profile.parse(p.toUri());
        assertEquals(p.toUri(), q.toUri());
        assertEquals(pbk, q.publicKey);
        assertEquals("0123abcd", q.shortId);
    }

    @Test(expected = IllegalArgumentException.class)
    public void rejectsRealityWithBadPbk() {
        Profile.parse("vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443"
                + "?security=reality&pbk=tooshort&type=tcp");
    }

    @Test(expected = IllegalArgumentException.class)
    public void rejectsBadUuid() {
        Profile.parse("vless://not-a-uuid@host:443");
    }
}
