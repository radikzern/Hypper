package com.apo.hypper;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class SubscriptionTest {
    private static final String A = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@nl.example.com:443?security=tls&type=ws#NL";
    private static final String B = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@de.example.com:443?security=tls#DE";

    @Test
    public void plainList() {
        SubscriptionUpdater.Parsed p = SubscriptionUpdater.parse(A + "\r\n" + B + "\nvmess://abc\n");
        assertEquals(2, p.profiles.size());
        assertEquals(1, p.skipped);
        assertEquals("DE", p.profiles.get(1).name);
    }

    @Test
    public void base64List() {
        String b64 = java.util.Base64.getEncoder().withoutPadding().encodeToString((A + "\n" + B).getBytes());
        assertEquals(2, SubscriptionUpdater.parse(b64.substring(0, 40) + "\n" + b64.substring(40)).profiles.size());
        String url = java.util.Base64.getUrlEncoder().encodeToString((A + "\n" + B).getBytes());
        assertEquals(2, SubscriptionUpdater.parse(url).profiles.size());
    }

    @Test
    public void userInfo() {
        Subscription s = new Subscription();
        SubscriptionUpdater.applyUserInfo(s, "upload=1024; download=2048; total=10737418240; expire=1800000000");
        assertEquals(2048, s.download);
        assertEquals(10737418240L, s.total);
        assertEquals(1800000000L, s.expire);
        assertEquals("Мой VPN", SubscriptionUpdater.decodeTitle("base64:0JzQvtC5IFZQTg=="));
    }
}
