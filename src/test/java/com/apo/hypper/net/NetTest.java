package com.apo.hypper.net;

import com.apo.hypper.Profile;

import org.junit.Test;

import java.util.List;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class NetTest {
    @Test
    public void vlessHeaderDomain() {
        Profile p = Profile.parse("vless://00112233-4455-6677-8899-aabbccddeeff@h:1");
        byte[] h = new VlessClient(p, null, null).header(VlessClient.CMD_TCP, "ya.ru", null, 443);
        byte[] expected = {0, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88, (byte) 0x99,
                (byte) 0xaa, (byte) 0xbb, (byte) 0xcc, (byte) 0xdd, (byte) 0xee, (byte) 0xff,
                0, 1, 0x01, (byte) 0xbb, 2, 5, 'y', 'a', '.', 'r', 'u'};
        assertArrayEquals(expected, h);
    }

    @Test
    public void vlessHeaderVisionAddons() {
        Profile p = Profile.parse("vless://00112233-4455-6677-8899-aabbccddeeff@h:1");
        byte[] h = new VlessClient(p, null, null).header(VlessClient.CMD_TCP, "ya.ru", null, 443, true);
        // после UUID (байты 1..16) идёт длина addons = 18 и protobuf Addons{Flow="xtls-rprx-vision"}
        assertEquals(18, h[17] & 0xff);
        assertEquals(0x0a, h[18] & 0xff); // поле 1, string
        assertEquals(16, h[19] & 0xff);   // длина "xtls-rprx-vision"
        assertEquals("xtls-rprx-vision", new String(h, 20, 16));
        assertEquals(VlessClient.CMD_TCP, h[36]); // command сразу после addons
    }

    @Test
    public void vlessHeaderIp() {
        Profile p = Profile.parse("vless://00112233-4455-6677-8899-aabbccddeeff@h:1");
        byte[] h = new VlessClient(p, null, null).header(VlessClient.CMD_UDP, "8.8.8.8", null, 53);
        assertEquals(2, h[18]);
        assertEquals(1, h[21]);
        assertEquals(26, h.length);
    }

    @Test
    public void routesCoverPublicSpace() {
        List<int[]> r = TunStack.routesExcludingPrivate();
        long total = 0;
        for (int[] x : r) total += 1L << (32 - x[1]);
        long excluded = (1L << 24) * 3 + (1L << 22) + (1L << 16) * 2 + (1L << 20) + (1L << 29);
        assertEquals((1L << 32) - excluded, total);
    }

    @Test
    public void tcpChecksumValid() {
        byte[] p = Packets.tcp(0x0a000001, 0x0a000002, 1000, 80, 1, 2, Packets.ACK, 65535, 0, "hi".getBytes(), 0, 2);
        // повторный подсчёт по заполненному пакету должен давать 0
        long acc = 0;
        for (int i = 0; i < 20; i += 2) acc += ((p[i] & 0xff) << 8) | (p[i + 1] & 0xff);
        while ((acc >> 16) != 0) acc = (acc & 0xffff) + (acc >> 16);
        assertEquals(0xffff, acc);
    }

    @Test
    public void base64() {
        assertEquals("aGk=", WebSocket.base64("hi".getBytes()));
        assertEquals("aGVsbG8=", WebSocket.base64("hello".getBytes()));
    }
}
