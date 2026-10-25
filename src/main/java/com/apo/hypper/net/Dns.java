package com.apo.hypper.net;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Random;

/**
 * Резолвинг адреса сервера в обход VPN: при работающем туннеле системный DNS
 * пошёл бы через текущий сервер, а он может быть уже недоступен.
 */
public final class Dns {
    public interface DatagramProtector {
        boolean protect(DatagramSocket s);
    }

    private Dns() {
    }

    public static InetAddress resolve(String host, String dnsServer, DatagramProtector protector)
            throws UnknownHostException {
        if (VlessClient.parseIpv4(host) != null || host.indexOf(':') >= 0 || protector == null) {
            return InetAddress.getByName(host);
        }
        try {
            byte[] ip = queryA(host, InetAddress.getByName(dnsServer), protector);
            if (ip != null) return InetAddress.getByAddress(host, ip);
        } catch (IOException ignored) {
        }
        return InetAddress.getByName(host);
    }

    static byte[] queryA(String host, InetAddress dns, DatagramProtector protector) throws IOException {
        DatagramSocket s = new DatagramSocket();
        try {
            if (!protector.protect(s)) return null;
            s.setSoTimeout(3000);
            byte[] q = buildQuery(host, new Random().nextInt(0xffff));
            for (int attempt = 0; attempt < 2; attempt++) {
                s.send(new DatagramPacket(q, q.length, dns, 53));
                byte[] buf = new byte[1500];
                DatagramPacket resp = new DatagramPacket(buf, buf.length);
                try {
                    s.receive(resp);
                } catch (java.net.SocketTimeoutException e) {
                    continue;
                }
                return parseA(buf, resp.getLength(), q[0], q[1]);
            }
            return null;
        } finally {
            s.close();
        }
    }

    static byte[] buildQuery(String host, int id) {
        byte[] name = host.getBytes(VlessClient.UTF8);
        byte[] q = new byte[12 + name.length + 2 + 4];
        q[0] = (byte) (id >> 8);
        q[1] = (byte) id;
        q[2] = 0x01; // RD
        q[5] = 1; // QDCOUNT
        int p = 12;
        for (String label : host.split("\\.")) {
            byte[] l = label.getBytes(VlessClient.UTF8);
            q[p++] = (byte) l.length;
            System.arraycopy(l, 0, q, p, l.length);
            p += l.length;
        }
        q[p++] = 0;
        q[p++] = 0;
        q[p++] = 1; // A
        q[p++] = 0;
        q[p] = 1; // IN
        return q;
    }

    static byte[] parseA(byte[] b, int len, byte id0, byte id1) {
        if (len < 12 || b[0] != id0 || b[1] != id1) return null;
        if ((b[3] & 0x0f) != 0) return null; // RCODE
        int qd = Packets.u16(b, 4), an = Packets.u16(b, 6);
        int p = 12;
        for (int i = 0; i < qd; i++) {
            p = skipName(b, p, len);
            p += 4;
        }
        for (int i = 0; i < an && p < len; i++) {
            p = skipName(b, p, len);
            if (p + 10 > len) return null;
            int type = Packets.u16(b, p), rdlen = Packets.u16(b, p + 8);
            p += 10;
            if (type == 1 && rdlen == 4 && p + 4 <= len) {
                return new byte[]{b[p], b[p + 1], b[p + 2], b[p + 3]};
            }
            p += rdlen;
        }
        return null;
    }

    private static int skipName(byte[] b, int p, int len) {
        while (p < len) {
            int l = b[p] & 0xff;
            if (l == 0) return p + 1;
            if ((l & 0xc0) == 0xc0) return p + 2;
            p += l + 1;
        }
        return p;
    }
}
