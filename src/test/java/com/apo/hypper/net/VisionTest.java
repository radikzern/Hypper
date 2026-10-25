package com.apo.hypper.net;

import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

/** Проверяет, что VisionInput снимает padding-кадры ровно так, как их шлёт сервер (xray). */
public class VisionTest {
    private static final byte[] UUID = {
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

    /** Строит один padding-блок: [uuid]? command contentLen(2) paddingLen(2) content padding. */
    private static void block(ByteArrayOutputStream o, boolean uuid, int command, byte[] content, int pad) {
        if (uuid) o.write(UUID, 0, 16);
        int clen = content == null ? 0 : content.length;
        o.write(command);
        o.write(clen >> 8);
        o.write(clen & 0xff);
        o.write(pad >> 8);
        o.write(pad & 0xff);
        if (content != null) o.write(content, 0, content.length);
        for (int i = 0; i < pad; i++) o.write(0xEE); // мусорный padding
    }

    private static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        byte[] b = new byte[7]; // мелкими порциями, чтобы задеть логику pend
        int n;
        while ((n = in.read(b, 0, b.length)) > 0) o.write(b, 0, n);
        return o.toByteArray();
    }

    @Test
    public void unpadsContinueThenEnd() throws IOException {
        byte[] c1 = "ServerHelloPayload".getBytes();
        byte[] c2 = "more-handshake-data".getBytes();
        byte[] tail = "RAW-APPLICATION-DATA-AFTER-VISION".getBytes();

        ByteArrayOutputStream wire = new ByteArrayOutputStream();
        block(wire, true, 0, null, 931);    // камуфляж сервера: пустой Continue с UUID
        block(wire, false, 0, c1, 40);      // Continue с данными
        block(wire, false, 1, c2, 7);       // End с данными
        wire.write(tail, 0, tail.length);   // далее — сырой поток

        InputStream vin = new Vision(UUID).wrap(new ByteArrayInputStream(wire.toByteArray()));
        ByteArrayOutputStream expect = new ByteArrayOutputStream();
        expect.write(c1, 0, c1.length);
        expect.write(c2, 0, c2.length);
        expect.write(tail, 0, tail.length);
        assertArrayEquals(expect.toByteArray(), readAll(vin));
    }

    @Test
    public void unpadsDirectCommand() throws IOException {
        byte[] c1 = "x".getBytes();
        byte[] tail = "rest".getBytes();
        ByteArrayOutputStream wire = new ByteArrayOutputStream();
        block(wire, true, 2, c1, 10);       // первый же блок — Direct
        wire.write(tail, 0, tail.length);

        InputStream vin = new Vision(UUID).wrap(new ByteArrayInputStream(wire.toByteArray()));
        assertArrayEquals("xrest".getBytes(), readAll(vin));
    }

    /** Поток, отдающий ровно по 1 байту за чтение — проверяет разбор кадров по кускам. */
    @Test
    public void unpadsAcrossTinyReads() throws IOException {
        byte[] c1 = "abcdefghij".getBytes();
        byte[] tail = "TAIL".getBytes();
        ByteArrayOutputStream wire = new ByteArrayOutputStream();
        block(wire, true, 0, null, 905);
        block(wire, false, 1, c1, 200);
        wire.write(tail, 0, tail.length);
        final byte[] data = wire.toByteArray();

        InputStream drip = new InputStream() {
            int p;
            public int read() {
                return p < data.length ? data[p++] & 0xff : -1;
            }
            public int read(byte[] b, int off, int len) {
                if (p >= data.length) return -1;
                b[off] = data[p++];
                return 1; // всегда по одному байту
            }
        };
        InputStream vin = new Vision(UUID).wrap(drip);
        assertEquals("abcdefghijTAIL", new String(readAll(vin)));
    }
}
