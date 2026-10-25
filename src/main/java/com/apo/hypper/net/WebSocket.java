package com.apo.hypper.net;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/** Минимальный WebSocket-клиент (RFC 6455): бинарные кадры поверх готового потока. */
class WebSocket {
    private final InputStream in;
    private final OutputStream out;
    private final Object writeLock = new Object();

    WebSocket(InputStream in, OutputStream out) {
        this.in = in;
        this.out = out;
    }

    void handshake(String host, String path) throws IOException {
        String key = base64(VlessClient.randomBytes(16));
        String req = "GET " + path + " HTTP/1.1\r\n"
                + "Host: " + host + "\r\n"
                + "User-Agent: Mozilla/5.0 (Linux; Android 4.4) AppleWebKit/537.36\r\n"
                + "Upgrade: websocket\r\n"
                + "Connection: Upgrade\r\n"
                + "Sec-WebSocket-Key: " + key + "\r\n"
                + "Sec-WebSocket-Version: 13\r\n\r\n";
        out.write(req.getBytes(VlessClient.UTF8));
        out.flush();

        StringBuilder head = new StringBuilder();
        while (true) {
            int c = in.read();
            if (c < 0) throw new EOFException("WebSocket: соединение закрыто при рукопожатии");
            head.append((char) c);
            int n = head.length();
            if (n >= 4 && head.charAt(n - 4) == '\r' && head.charAt(n - 3) == '\n'
                    && head.charAt(n - 2) == '\r' && head.charAt(n - 1) == '\n') break;
            if (n > 16384) throw new IOException("WebSocket: слишком длинный ответ");
        }
        String status = head.substring(0, Math.max(0, head.indexOf("\r\n")));
        if (!status.contains(" 101")) throw new IOException("WebSocket: " + status);
    }

    InputStream input() {
        return new InputStream() {
            private long remaining;
            private boolean closed;

            private boolean nextFrame() throws IOException {
                while (remaining == 0) {
                    if (closed) return false;
                    int b0 = in.read();
                    int b1 = in.read();
                    if (b0 < 0 || b1 < 0) return false;
                    int opcode = b0 & 0x0f;
                    long len = b1 & 0x7f;
                    if (len == 126) len = (readByte() << 8) | readByte();
                    else if (len == 127) {
                        len = 0;
                        for (int i = 0; i < 8; i++) len = (len << 8) | readByte();
                    }
                    byte[] mask = null;
                    if ((b1 & 0x80) != 0) {
                        mask = new byte[4];
                        for (int i = 0; i < 4; i++) mask[i] = (byte) readByte();
                    }
                    if (opcode >= 0x8) {
                        // управляющие кадры короткие, читаем целиком
                        byte[] payload = new byte[(int) len];
                        for (int i = 0; i < len; i++) {
                            payload[i] = (byte) readByte();
                            if (mask != null) payload[i] ^= mask[i & 3];
                        }
                        if (opcode == 0x8) {
                            closed = true;
                            return false;
                        }
                        if (opcode == 0x9) sendFrame(0xA, payload, 0, payload.length);
                        continue;
                    }
                    if (mask != null) throw new IOException("WebSocket: маскированный кадр от сервера");
                    remaining = len;
                }
                return true;
            }

            private int readByte() throws IOException {
                int b = in.read();
                if (b < 0) throw new EOFException();
                return b;
            }

            @Override
            public int read() throws IOException {
                if (!nextFrame()) return -1;
                int b = in.read();
                if (b < 0) return -1;
                remaining--;
                return b;
            }

            @Override
            public int read(byte[] buf, int off, int len) throws IOException {
                if (len == 0) return 0;
                if (!nextFrame()) return -1;
                int n = in.read(buf, off, (int) Math.min(len, remaining));
                if (n < 0) return -1;
                remaining -= n;
                return n;
            }
        };
    }

    OutputStream output() {
        return new OutputStream() {
            @Override
            public void write(int b) throws IOException {
                write(new byte[]{(byte) b}, 0, 1);
            }

            @Override
            public void write(byte[] b, int off, int len) throws IOException {
                if (len > 0) sendFrame(0x2, b, off, len);
            }

            @Override
            public void flush() throws IOException {
                out.flush();
            }

            @Override
            public void close() throws IOException {
                try {
                    sendFrame(0x8, new byte[0], 0, 0);
                } finally {
                    out.close();
                }
            }
        };
    }

    private void sendFrame(int opcode, byte[] b, int off, int len) throws IOException {
        int hl = len < 126 ? 2 : len <= 0xffff ? 4 : 10;
        byte[] frame = new byte[hl + 4 + len];
        frame[0] = (byte) (0x80 | opcode);
        if (len < 126) {
            frame[1] = (byte) (0x80 | len);
        } else if (len <= 0xffff) {
            frame[1] = (byte) (0x80 | 126);
            frame[2] = (byte) (len >> 8);
            frame[3] = (byte) len;
        } else {
            frame[1] = (byte) (0x80 | 127);
            for (int i = 0; i < 8; i++) frame[2 + i] = (byte) (i < 4 ? 0 : len >> (8 * (7 - i)));
        }
        byte[] mask = VlessClient.randomBytes(4);
        System.arraycopy(mask, 0, frame, hl, 4);
        int p = hl + 4;
        for (int i = 0; i < len; i++) frame[p + i] = (byte) (b[off + i] ^ mask[i & 3]);
        synchronized (writeLock) {
            out.write(frame);
            out.flush();
        }
    }

    private static final char[] B64 =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray();

    static String base64(byte[] d) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < d.length; i += 3) {
            int n = (d[i] & 0xff) << 16;
            if (i + 1 < d.length) n |= (d[i + 1] & 0xff) << 8;
            if (i + 2 < d.length) n |= d[i + 2] & 0xff;
            sb.append(B64[(n >> 18) & 63]).append(B64[(n >> 12) & 63]);
            sb.append(i + 1 < d.length ? B64[(n >> 6) & 63] : '=');
            sb.append(i + 2 < d.length ? B64[n & 63] : '=');
        }
        return sb.toString();
    }
}
