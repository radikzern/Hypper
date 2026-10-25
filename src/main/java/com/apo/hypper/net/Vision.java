package com.apo.hypper.net;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/**
 * XTLS Vision (flow=xtls-rprx-vision) поверх TLS/REALITY.
 *
 * <p>Порт протокола из xray-core (proxy/proxy.go): данные оборачиваются в padding-кадры
 * (чтобы скрыть длины рукопожатия внутреннего TLS), затем обе стороны переходят на «прямую»
 * передачу без обёртки. Мы не делаем splice сырого сокета (это лишь оптимизация xray),
 * а просто перестаём добавлять/снимать обёртку — для сервера это неотличимо.
 *
 * <p>Один экземпляр на одно VLESS-соединение. Поля TLS-фильтра общие для потоков чтения и
 * записи, поэтому доступ к ним синхронизирован; состояние ридера и райтера не пересекается.
 */
final class Vision {
    static final String FLOW = com.apo.hypper.Profile.FLOW_VISION; // "xtls-rprx-vision"

    private static final int BUF_SIZE = 8192; // buf.Size в xray-core
    private static final SecureRandom RANDOM = new SecureRandom();

    static final byte CMD_CONTINUE = 0;
    static final byte CMD_END = 1;
    static final byte CMD_DIRECT = 2;

    // testseed по умолчанию: {900, 500, 900, 256}
    private static final int SEED_THRESHOLD = 900;
    private static final int SEED_LONG_RAND = 500;
    private static final int SEED_LONG_BASE = 900;
    private static final int SEED_SHORT_RAND = 256;

    private static final byte[] TLS13_SUPPORTED_VERSIONS = {0x00, 0x2b, 0x00, 0x02, 0x03, 0x04};

    private final byte[] uuid; // 16 байт

    // --- общее состояние TLS-фильтра (оба потока) ---
    private int numberToFilter = 8;
    private boolean enableXtls;
    private boolean isTls;
    private boolean isTls12plus;
    private int cipher;
    private int remainingServerHello = -1;

    // --- состояние записи (только поток отправки) ---
    private boolean uuidSent;
    private boolean writerPadding = true;

    Vision(byte[] uuid) {
        this.uuid = uuid;
    }

    // ------------------------------------------------------------------
    // TLS-фильтр: распознаёт ClientHello / ServerHello и TLS 1.3.
    // ------------------------------------------------------------------
    private synchronized void filter(byte[] b, int off, int len) {
        if (numberToFilter <= 0) return;
        numberToFilter--;
        if (len >= 6) {
            if (b[off] == 0x16 && b[off + 1] == 0x03 && b[off + 2] == 0x03 && (b[off + 5] & 0xff) == 0x02) {
                // ServerHello
                remainingServerHello = (((b[off + 3] & 0xff) << 8) | (b[off + 4] & 0xff)) + 5;
                isTls12plus = true;
                isTls = true;
                if (len >= 79 && remainingServerHello >= 79) {
                    int sidLen = b[off + 43] & 0xff;
                    int c0 = b[off + 43 + sidLen + 1] & 0xff;
                    int c1 = b[off + 43 + sidLen + 2] & 0xff;
                    cipher = (c0 << 8) | c1;
                }
            } else if (b[off] == 0x16 && b[off + 1] == 0x03 && (b[off + 5] & 0xff) == 0x01) {
                // ClientHello
                isTls = true;
            }
        }
        if (remainingServerHello > 0) {
            int end = Math.min(remainingServerHello, len);
            remainingServerHello -= len;
            if (indexOf(b, off, end, TLS13_SUPPORTED_VERSIONS) >= 0) {
                // TLS 1.3: включаем XTLS, кроме шифра TLS_AES_128_CCM_8_SHA256 (0x1305)
                // и неизвестных старых шифров (cipher == 0).
                if (cipher == 0x1301 || cipher == 0x1302 || cipher == 0x1303 || cipher == 0x1304) {
                    enableXtls = true;
                }
                numberToFilter = 0;
            } else if (remainingServerHello <= 0) {
                // TLS 1.2
                numberToFilter = 0;
            }
        }
    }

    private synchronized boolean isTls() {
        return isTls;
    }

    private synchronized boolean isTls12plus() {
        return isTls12plus;
    }

    private synchronized boolean enableXtls() {
        return enableXtls;
    }

    private synchronized int numberToFilter() {
        return numberToFilter;
    }

    private synchronized boolean filtering() {
        return numberToFilter > 0;
    }

    private synchronized boolean consumeUuid() {
        if (uuidSent) return false;
        uuidSent = true;
        return true;
    }

    // ------------------------------------------------------------------
    // Формирование padding-кадра (XtlsPadding).
    // layout: [uuid(16)]? command(1) contentLen(2 BE) paddingLen(2 BE) content padding
    // ------------------------------------------------------------------
    private byte[] pad(byte[] content, int coff, int clen, byte command, boolean prependUuid, boolean longPadding) {
        int contentLen = content == null ? 0 : clen;
        int paddingLen;
        if (contentLen < SEED_THRESHOLD && longPadding) {
            paddingLen = RANDOM.nextInt(SEED_LONG_RAND) + SEED_LONG_BASE - contentLen;
        } else {
            paddingLen = RANDOM.nextInt(SEED_SHORT_RAND);
        }
        int cap = BUF_SIZE - 21 - contentLen;
        if (paddingLen > cap) paddingLen = cap;
        if (paddingLen < 0) paddingLen = 0;

        int uuidLen = prependUuid ? 16 : 0;
        byte[] out = new byte[uuidLen + 5 + contentLen + paddingLen];
        int p = 0;
        if (prependUuid) {
            System.arraycopy(uuid, 0, out, 0, 16);
            p = 16;
        }
        out[p++] = command;
        out[p++] = (byte) (contentLen >> 8);
        out[p++] = (byte) contentLen;
        out[p++] = (byte) (paddingLen >> 8);
        out[p++] = (byte) paddingLen;
        if (contentLen > 0) System.arraycopy(content, coff, out, p, contentLen);
        // байты padding остаются нулевыми — сервер их отбрасывает
        return out;
    }

    /** Кадр-камуфляж (пустое содержимое, длинный padding) — прячет VLESS-заголовок. */
    byte[] firstPadding() {
        return pad(null, 0, 0, CMD_CONTINUE, consumeUuid(), true);
    }

    OutputStream wrap(OutputStream out) {
        return new VisionOutput(out);
    }

    InputStream wrap(InputStream in) {
        return new VisionInput(in);
    }

    // ------------------------------------------------------------------
    // Поток отправки (VisionWriter, isUplink=true).
    // ------------------------------------------------------------------
    private final class VisionOutput extends OutputStream {
        private final OutputStream out;
        private final byte[] one = new byte[1];

        VisionOutput(OutputStream out) {
            this.out = out;
        }

        @Override
        public void write(int b) throws IOException {
            one[0] = (byte) b;
            write(one, 0, 1);
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            // режем входные данные на куски <= BUF_SIZE (как буферы buf.Reader в xray)
            while (len > 0) {
                int n = Math.min(len, BUF_SIZE);
                writeChunk(b, off, n);
                off += n;
                len -= n;
            }
        }

        private void writeChunk(byte[] b, int off, int len) throws IOException {
            if (filtering()) filter(b, off, len);
            if (!writerPadding) {
                out.write(b, off, len);
                out.flush();
                return;
            }
            boolean isComplete = isCompleteRecord(b, off, len);
            List<int[]> pieces = reshape(b, off, len);
            boolean longPad = isTls();
            int n = pieces.size();
            for (int i = 0; i < n; i++) {
                int po = pieces.get(i)[0];
                int pl = pieces.get(i)[1];
                boolean last = i == n - 1;
                boolean appData = isTls() && pl >= 6
                        && b[po] == 0x17 && b[po + 1] == 0x03 && b[po + 2] == 0x03 && isComplete;
                if (appData) {
                    byte command = CMD_CONTINUE;
                    if (last) command = enableXtls() ? CMD_DIRECT : CMD_END;
                    out.write(pad(b, po, pl, command, consumeUuid(), true));
                    writerPadding = false; // padding заканчивается
                    longPad = false;
                    continue;
                } else if (!isTls12plus() && numberToFilter() <= 1) {
                    // для совместимости со старым приёмником заканчиваем padding на пакет раньше
                    writerPadding = false;
                    out.write(pad(b, po, pl, CMD_END, consumeUuid(), longPad));
                    for (int j = i + 1; j < n; j++) out.write(b, pieces.get(j)[0], pieces.get(j)[1]);
                    out.flush();
                    return;
                }
                byte command = CMD_CONTINUE;
                if (last && !writerPadding) command = enableXtls() ? CMD_DIRECT : CMD_END;
                out.write(pad(b, po, pl, command, consumeUuid(), longPad));
            }
            out.flush();
        }

        @Override
        public void flush() throws IOException {
            out.flush();
        }

        @Override
        public void close() throws IOException {
            out.close();
        }
    }

    /** Разбивает буфер >= BUF_SIZE-21 на два, желательно по границе TLS-записи. */
    private static List<int[]> reshape(byte[] b, int off, int len) {
        List<int[]> r = new ArrayList<int[]>(2);
        if (len < BUF_SIZE - 21) {
            r.add(new int[]{off, len});
            return r;
        }
        int abs = lastIndexOf(b, off, len, (byte) 0x17, (byte) 0x03, (byte) 0x03);
        int rel = abs < 0 ? -1 : abs - off;
        if (rel < 21 || rel > BUF_SIZE - 21) rel = BUF_SIZE / 2;
        r.add(new int[]{off, rel});
        r.add(new int[]{off + rel, len - rel});
        return r;
    }

    /** Полная ли последовательность TLS-записей (0x17 0x03 0x03 + длина) в буфере. */
    private static boolean isCompleteRecord(byte[] b, int off, int len) {
        int headerLen = 5;
        int recordLen = 0;
        int i = 0;
        while (i < len) {
            if (headerLen > 0) {
                int data = b[off + i] & 0xff;
                i++;
                switch (headerLen) {
                    case 5: if (data != 0x17) return false; break;
                    case 4: if (data != 0x03) return false; break;
                    case 3: if (data != 0x03) return false; break;
                    case 2: recordLen = data << 8; break;
                    case 1: recordLen = recordLen | data; break;
                }
                headerLen--;
            } else if (recordLen > 0) {
                int remaining = len - i;
                if (remaining < recordLen) return false;
                i += recordLen;
                recordLen = 0;
                headerLen = 5;
            } else {
                return false;
            }
        }
        return headerLen == 5 && recordLen == 0;
    }

    // ------------------------------------------------------------------
    // Поток чтения (VisionReader, isUplink=false): снимает padding-кадры.
    // ------------------------------------------------------------------
    private final class VisionInput extends InputStream {
        private final InputStream in;

        private boolean raw;        // прямая передача без обёртки
        private boolean unpadDone;  // приняли команду END/DIRECT — обёртка закончилась

        // состояние разбора кадра (аналог Remaining* в xray)
        private int rCmd = -1, rContent = -1, rPad = -1, curCmd;

        private byte[] carry = new byte[0]; // не разобранный «хвост» входа
        private int carryOff, carryLen;

        private byte[] pend = new byte[0];  // раскодированные байты, готовые для вызывающего
        private int pendOff, pendLen;

        private final byte[] chunk = new byte[16384];
        private final byte[] one = new byte[1];

        VisionInput(InputStream in) {
            this.in = in;
        }

        @Override
        public int read() throws IOException {
            int n = read(one, 0, 1);
            return n < 0 ? -1 : one[0] & 0xff;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (len == 0) return 0;
            while (true) {
                if (pendLen > 0) {
                    int n = Math.min(len, pendLen);
                    System.arraycopy(pend, pendOff, b, off, n);
                    pendOff += n;
                    pendLen -= n;
                    return n;
                }
                if (raw) {
                    if (carryLen > 0) {
                        int n = Math.min(len, carryLen);
                        System.arraycopy(carry, carryOff, b, off, n);
                        carryOff += n;
                        carryLen -= n;
                        return n;
                    }
                    return in.read(b, off, len);
                }
                int r = in.read(chunk);
                if (r < 0) return -1;
                appendCarry(chunk, 0, r);
                pendOff = 0;
                pendLen = 0;
                parse();
                if (pendLen > 0 && filtering()) filter(pend, pendOff, pendLen);
                if (!raw && unpadDone && !filtering()) raw = true;
            }
        }

        private void appendCarry(byte[] b, int off, int len) {
            if (carryLen == 0) carryOff = 0;
            if (carryOff + carryLen + len > carry.length) {
                byte[] n = new byte[Math.max(carryLen + len, carry.length * 2 + 64)];
                System.arraycopy(carry, carryOff, n, 0, carryLen);
                carry = n;
                carryOff = 0;
            }
            System.arraycopy(b, off, carry, carryOff + carryLen, len);
            carryLen += len;
        }

        private void appendPend(byte[] b, int off, int len) {
            if (pendLen == 0) pendOff = 0;
            if (pendOff + pendLen + len > pend.length) {
                byte[] n = new byte[Math.max(pendLen + len, pend.length * 2 + 64)];
                System.arraycopy(pend, pendOff, n, 0, pendLen);
                pend = n;
                pendOff = 0;
            }
            System.arraycopy(b, off, pend, pendOff + pendLen, len);
            pendLen += len;
        }

        private void parse() {
            if (unpadDone) {
                // обёртка уже закончилась: всё остальное — сырые данные
                if (carryLen > 0) {
                    appendPend(carry, carryOff, carryLen);
                    carryOff += carryLen;
                    carryLen = 0;
                }
                return;
            }
            if (rCmd == -1 && rContent == -1 && rPad == -1) { // начальное состояние
                if (carryLen < 21) return; // ждём UUID + заголовок кадра
                if (!regionEquals(carry, carryOff, uuid)) {
                    // поток не обёрнут Vision — передаём как есть
                    raw = true;
                    appendPend(carry, carryOff, carryLen);
                    carryOff += carryLen;
                    carryLen = 0;
                    return;
                }
                carryOff += 16;
                carryLen -= 16;
                rCmd = 5;
            }
            while (carryLen > 0) {
                if (rCmd > 0) {
                    int data = carry[carryOff++] & 0xff;
                    carryLen--;
                    switch (rCmd) {
                        case 5: curCmd = data; break;
                        case 4: rContent = data << 8; break;
                        case 3: rContent = rContent | data; break;
                        case 2: rPad = data << 8; break;
                        case 1: rPad = rPad | data; break;
                    }
                    rCmd--;
                } else if (rContent > 0) {
                    int take = Math.min(rContent, carryLen);
                    appendPend(carry, carryOff, take);
                    carryOff += take;
                    carryLen -= take;
                    rContent -= take;
                    if (rContent > 0) return;
                } else { // rPad > 0
                    int take = Math.min(rPad, carryLen);
                    carryOff += take;
                    carryLen -= take;
                    rPad -= take;
                    if (rPad > 0) return;
                }
                if (rCmd <= 0 && rContent <= 0 && rPad <= 0) { // кадр разобран
                    if (curCmd == 0) {
                        rCmd = 5; // следующий блок того же padding-потока (без UUID)
                    } else {
                        rCmd = -1;
                        rContent = -1;
                        rPad = -1;
                        unpadDone = true;
                        if (curCmd == 2) raw = true;
                        if (carryLen > 0) { // остаток — сырые данные
                            appendPend(carry, carryOff, carryLen);
                            carryOff += carryLen;
                            carryLen = 0;
                        }
                        return;
                    }
                }
            }
        }

        @Override
        public int available() throws IOException {
            if (pendLen > 0) return pendLen;
            if (raw) return (carryLen > 0 ? carryLen : 0) + in.available();
            return 0;
        }

        @Override
        public void close() throws IOException {
            in.close();
        }
    }

    // ------------------------------------------------------------------
    // Вспомогательные функции.
    // ------------------------------------------------------------------
    private static boolean regionEquals(byte[] b, int off, byte[] uuid) {
        for (int i = 0; i < 16; i++) if (b[off + i] != uuid[i]) return false;
        return true;
    }

    private static int indexOf(byte[] b, int off, int len, byte[] pat) {
        int last = off + len - pat.length;
        for (int i = off; i <= last; i++) {
            boolean ok = true;
            for (int j = 0; j < pat.length; j++) {
                if (b[i + j] != pat[j]) {
                    ok = false;
                    break;
                }
            }
            if (ok) return i;
        }
        return -1;
    }

    private static int lastIndexOf(byte[] b, int off, int len, byte a, byte c, byte d) {
        for (int i = off + len - 3; i >= off; i--) {
            if (b[i] == a && b[i + 1] == c && b[i + 2] == d) return i;
        }
        return -1;
    }
}
