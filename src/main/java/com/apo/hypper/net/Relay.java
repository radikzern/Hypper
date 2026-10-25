package com.apo.hypper.net;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

final class Relay {
    private Relay() {
    }

    /** Гоняет данные между локальным сокетом и VLESS-соединением, пока одна из сторон не закроется. */
    static void pipe(final Socket local, InputStream localIn, final OutputStream localOut,
                     final VlessClient.Conn remote) {
        Thread down = new Thread(new Runnable() {
            public void run() {
                try {
                    copy(remote.in, localOut);
                } catch (IOException ignored) {
                } finally {
                    try {
                        local.close();
                    } catch (IOException ignored) {
                    }
                    remote.close();
                }
            }
        }, "relay-down");
        down.setDaemon(true);
        down.start();
        try {
            copy(localIn, remote.out);
            // клиент закончил отправку — ждём, пока сервер дошлёт ответ
            down.join(120000);
        } catch (IOException ignored) {
        } catch (InterruptedException ignored) {
        } finally {
            remote.close();
        }
    }

    static void copy(InputStream in, OutputStream out) throws IOException {
        byte[] buf = new byte[16384];
        int n;
        while ((n = in.read(buf)) > 0) {
            out.write(buf, 0, n);
            out.flush();
        }
    }
}
