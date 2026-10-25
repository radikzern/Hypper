package com.apo.hypper;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;

import com.apo.hypper.net.Dns;
import com.apo.hypper.net.VlessClient;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.nio.charset.Charset;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Проверка задержки: через сервер делается настоящий HTTP-запрос к generate_204.
 * Так проверяется не только доступность хоста, но и что UUID/транспорт рабочие.
 */
public final class DelayTest {
    public interface Callback {
        void onResult(Profile p);

        void onFinished();
    }

    private static final String HOST = "www.gstatic.com";
    private static final int TIMEOUT = 8000;
    private static final Handler MAIN = new Handler(Looper.getMainLooper());
    private static volatile int generation;
    /** Результаты живут, пока жив процесс: список серверов перечитывается из хранилища. */
    private static final Map<String, Integer> RESULTS = new ConcurrentHashMap<String, Integer>();

    private DelayTest() {
    }

    public static boolean running() {
        return active > 0;
    }

    private static volatile int active;

    public static void restore(List<Profile> list) {
        for (Profile p : list) {
            Integer d = RESULTS.get(p.key());
            if (d != null) p.delay = d;
        }
    }

    public static void cancel() {
        generation++;
    }

    public static void run(Context c, final List<Profile> profiles, final Callback cb) {
        final int gen = ++generation;
        final String dns = VlessService.dnsServer(c);
        final VlessClient.Protector protector = VlessService.protector();
        final Dns.DatagramProtector dprotector = VlessService.datagramProtector();
        final ExecutorService pool = Executors.newFixedThreadPool(6);
        active = profiles.size();
        for (final Profile p : profiles) p.delay = Profile.DELAY_TESTING;
        for (final Profile p : profiles) {
            pool.execute(new Runnable() {
                public void run() {
                    if (gen != generation) {
                        p.delay = Profile.DELAY_UNKNOWN;
                    } else {
                        p.delay = measure(p, dns, protector, dprotector);
                        RESULTS.put(p.key(), p.delay);
                    }
                    MAIN.post(new Runnable() {
                        public void run() {
                            cb.onResult(p);
                            if (--active == 0) cb.onFinished();
                        }
                    });
                }
            });
        }
        pool.shutdown();
    }

    static int measure(Profile p, String dns, VlessClient.Protector protector, Dns.DatagramProtector dp) {
        VlessClient.Conn conn = null;
        try {
            if (p.unsupportedReason() != null) return Profile.DELAY_FAILED;
            InetAddress server = Dns.resolve(p.address, dns, dp);
            if (p.isWg()) {
                int ms = com.apo.hypper.net.wg.WgTunnel.ping(p.wg, server, dp);
                return ms > 0 ? ms : Profile.DELAY_FAILED;
            }
            long start = System.currentTimeMillis();
            conn = new VlessClient(p, server, protector).connect(VlessClient.CMD_TCP, HOST, null, 80);
            conn.setTimeout(TIMEOUT);
            conn.out.write(("GET /generate_204 HTTP/1.1\r\nHost: " + HOST
                    + "\r\nConnection: close\r\n\r\n").getBytes(Charset.forName("UTF-8")));
            conn.out.flush();
            InputStream in = conn.in;
            byte[] head = new byte[12];
            int got = 0;
            while (got < head.length) {
                int n = in.read(head, got, head.length - got);
                if (n < 0) break;
                got += n;
            }
            if (got < 12 || !new String(head, 0, 5, "US-ASCII").equals("HTTP/")) return Profile.DELAY_FAILED;
            return (int) Math.max(1, System.currentTimeMillis() - start);
        } catch (IOException e) {
            AppLog.d("Задержка " + p.title() + ": " + e.getMessage());
            return Profile.DELAY_FAILED;
        } catch (RuntimeException e) {
            return Profile.DELAY_FAILED;
        } finally {
            if (conn != null) conn.close();
        }
    }
}
