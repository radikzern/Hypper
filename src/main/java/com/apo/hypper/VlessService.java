package com.apo.hypper;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.VpnService;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.preference.PreferenceManager;

import com.apo.hypper.net.Dns;
import com.apo.hypper.net.LocalProxy;
import com.apo.hypper.net.RootRedirect;
import com.apo.hypper.net.TunStack;
import com.apo.hypper.net.VlessClient;
import com.apo.hypper.net.wg.WgConfig;
import com.apo.hypper.net.wg.WgTunnel;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.Socket;

/** Поднимает VPN (tun → VLESS) и/или локальный прокси. Сервер можно сменить без переподключения. */
public class VlessService extends VpnService {
    public static final String ACTION_START = "com.apo.hypper.START";
    public static final String ACTION_STOP = "com.apo.hypper.STOP";
    public static final String ACTION_SWITCH = "com.apo.hypper.SWITCH";

    public static final int STOPPED = 0;
    public static final int CONNECTING = 1;
    public static final int RUNNING = 2;

    public interface Listener {
        void onStateChanged();
    }

    private static volatile int state = STOPPED;
    private static volatile String message = "";
    private static volatile TunStack activeStack;
    private static volatile WgTunnel activeWg;
    private static volatile VlessService vpnInstance;
    private static volatile String activeKey = "";
    private static Listener listener;

    private static final int NOTIFY_ID = 1;
    private static final String CHANNEL = "vpn";
    private static final String TUN_ADDR = "172.19.0.1";

    private final Handler main = new Handler(Looper.getMainLooper());
    private final Object switchLock = new Object();
    private ParcelFileDescriptor tun;
    private TunStack stack;
    private WgTunnel wgTunnel;
    private boolean activeIsWg;
    private LocalProxy proxy;
    private RootRedirect redirect;
    private boolean vpnMode;
    private boolean rootMode;
    private int proxyPort;
    private String dns = "8.8.8.8";

    public static int state() {
        return state;
    }

    public static String message() {
        return message;
    }

    /** Ключ сервера, через который сейчас идёт трафик. */
    public static String activeKey() {
        return activeKey;
    }

    public static int connections() {
        TunStack s = activeStack;
        return s == null ? 0 : s.connections();
    }

    /** Дополнительная строка состояния (для WireGuard — рукопожатие и трафик). */
    public static String detail() {
        WgTunnel w = activeWg;
        if (w != null) return w.status();
        int n = connections();
        return n > 0 ? "соединений: " + n : "";
    }

    public static void setListener(Listener l) {
        listener = l;
    }

    /** Для проверки задержки при включённом VPN: сокеты к серверам должны идти мимо туннеля. */
    public static VlessClient.Protector protector() {
        final VlessService s = vpnInstance;
        if (s == null) return null;
        return new VlessClient.Protector() {
            public boolean protect(Socket sock) {
                return s.protect(sock);
            }
        };
    }

    public static Dns.DatagramProtector datagramProtector() {
        final VlessService s = vpnInstance;
        if (s == null) return null;
        return new Dns.DatagramProtector() {
            public boolean protect(DatagramSocket sock) {
                return s.protect(sock);
            }
        };
    }

    private static final String ROOT_RULES = "root_rules_active";

    private static void setRootRules(Context c, boolean on) {
        PreferenceManager.getDefaultSharedPreferences(c).edit().putBoolean(ROOT_RULES, on).commit();
    }

    /**
     * Если процесс упал с поднятыми правилами iptables, весь TCP уходит в мёртвый порт —
     * снимаем их (вызывать не из UI-потока: su может ждать подтверждения).
     */
    public static void cleanupStaleRoot(Context c) {
        if (state != STOPPED && state != CONNECTING) return;
        if (!PreferenceManager.getDefaultSharedPreferences(c).getBoolean(ROOT_RULES, false)) return;
        AppLog.i("Снимаю оставшиеся правила iptables");
        RootRedirect.cleanup();
        setRootRules(c, false);
    }

    public static String dnsServer(Context c) {
        return PreferenceManager.getDefaultSharedPreferences(c).getString("dns", "8.8.8.8").trim();
    }

    public static void start(Context c) {
        c.startService(new Intent(c, VlessService.class).setAction(ACTION_START));
    }

    public static void stop(Context c) {
        c.startService(new Intent(c, VlessService.class).setAction(ACTION_STOP));
    }

    /** Переключиться на выбранный сервер, если подключены. */
    public static void switchServer(Context c) {
        if (state == STOPPED) return;
        c.startService(new Intent(c, VlessService.class).setAction(ACTION_SWITCH));
    }

    private void setState(int s, String msg) {
        state = s;
        message = msg;
        main.post(new Runnable() {
            public void run() {
                Listener l = listener;
                if (l != null) l.onStateChanged();
            }
        });
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent != null ? intent.getAction() : null;
        if (ACTION_STOP.equals(action)) {
            shutdown("Отключено");
            return START_NOT_STICKY;
        }
        if (ACTION_SWITCH.equals(action)) {
            if (state == RUNNING) {
                new Thread(new Runnable() {
                    public void run() {
                        switchToSelected();
                    }
                }, "vless-switch").start();
            }
            return START_NOT_STICKY;
        }
        if (state != STOPPED) return START_NOT_STICKY;
        final Profile p = ProfileStore.selectedProfile(this);
        if (p == null) {
            setState(STOPPED, "Нет выбранного сервера");
            stopSelf();
            return START_NOT_STICKY;
        }
        setState(CONNECTING, "Подключение к " + p.title() + "…");
        startForeground(NOTIFY_ID, notification(p.title(), "Подключение…"));
        new Thread(new Runnable() {
            public void run() {
                try {
                    bringUp(p);
                } catch (Exception e) {
                    AppLog.e("Запуск: " + e.getMessage());
                    shutdown("Ошибка: " + e.getMessage());
                }
            }
        }, "vless-start").start();
        return START_NOT_STICKY;
    }

    /** @param tunnelUp туннель уже поднят — адрес сервера резолвим мимо него */
    private VlessClient makeClient(Profile p, boolean tunnelUp) throws IOException {
        String warn = p.unsupportedReason();
        if (warn != null) AppLog.e("Внимание: " + warn);
        InetAddress server = Dns.resolve(p.address, dns, tunnelUp && vpnMode ? datagramProtectorSelf() : null);
        AppLog.i("Сервер " + p.title() + ": " + p.address + " → " + server.getHostAddress());
        VlessClient.Protector protector = vpnMode ? new VlessClient.Protector() {
            public boolean protect(Socket s) {
                return VlessService.this.protect(s);
            }
        } : null;
        return new VlessClient(p, server, protector);
    }

    private Dns.DatagramProtector datagramProtectorSelf() {
        return new Dns.DatagramProtector() {
            public boolean protect(DatagramSocket s) {
                return VlessService.this.protect(s);
            }
        };
    }

    private void bringUp(Profile p) throws IOException {
        SharedPreferences sp = PreferenceManager.getDefaultSharedPreferences(this);
        String mode = sp.getString("mode", "vpn");
        rootMode = "root".equals(mode);
        vpnMode = !"proxy".equals(mode) && !rootMode;
        cleanupStaleRoot(this);
        proxyPort = parseInt(sp.getString("proxy_port", "10808"), 10808);
        boolean proxyLan = sp.getBoolean("proxy_lan", false);
        dns = dnsServer(this);
        boolean bypassLan = sp.getBoolean("bypass_lan", true);
        AppLog.verbose = sp.getBoolean("verbose", false);

        if (p.isWg()) {
            bringUpWg(p, bypassLan);
        } else {
            bringUpVless(p, proxyLan, bypassLan);
        }
        activeIsWg = p.isWg();

        synchronized (this) {
            if (state == STOPPED) {
                // пока поднимались, пользователь уже нажал «стоп»
                shutdown("Отключено");
                return;
            }
        }
        activeKey = p.key();
        running(p);
        // пока подключались, пользователь мог выбрать другой сервер
        if (!ProfileStore.selectedKey(this).equals(p.key())) switchToSelected();
    }

    private void addRoutes(Builder b, java.util.List<String> allowed, boolean bypassLan, String dnsIp) throws IOException {
        for (String cidr : allowed) {
            int slash = cidr.indexOf('/');
            String ip = slash < 0 ? cidr : cidr.substring(0, slash);
            int prefix = slash < 0 ? (ip.indexOf(':') >= 0 ? 128 : 32) : Integer.parseInt(cidr.substring(slash + 1).trim());
            if (bypassLan && prefix == 0 && ip.indexOf(':') < 0) {
                for (int[] r : TunStack.routesExcludingPrivate()) {
                    b.addRoute(InetAddress.getByAddress(new byte[]{
                            (byte) (r[0] >> 24), (byte) (r[0] >> 16), (byte) (r[0] >> 8), (byte) r[0]}), r[1]);
                }
                if (dnsIp != null && dnsIp.indexOf(':') < 0) b.addRoute(dnsIp, 32);
            } else {
                b.addRoute(ip.trim(), prefix);
            }
        }
    }

    private void bringUpWg(Profile p, boolean bypassLan) throws IOException {
        vpnMode = true; // у WireGuard нет режима «только прокси»
        rootMode = false;
        WgConfig c = p.wg;
        InetAddress endpoint = InetAddress.getByName(c.host);
        AppLog.i(p.protocolName() + " " + p.title() + ": " + c.host + " → " + endpoint.getHostAddress());

        Builder b = new Builder();
        b.setSession(getString(R.string.app_name));
        b.setMtu(c.mtuOrDefault());
        boolean v6 = false;
        for (String a : c.address) {
            int slash = a.indexOf('/');
            String ip = (slash < 0 ? a : a.substring(0, slash)).trim();
            int prefix = slash < 0 ? (ip.indexOf(':') >= 0 ? 128 : 32) : Integer.parseInt(a.substring(slash + 1).trim());
            b.addAddress(ip, prefix);
            if (ip.indexOf(':') >= 0) v6 = true;
        }
        java.util.List<String> allowed = new java.util.ArrayList<String>();
        for (String r : c.allowedIps) {
            // без IPv6-адреса маршрут ::/0 только сломает IPv6 на устройстве
            if (r.indexOf(':') >= 0 && !v6) continue;
            allowed.add(r);
        }
        String wgDns = null;
        for (String d : c.dns) {
            if (VlessClient.isIpLiteral(d)) {
                b.addDnsServer(d);
                if (wgDns == null) wgDns = d;
            }
        }
        if (wgDns == null) {
            b.addDnsServer(dns);
            wgDns = dns;
        }
        addRoutes(b, allowed, bypassLan, wgDns);
        b.setConfigureIntent(mainIntent());
        synchronized (this) {
            if (state == STOPPED) return;
            tun = b.establish();
        }
        if (tun == null) throw new IOException("Нет разрешения на VPN");
        vpnInstance = this;
        wgTunnel = new WgTunnel(c, endpoint, tun.getFileDescriptor(), datagramProtectorSelf());
        wgTunnel.start();
        activeWg = wgTunnel;
        AppLog.i("VPN поднят, DNS " + wgDns + ", MTU " + c.mtuOrDefault());
    }

    private void bringUpVless(Profile p, boolean proxyLan, boolean bypassLan) throws IOException {
        boolean vpn = vpnMode;
        // туннеля ещё нет — системный DNS работает напрямую
        VlessClient client = makeClient(p, false);

        proxy = new LocalProxy(client, proxyPort, proxyLan);
        try {
            proxy.start();
        } catch (IOException e) {
            AppLog.e("Порт " + proxyPort + " занят: " + e.getMessage());
            proxy = null;
            if (!vpn && !rootMode) throw e;
        }

        if (rootMode) {
            RootRedirect r = new RootRedirect(client, dns, bypassLan, android.os.Process.myUid());
            synchronized (this) {
                if (state == STOPPED) return;
                redirect = r;
            }
            setRootRules(this, true);
            r.start();
        }

        if (vpn) {
            Builder b = new Builder();
            b.setSession(getString(R.string.app_name));
            b.setMtu(1500);
            b.addAddress(TUN_ADDR, 30);
            if (bypassLan) {
                for (int[] r : TunStack.routesExcludingPrivate()) {
                    b.addRoute(InetAddress.getByAddress(new byte[]{
                            (byte) (r[0] >> 24), (byte) (r[0] >> 16), (byte) (r[0] >> 8), (byte) r[0]}), r[1]);
                }
                // DNS-сервер мог попасть в исключённые сети
                b.addRoute(dns, 32);
            } else {
                b.addRoute("0.0.0.0", 0);
            }
            b.addDnsServer(dns);
            b.setConfigureIntent(mainIntent());
            synchronized (this) {
                if (state == STOPPED) return;
                tun = b.establish();
            }
            if (tun == null) throw new IOException("Нет разрешения на VPN");
            stack = new TunStack(tun.getFileDescriptor(), client);
            stack.start();
            activeStack = stack;
            vpnInstance = this;
            AppLog.i("VPN поднят, DNS " + dns);
        }
    }

    private void running(Profile p) {
        String text = vpnMode ? "VPN активен" : rootMode ? "Root-перехват активен" : "Прокси 127.0.0.1:" + proxyPort;
        notify(p.title(), text);
        setState(RUNNING, text + " · " + p.title());
    }

    private void switchToSelected() {
        synchronized (switchLock) {
            Profile p = ProfileStore.selectedProfile(this);
            if (p == null || state != RUNNING || p.key().equals(activeKey)) return;
            if (p.isWg() || activeIsWg) {
                // у WireGuard свои адреса, MTU и маршруты — туннель пересоздаём
                setState(CONNECTING, "Подключение к " + p.title() + "…");
                teardown();
                try {
                    bringUp(p);
                } catch (Exception e) {
                    AppLog.e("Переключение: " + e.getMessage());
                    shutdown("Ошибка: " + e.getMessage());
                }
                return;
            }
            setState(RUNNING, "Переключение на " + p.title() + "…");
            try {
                VlessClient client = makeClient(p, true);
                synchronized (this) {
                    if (state != RUNNING) return;
                    if (stack != null) stack.setClient(client);
                    if (proxy != null) proxy.setClient(client);
                    if (redirect != null) redirect.setClient(client);
                }
                activeKey = p.key();
                AppLog.i("Переключено на " + p.title());
                running(p);
            } catch (IOException e) {
                AppLog.e("Переключение: " + e.getMessage());
                setState(RUNNING, "Не удалось переключиться: " + e.getMessage());
            }
        }
    }

    private synchronized void shutdown(String msg) {
        teardown();
        if (state != STOPPED) AppLog.i(msg);
        setState(STOPPED, msg);
        stopForeground(true);
        stopSelf();
    }

    /** Останавливает туннель и прокси, не меняя состояние сервиса. */
    private synchronized void teardown() {
        activeStack = null;
        activeWg = null;
        vpnInstance = null;
        activeKey = "";
        if (wgTunnel != null) {
            wgTunnel.stop();
            wgTunnel = null;
        }
        if (stack != null) {
            stack.stop();
            stack = null;
        }
        if (proxy != null) {
            proxy.stop();
            proxy = null;
        }
        if (redirect != null) {
            redirect.stop();
            redirect = null;
            setRootRules(this, false);
        }
        if (tun != null) {
            try {
                tun.close();
            } catch (IOException ignored) {
            }
            tun = null;
        }
    }

    @Override
    public void onRevoke() {
        shutdown("VPN отключён системой");
    }

    @Override
    public void onDestroy() {
        if (state != STOPPED) shutdown("Отключено");
        super.onDestroy();
    }

    private static int immutable() {
        return Build.VERSION.SDK_INT >= 23 ? PendingIntent.FLAG_IMMUTABLE : 0;
    }

    private PendingIntent mainIntent() {
        Intent i = new Intent(this, MainActivity.class).setFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP);
        return PendingIntent.getActivity(this, 0, i, immutable());
    }

    private void notify(String title, String text) {
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        nm.notify(NOTIFY_ID, notification(title, text));
    }

    @SuppressWarnings("deprecation")
    private Notification notification(String title, String text) {
        Notification.Builder b;
        if (Build.VERSION.SDK_INT >= 26) {
            NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
            nm.createNotificationChannel(new NotificationChannel(CHANNEL, "VPN", NotificationManager.IMPORTANCE_LOW));
            b = new Notification.Builder(this, CHANNEL);
        } else {
            b = new Notification.Builder(this);
        }
        b.setSmallIcon(R.drawable.ic_stat)
                .setContentTitle(title)
                .setContentText(text)
                .setOngoing(true)
                .setContentIntent(mainIntent());
        if (Build.VERSION.SDK_INT >= 16) {
            PendingIntent stop = PendingIntent.getService(this, 1,
                    new Intent(this, VlessService.class).setAction(ACTION_STOP), immutable());
            b.addAction(android.R.drawable.ic_menu_close_clear_cancel, "Отключить", stop);
            return b.build();
        }
        return b.getNotification();
    }

    private static int parseInt(String s, int def) {
        try {
            int v = Integer.parseInt(s.trim());
            return v > 0 && v < 65536 ? v : def;
        } catch (NumberFormatException e) {
            return def;
        }
    }
}
