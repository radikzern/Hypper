package com.apo.hypper;

import android.content.Context;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;


/** Скачивание и разбор подписок. */
public final class SubscriptionUpdater {
    private static final Charset UTF8 = Charset.forName("UTF-8");
    // Панели (Marzban, 3x-ui и др.) по User-Agent решают, в каком формате отдавать список
    private static final String USER_AGENT = "v2rayNG/1.8.19";

    private SubscriptionUpdater() {
    }

    public static class Parsed {
        public final List<Profile> profiles = new ArrayList<Profile>();
        public int skipped;
        public String firstError;
    }

    public interface Done {
        /** @param errors текст ошибок по подпискам, пусто — всё хорошо */
        void onDone(int ok, String errors);
    }

    /** Обновляет подписки в фоне, результат — в UI-потоке. */
    public static void updateAsync(final Context c, final List<String> ids, final Done done) {
        final Context app = c.getApplicationContext();
        final android.os.Handler main = new android.os.Handler(android.os.Looper.getMainLooper());
        new Thread(new Runnable() {
            public void run() {
                int ok = 0;
                StringBuilder errors = new StringBuilder();
                for (String id : ids) {
                    try {
                        update(app, id);
                        ok++;
                    } catch (IOException e) {
                        Subscription s = ProfileStore.findSub(ProfileStore.loadSubs(app), id);
                        errors.append(s != null ? s.title() : id).append(": ").append(e.getMessage()).append('\n');
                    }
                }
                final int fOk = ok;
                final String fErr = errors.toString().trim();
                main.post(new Runnable() {
                    public void run() {
                        done.onDone(fOk, fErr);
                    }
                });
            }
        }, "sub-update").start();
    }

    /** Обновляет подписку и её серверы в хранилище. Вызывать не из UI-потока. */
    public static void update(Context c, String subId) throws IOException {
        List<Subscription> subs = ProfileStore.loadSubs(c);
        Subscription s = ProfileStore.findSub(subs, subId);
        if (s == null) return;
        try {
            Parsed parsed = fetch(s);
            for (Profile p : parsed.profiles) p.sub = s.id;
            if (parsed.profiles.isEmpty()) {
                throw new IOException(parsed.skipped > 0
                        ? "Нет поддерживаемых серверов (других протоколов: " + parsed.skipped + ")"
                        : "В подписке нет серверов");
            }
            ProfileStore.replaceSubProfiles(c, s.id, parsed.profiles);
            s.count = parsed.profiles.size();
            s.updated = System.currentTimeMillis();
            s.lastError = "";
            AppLog.i("Подписка «" + s.title() + "»: серверов " + s.count
                    + (parsed.skipped > 0 ? ", пропущено " + parsed.skipped : ""));
        } catch (IOException e) {
            s.lastError = e.getMessage() == null ? e.toString() : e.getMessage();
            AppLog.e("Подписка «" + s.title() + "»: " + s.lastError);
            throw e;
        } finally {
            // перечитываем: пока качали, список могли изменить
            List<Subscription> now = ProfileStore.loadSubs(c);
            for (int i = 0; i < now.size(); i++) {
                if (now.get(i).id.equals(s.id)) now.set(i, s);
            }
            ProfileStore.saveSubs(c, now);
        }
    }

    static Parsed fetch(Subscription s) throws IOException {
        com.apo.hypper.net.tls.Https.Response r =
                com.apo.hypper.net.tls.Https.get(new URL(s.url.trim()), USER_AGENT, s.insecure);
        if (r.code != 200) throw new IOException("HTTP " + r.code);
        applyUserInfo(s, r.header("subscription-userinfo"));
        if (s.name.length() == 0) {
            String title = r.header("profile-title");
            if (title != null) s.name = decodeTitle(title);
        }
        return parse(new String(r.body, UTF8));
    }

    /** Текст подписки: ссылки построчно, либо всё это в base64. */
    public static Parsed parse(String body) {
        String text = body.trim();
        if (com.apo.hypper.net.wg.WgConfig.looksLikeConf(text)) {
            Parsed r = new Parsed();
            try {
                r.profiles.add(Profile.fromWg(com.apo.hypper.net.wg.WgConfig.parseConf(text), ""));
            } catch (IllegalArgumentException e) {
                r.firstError = "Конфиг WireGuard: " + e.getMessage();
            }
            return r;
        }
        if (!text.contains("://")) {
            byte[] decoded = base64(text);
            if (decoded != null) text = new String(decoded, UTF8);
        }
        Parsed r = new Parsed();
        for (String line : text.split("[\\r\\n]+")) {
            line = line.trim();
            if (line.length() == 0) continue;
            if (!Profile.isLink(line)) {
                if (line.contains("://")) r.skipped++;
                continue;
            }
            try {
                r.profiles.add(Profile.parse(line));
            } catch (IllegalArgumentException e) {
                r.skipped++;
                if (r.firstError == null) r.firstError = e.getMessage();
            }
        }
        return r;
    }

    static void applyUserInfo(Subscription s, String header) {
        s.upload = s.download = s.total = s.expire = 0;
        if (header == null) return;
        for (String part : header.split(";")) {
            String[] kv = part.trim().split("=", 2);
            if (kv.length != 2) continue;
            long v;
            try {
                v = (long) Double.parseDouble(kv[1].trim());
            } catch (NumberFormatException e) {
                continue;
            }
            String k = kv[0].trim().toLowerCase(Locale.US);
            if (k.equals("upload")) s.upload = v;
            else if (k.equals("download")) s.download = v;
            else if (k.equals("total")) s.total = v;
            else if (k.equals("expire")) s.expire = v;
        }
    }

    static String decodeTitle(String t) {
        if (t.startsWith("base64:")) {
            byte[] d = base64(t.substring(7));
            if (d != null) return new String(d, UTF8).trim();
        }
        return t.trim();
    }

    /** base64 и base64url, с паддингом или без, с переводами строк. null — не base64. */
    static byte[] base64(String s) {
        StringBuilder clean = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\r' || c == '\n' || c == ' ' || c == '\t' || c == '=') continue;
            if (c == '-') c = '+';
            else if (c == '_') c = '/';
            if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/'))
                return null;
            clean.append(c);
        }
        if (clean.length() % 4 == 1) return null;
        ByteArrayOutputStream out = new ByteArrayOutputStream(clean.length() * 3 / 4);
        int buf = 0, bits = 0;
        for (int i = 0; i < clean.length(); i++) {
            char c = clean.charAt(i);
            int v = c >= 'A' && c <= 'Z' ? c - 'A' : c >= 'a' && c <= 'z' ? c - 'a' + 26
                    : c >= '0' && c <= '9' ? c - '0' + 52 : c == '+' ? 62 : 63;
            buf = (buf << 6) | v;
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                out.write((buf >> bits) & 0xff);
            }
        }
        return out.toByteArray();
    }

    private static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0) {
            out.write(buf, 0, n);
            if (out.size() > 8 << 20) throw new IOException("Слишком большой ответ");
        }
        in.close();
        return out.toByteArray();
    }
}
