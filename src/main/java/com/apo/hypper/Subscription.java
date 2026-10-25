package com.apo.hypper;

import org.json.JSONException;
import org.json.JSONObject;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/** Подписка: URL, по которому отдаётся список ссылок vless:// (обычным текстом или в base64). */
public class Subscription {
    public String id = "";
    public String name = "";
    public String url = "";
    public boolean insecure = false;
    public long updated = 0;
    public int count = 0;
    /** Трафик и срок из заголовка subscription-userinfo (байты, unix-время). */
    public long upload, download, total, expire;
    public String lastError = "";

    public String title() {
        if (name.length() > 0) return name;
        try {
            return new java.net.URL(url).getHost();
        } catch (java.net.MalformedURLException e) {
            return url;
        }
    }

    public String describe() {
        StringBuilder sb = new StringBuilder();
        if (lastError.length() > 0) {
            sb.append("Ошибка: ").append(lastError);
            return sb.toString();
        }
        if (updated == 0) return "Ещё не обновлялась";
        sb.append("Серверов: ").append(count);
        if (total > 0) sb.append(" · ").append(size(upload + download)).append(" из ").append(size(total));
        else if (upload + download > 0) sb.append(" · ").append(size(upload + download));
        if (expire > 0) {
            sb.append(" · до ").append(new SimpleDateFormat("dd.MM.yyyy", Locale.US).format(new Date(expire * 1000)));
        }
        return sb.toString();
    }

    public String updatedText() {
        if (updated == 0) return "";
        return "Обновлено " + new SimpleDateFormat("dd.MM HH:mm", Locale.US).format(new Date(updated));
    }

    static String size(long b) {
        if (b >= 1L << 30) return String.format(Locale.US, "%.1f ГБ", b / (double) (1L << 30));
        if (b >= 1L << 20) return String.format(Locale.US, "%.0f МБ", b / (double) (1L << 20));
        return (b >> 10) + " КБ";
    }

    JSONObject toJson() throws JSONException {
        JSONObject o = new JSONObject();
        o.put("id", id).put("name", name).put("url", url).put("insecure", insecure)
                .put("updated", updated).put("count", count)
                .put("up", upload).put("down", download).put("total", total).put("expire", expire)
                .put("error", lastError);
        return o;
    }

    static Subscription fromJson(JSONObject o) {
        Subscription s = new Subscription();
        s.id = o.optString("id");
        s.name = o.optString("name");
        s.url = o.optString("url");
        s.insecure = o.optBoolean("insecure");
        s.updated = o.optLong("updated");
        s.count = o.optInt("count");
        s.upload = o.optLong("up");
        s.download = o.optLong("down");
        s.total = o.optLong("total");
        s.expire = o.optLong("expire");
        s.lastError = o.optString("error");
        return s;
    }
}
