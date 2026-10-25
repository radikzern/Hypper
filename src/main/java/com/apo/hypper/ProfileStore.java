package com.apo.hypper;

import android.content.Context;
import android.content.SharedPreferences;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

/** Серверы и подписки в SharedPreferences (JSON). */
public final class ProfileStore {
    private static final String PREFS = "profiles";
    private static final String KEY_LIST = "list";
    private static final String KEY_SUBS = "subs";
    private static final String KEY_SELECTED = "selected_key";
    private static final String KEY_SELECTED_OLD = "selected";

    private ProfileStore() {
    }

    private static SharedPreferences prefs(Context c) {
        return c.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    public static synchronized List<Profile> load(Context c) {
        List<Profile> out = new ArrayList<Profile>();
        try {
            JSONArray a = new JSONArray(prefs(c).getString(KEY_LIST, "[]"));
            for (int i = 0; i < a.length(); i++) {
                try {
                    // старый формат — просто строка со ссылкой
                    JSONObject o = a.optJSONObject(i);
                    Profile p = Profile.parse(o != null ? o.getString("u") : a.getString(i));
                    if (o != null) p.sub = o.optString("s");
                    out.add(p);
                } catch (IllegalArgumentException e) {
                    AppLog.e("Сервер " + i + " повреждён: " + e.getMessage());
                }
            }
        } catch (JSONException e) {
            AppLog.e("Список серверов повреждён");
        }
        return out;
    }

    public static synchronized void save(Context c, List<Profile> list) {
        JSONArray a = new JSONArray();
        try {
            for (Profile p : list) {
                JSONObject o = new JSONObject().put("u", p.toUri());
                if (p.sub.length() > 0) o.put("s", p.sub);
                a.put(o);
            }
        } catch (JSONException ignored) {
        }
        prefs(c).edit().putString(KEY_LIST, a.toString()).commit();
    }

    public static synchronized List<Subscription> loadSubs(Context c) {
        List<Subscription> out = new ArrayList<Subscription>();
        try {
            JSONArray a = new JSONArray(prefs(c).getString(KEY_SUBS, "[]"));
            for (int i = 0; i < a.length(); i++) out.add(Subscription.fromJson(a.getJSONObject(i)));
        } catch (JSONException e) {
            AppLog.e("Список подписок повреждён");
        }
        return out;
    }

    public static synchronized void saveSubs(Context c, List<Subscription> subs) {
        JSONArray a = new JSONArray();
        try {
            for (Subscription s : subs) a.put(s.toJson());
        } catch (JSONException ignored) {
        }
        prefs(c).edit().putString(KEY_SUBS, a.toString()).commit();
    }

    public static Subscription findSub(List<Subscription> subs, String id) {
        for (Subscription s : subs) if (s.id.equals(id)) return s;
        return null;
    }

    /** Заменяет серверы подписки новым списком, сохраняя их место в общем списке. */
    public static synchronized void replaceSubProfiles(Context c, String subId, List<Profile> fresh) {
        List<Profile> all = load(c);
        List<Profile> out = new ArrayList<Profile>();
        boolean inserted = false;
        for (Profile p : all) {
            if (subId.equals(p.sub)) {
                if (!inserted) {
                    out.addAll(fresh);
                    inserted = true;
                }
            } else {
                out.add(p);
            }
        }
        if (!inserted) out.addAll(fresh);
        save(c, out);
    }

    public static String selectedKey(Context c) {
        return prefs(c).getString(KEY_SELECTED, "");
    }

    public static void setSelected(Context c, Profile p) {
        prefs(c).edit().putString(KEY_SELECTED, p == null ? "" : p.key()).commit();
    }

    public static Profile selectedProfile(Context c) {
        List<Profile> list = load(c);
        if (list.isEmpty()) return null;
        String key = selectedKey(c);
        for (Profile p : list) if (p.key().equals(key)) return p;
        int old = prefs(c).getInt(KEY_SELECTED_OLD, 0);
        return list.get(old >= 0 && old < list.size() ? old : 0);
    }
}
