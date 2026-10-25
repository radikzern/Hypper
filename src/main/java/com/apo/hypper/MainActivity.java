package com.apo.hypper;

import android.app.ActionBar;
import android.app.AlertDialog;
import android.app.ListActivity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Handler;
import android.preference.PreferenceManager;
import android.view.ContextMenu;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.BaseAdapter;
import android.widget.CompoundButton;
import android.widget.ListView;
import android.widget.ProgressBar;
import android.widget.RadioButton;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

public class MainActivity extends ListActivity implements VlessService.Listener, ActionBar.OnNavigationListener {
    private static final int REQ_VPN = 1;
    private static final int REQ_FILE = 2;
    private static final long AUTO_UPDATE_MS = 12 * 3600 * 1000L;
    private static final String GROUP_ALL = "*";
    private static final String GROUP_MANUAL = "";

    private final Handler handler = new Handler();
    private List<Profile> all = new ArrayList<Profile>();
    private List<Profile> shown = new ArrayList<Profile>();
    private List<Subscription> subs = new ArrayList<Subscription>();
    private final List<String> groupIds = new ArrayList<String>();
    private ArrayAdapter<String> groupAdapter;
    private String group = GROUP_ALL;
    private String selectedKey = "";
    private boolean sortByDelay;
    private Adapter adapter;
    private TextView status, statusDetail;
    private Switch toggle;
    private ProgressBar progress;
    private boolean updatingToggle;
    private boolean updatingNav;

    private final Runnable ticker = new Runnable() {
        public void run() {
            onStateChanged();
            handler.postDelayed(this, 1000);
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        final android.content.Context app = getApplicationContext();
        new Thread(new Runnable() {
            public void run() {
                VlessService.cleanupStaleRoot(app); // правила iptables после аварийного завершения
            }
        }, "root-cleanup").start();
        requestWindowFeature(Window.FEATURE_INDETERMINATE_PROGRESS);
        setContentView(R.layout.activity_main);
        setProgressBarIndeterminateVisibility(false);
        PreferenceManager.setDefaultValues(this, R.xml.prefs, false);

        SharedPreferences ui = getSharedPreferences("ui", MODE_PRIVATE);
        group = ui.getString("group", GROUP_ALL);
        sortByDelay = ui.getBoolean("sort", false);

        status = (TextView) findViewById(R.id.status);
        statusDetail = (TextView) findViewById(R.id.status_detail);
        toggle = (Switch) findViewById(R.id.toggle);
        progress = (ProgressBar) findViewById(R.id.progress);

        ActionBar ab = getActionBar();
        groupAdapter = new ArrayAdapter<String>(ab.getThemedContext(),
                android.R.layout.simple_spinner_item, new ArrayList<String>());
        groupAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        ab.setListNavigationCallbacks(groupAdapter, this);

        adapter = new Adapter();
        setListAdapter(adapter);
        registerForContextMenu(getListView());

        toggle.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            public void onCheckedChanged(CompoundButton b, boolean on) {
                if (updatingToggle) return;
                if (on) connect();
                else VlessService.stop(MainActivity.this);
            }
        });

        reload();
        handleIntent(getIntent());
        if (savedInstanceState == null) autoUpdate();
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        handleIntent(intent);
    }

    /** Ссылка vless:// или подписка, открытая из браузера или присланная через «Поделиться». */
    private void handleIntent(Intent intent) {
        if (intent == null) return;
        String text = null;
        if (Intent.ACTION_VIEW.equals(intent.getAction()) && intent.getData() != null) {
            text = intent.getData().toString();
        } else if (Intent.ACTION_SEND.equals(intent.getAction())) {
            text = intent.getStringExtra(Intent.EXTRA_TEXT);
        }
        if (text == null) return;
        setIntent(new Intent());
        reload();
        importText(text);
    }

    @Override
    protected void onResume() {
        super.onResume();
        reload();
        VlessService.setListener(this);
        handler.post(ticker);
    }

    @Override
    protected void onPause() {
        super.onPause();
        VlessService.setListener(null);
        handler.removeCallbacks(ticker);
        getSharedPreferences("ui", MODE_PRIVATE).edit()
                .putString("group", group).putBoolean("sort", sortByDelay).commit();
    }

    private void reload() {
        all = ProfileStore.load(this);
        subs = ProfileStore.loadSubs(this);
        DelayTest.restore(all);
        Profile sel = ProfileStore.selectedProfile(this);
        selectedKey = sel == null ? "" : sel.key();
        rebuildGroups();
        rebuildShown();
    }

    private void rebuildGroups() {
        groupIds.clear();
        List<String> names = new ArrayList<String>();
        groupIds.add(GROUP_ALL);
        names.add("Все серверы (" + all.size() + ")");
        for (Subscription s : subs) {
            groupIds.add(s.id);
            names.add(s.title() + " (" + countIn(s.id) + ")");
        }
        int manual = countIn(GROUP_MANUAL);
        if (manual > 0 && !subs.isEmpty()) {
            groupIds.add(GROUP_MANUAL);
            names.add("Свои (" + manual + ")");
        }
        if (!groupIds.contains(group)) group = GROUP_ALL;

        ActionBar ab = getActionBar();
        if (groupIds.size() > 1) {
            groupAdapter.clear();
            for (String n : names) groupAdapter.add(n);
            updatingNav = true;
            ab.setDisplayShowTitleEnabled(false);
            ab.setNavigationMode(ActionBar.NAVIGATION_MODE_LIST);
            ab.setSelectedNavigationItem(groupIds.indexOf(group));
            updatingNav = false;
        } else {
            ab.setNavigationMode(ActionBar.NAVIGATION_MODE_STANDARD);
            ab.setDisplayShowTitleEnabled(true);
        }
    }

    private int countIn(String subId) {
        int n = 0;
        for (Profile p : all) if (p.sub.equals(subId)) n++;
        return n;
    }

    private void rebuildShown() {
        shown = new ArrayList<Profile>();
        for (Profile p : all) {
            if (GROUP_ALL.equals(group) || p.sub.equals(group)) shown.add(p);
        }
        if (sortByDelay) {
            Collections.sort(shown, new Comparator<Profile>() {
                public int compare(Profile a, Profile b) {
                    return rank(a) - rank(b);
                }

                private int rank(Profile p) {
                    return p.delay > 0 ? p.delay : p.delay == Profile.DELAY_FAILED ? 1000000 : 999999;
                }
            });
        }
        adapter.notifyDataSetChanged();
    }

    public boolean onNavigationItemSelected(int position, long id) {
        if (updatingNav || position >= groupIds.size()) return true;
        group = groupIds.get(position);
        rebuildShown();
        return true;
    }

    public void onStateChanged() {
        int st = VlessService.state();
        updatingToggle = true;
        toggle.setChecked(st != VlessService.STOPPED);
        updatingToggle = false;
        progress.setVisibility(st == VlessService.CONNECTING ? View.VISIBLE : View.INVISIBLE);
        switch (st) {
            case VlessService.RUNNING:
                status.setText(R.string.status_on);
                String extra = VlessService.detail();
                statusDetail.setText(VlessService.message() + (extra.length() > 0 ? "\n" + extra : ""));
                break;
            case VlessService.CONNECTING:
                status.setText(R.string.status_connecting);
                statusDetail.setText(VlessService.message());
                break;
            default:
                status.setText(R.string.status_off);
                statusDetail.setText(VlessService.message());
        }
    }

    private void connect() {
        if (all.isEmpty()) {
            Toast.makeText(this, "Сначала добавьте сервер или подписку", Toast.LENGTH_SHORT).show();
            onStateChanged();
            return;
        }
        String mode = PreferenceManager.getDefaultSharedPreferences(this).getString("mode", "vpn");
        Profile sel = ProfileStore.selectedProfile(this);
        // WireGuard всегда работает через VPN; режимы proxy и root разрешения VPN не требуют
        if ("vpn".equals(mode) || (sel != null && sel.isWg())) {
            Intent consent = VpnService.prepare(this);
            if (consent != null) {
                startActivityForResult(consent, REQ_VPN);
                return;
            }
        }
        VlessService.start(this);
    }

    private void chooseNewType() {
        new AlertDialog.Builder(this)
                .setTitle(R.string.menu_add)
                .setItems(new String[]{"VLESS", "WireGuard / AmneziaWG"}, new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface d, int which) {
                        startActivity(new Intent(MainActivity.this,
                                which == 0 ? EditActivity.class : WgEditActivity.class));
                    }
                })
                .show();
    }

    private void importFile(android.net.Uri uri) {
        try {
            java.io.InputStream in = getContentResolver().openInputStream(uri);
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0 && out.size() < 1 << 20) out.write(buf, 0, n);
            in.close();
            String text = new String(out.toByteArray(), "UTF-8");
            String name = uri.getLastPathSegment();
            if (com.apo.hypper.net.wg.WgConfig.looksLikeConf(text) && name != null) {
                // имя файла (wg-nl.conf → wg-nl) — как в официальном клиенте
                name = name.substring(name.lastIndexOf('/') + 1).replaceAll("\\.conf$", "");
                try {
                    Profile p = Profile.fromWg(com.apo.hypper.net.wg.WgConfig.parseConf(text), name);
                    addProfiles(java.util.Collections.singletonList(p));
                } catch (IllegalArgumentException e) {
                    showImportError(e.getMessage());
                }
                return;
            }
            importText(text);
        } catch (java.io.IOException e) {
            showImportError("Не удалось прочитать файл: " + e.getMessage());
        }
    }

    private void showImportError(String msg) {
        new AlertDialog.Builder(this)
                .setTitle("Не удалось импортировать")
                .setMessage(msg)
                .setPositiveButton(android.R.string.ok, null)
                .show();
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode == REQ_FILE) {
            if (resultCode == RESULT_OK && data != null && data.getData() != null) importFile(data.getData());
            return;
        }
        if (requestCode == REQ_VPN) {
            if (resultCode == RESULT_OK) VlessService.start(this);
            else onStateChanged();
        }
    }

    @Override
    protected void onListItemClick(ListView l, View v, int position, long id) {
        select(shown.get(position));
    }

    private void select(Profile p) {
        if (p.key().equals(selectedKey)) return;
        selectedKey = p.key();
        ProfileStore.setSelected(this, p);
        adapter.notifyDataSetChanged();
        if (VlessService.state() != VlessService.STOPPED) {
            VlessService.switchServer(this);
            Toast.makeText(this, "Переключаемся на " + p.title(), Toast.LENGTH_SHORT).show();
        }
    }

    // ---------------------------------------------------------------- задержка

    private void testDelay() {
        if (shown.isEmpty()) return;
        setProgressBarIndeterminateVisibility(true);
        DelayTest.run(this, new ArrayList<Profile>(shown), new DelayTest.Callback() {
            public void onResult(Profile p) {
                adapter.notifyDataSetChanged();
            }

            public void onFinished() {
                setProgressBarIndeterminateVisibility(false);
                if (sortByDelay) rebuildShown();
            }
        });
        adapter.notifyDataSetChanged();
    }

    private void selectBest() {
        Profile best = null;
        for (Profile p : shown) if (p.delay > 0 && (best == null || p.delay < best.delay)) best = p;
        if (best == null) {
            Toast.makeText(this, "Сначала проверьте задержку", Toast.LENGTH_SHORT).show();
            testDelay();
            return;
        }
        select(best);
        Toast.makeText(this, best.title() + " — " + best.delay + " мс", Toast.LENGTH_SHORT).show();
    }

    // ---------------------------------------------------------------- подписки

    private void autoUpdate() {
        if (!PreferenceManager.getDefaultSharedPreferences(this).getBoolean("auto_update", true)) return;
        List<String> stale = new ArrayList<String>();
        long now = System.currentTimeMillis();
        for (Subscription s : subs) if (now - s.updated > AUTO_UPDATE_MS) stale.add(s.id);
        if (!stale.isEmpty()) updateSubs(stale, false);
    }

    private void updateSubs(List<String> ids, final boolean report) {
        if (ids.isEmpty()) {
            if (report) Toast.makeText(this, "Подписок нет", Toast.LENGTH_SHORT).show();
            return;
        }
        setProgressBarIndeterminateVisibility(true);
        SubscriptionUpdater.updateAsync(this, ids, new SubscriptionUpdater.Done() {
            public void onDone(int ok, String errors) {
                if (isFinishing()) return;
                setProgressBarIndeterminateVisibility(false);
                reload();
                if (report) SubscriptionsActivity.report(MainActivity.this, ok, errors);
            }
        });
    }

    private void updateAllSubs() {
        List<String> ids = new ArrayList<String>();
        for (Subscription s : subs) ids.add(s.id);
        updateSubs(ids, true);
    }

    // ---------------------------------------------------------------- меню

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.main, menu);
        return true;
    }

    @Override
    public boolean onPrepareOptionsMenu(Menu menu) {
        menu.findItem(R.id.sort).setChecked(sortByDelay);
        menu.findItem(R.id.update_subs).setVisible(!subs.isEmpty());
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        int id = item.getItemId();
        if (id == R.id.paste) {
            pasteFromClipboard();
        } else if (id == R.id.ping) {
            testDelay();
        } else if (id == R.id.best) {
            selectBest();
        } else if (id == R.id.sort) {
            sortByDelay = !sortByDelay;
            item.setChecked(sortByDelay);
            rebuildShown();
        } else if (id == R.id.update_subs) {
            updateAllSubs();
        } else if (id == R.id.subs) {
            startActivity(new Intent(this, SubscriptionsActivity.class));
        } else if (id == R.id.add) {
            chooseNewType();
        } else if (id == R.id.import_file) {
            Intent pick = new Intent(Intent.ACTION_GET_CONTENT).setType("*/*").addCategory(Intent.CATEGORY_OPENABLE);
            try {
                startActivityForResult(Intent.createChooser(pick, "Файл конфигурации"), REQ_FILE);
            } catch (android.content.ActivityNotFoundException e) {
                Toast.makeText(this, "Нет приложения для выбора файлов", Toast.LENGTH_SHORT).show();
            }
        } else if (id == R.id.log) {
            startActivity(new Intent(this, LogActivity.class));
        } else if (id == R.id.settings) {
            startActivity(new Intent(this, SettingsActivity.class));
        } else {
            return super.onOptionsItemSelected(item);
        }
        return true;
    }

    @Override
    public void onCreateContextMenu(ContextMenu menu, View v, ContextMenu.ContextMenuInfo info) {
        int pos = ((AdapterView.AdapterContextMenuInfo) info).position;
        menu.setHeaderTitle(shown.get(pos).title());
        getMenuInflater().inflate(R.menu.profile, menu);
    }

    @Override
    public boolean onContextItemSelected(MenuItem item) {
        final Profile p = shown.get(((AdapterView.AdapterContextMenuInfo) item.getMenuInfo()).position);
        final int index = all.indexOf(p);
        int id = item.getItemId();
        if (id == R.id.edit) {
            if (p.sub.length() > 0) {
                Toast.makeText(this, "Сервер из подписки: изменения пропадут при следующем обновлении",
                        Toast.LENGTH_LONG).show();
            }
            Class<?> editor = p.isWg() ? WgEditActivity.class : EditActivity.class;
            startActivity(new Intent(this, editor).putExtra(EditActivity.EXTRA_INDEX, index));
        } else if (id == R.id.copy) {
            ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            cm.setPrimaryClip(ClipData.newPlainText("vless", p.toUri()));
            Toast.makeText(this, "Ссылка скопирована", Toast.LENGTH_SHORT).show();
        } else if (id == R.id.share) {
            Intent s = new Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, p.toUri());
            startActivity(Intent.createChooser(s, p.title()));
        } else if (id == R.id.delete) {
            new AlertDialog.Builder(this)
                    .setTitle(p.title())
                    .setMessage(p.sub.length() > 0
                            ? "Удалить сервер? Он вернётся при следующем обновлении подписки."
                            : "Удалить сервер?")
                    .setNegativeButton(android.R.string.cancel, null)
                    .setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() {
                        public void onClick(DialogInterface d, int w) {
                            all.remove(p);
                            ProfileStore.save(MainActivity.this, all);
                            reload();
                        }
                    })
                    .show();
        } else {
            return super.onContextItemSelected(item);
        }
        return true;
    }

    private void pasteFromClipboard() {
        ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        ClipData clip = cm.getPrimaryClip();
        CharSequence text = clip != null && clip.getItemCount() > 0 ? clip.getItemAt(0).coerceToText(this) : null;
        if (text == null || text.toString().trim().length() == 0) {
            new AlertDialog.Builder(this)
                    .setTitle("Буфер обмена пуст")
                    .setMessage("Скопируйте ссылку vless:// или wireguard://, ключ Amnezia vpn://, конфиг WireGuard/AmneziaWG или ссылку на подписку https://… и нажмите «Вставить» ещё раз.")
                    .setPositiveButton(android.R.string.ok, null)
                    .setNeutralButton(R.string.menu_add_sub, new DialogInterface.OnClickListener() {
                        public void onClick(DialogInterface d, int w) {
                            addSubscription("");
                        }
                    })
                    .show();
            return;
        }
        importText(text.toString());
    }

    private void addSubscription(String url) {
        SubscriptionsActivity.showEditor(this, null, url, new SubscriptionsActivity.Saved() {
            public void onSaved(Subscription s) {
                reload();
                group = s.id;
                updateSubs(Collections.singletonList(s.id), true);
            }
        });
    }

    /**
     * Импорт: ссылка на подписку (http/https), одна или несколько ссылок vless://,
     * либо содержимое подписки в base64.
     */
    private void importText(String text) {
        String t = text.trim();
        if (t.regionMatches(true, 0, "http://", 0, 7) || t.regionMatches(true, 0, "https://", 0, 8)) {
            if (t.split("\\s+").length == 1) {
                for (Subscription s : subs) {
                    if (s.url.equals(t)) {
                        Toast.makeText(this, "Эта подписка уже добавлена, обновляю", Toast.LENGTH_SHORT).show();
                        updateSubs(Collections.singletonList(s.id), true);
                        return;
                    }
                }
                addSubscription(t);
                return;
            }
        }
        SubscriptionUpdater.Parsed parsed = SubscriptionUpdater.parse(t);
        if (!parsed.profiles.isEmpty()) {
            addProfiles(parsed.profiles);
            return;
        }
        showImportError(parsed.firstError != null ? parsed.firstError
                : parsed.skipped > 0 ? "Поддерживаются VLESS, WireGuard и AmneziaWG, а здесь другие протоколы (" + parsed.skipped + ")"
                : "Не нашёл здесь ни серверов, ни ссылки на подписку");
    }

    private void addProfiles(List<Profile> list) {
        int added = 0;
        Profile last = null;
        for (Profile p : list) {
            boolean dup = false;
            for (Profile q : all) if (q.key().equals(p.key())) dup = true;
            if (dup) continue;
            all.add(p);
            last = p;
            added++;
        }
        if (added == 0) {
            Toast.makeText(this, "Эти серверы уже есть в списке", Toast.LENGTH_SHORT).show();
            return;
        }
        ProfileStore.save(this, all);
        if (all.size() == added) ProfileStore.setSelected(this, all.get(0));
        group = GROUP_ALL;
        reload();
        Toast.makeText(this, added == 1 ? "Добавлен " + last.title() : "Добавлено серверов: " + added,
                Toast.LENGTH_SHORT).show();
    }

    private class Adapter extends BaseAdapter {
        public int getCount() {
            return shown.size();
        }

        public Object getItem(int i) {
            return shown.get(i);
        }

        public long getItemId(int i) {
            return i;
        }

        public View getView(int i, View v, ViewGroup parent) {
            if (v == null) v = getLayoutInflater().inflate(R.layout.item_profile, parent, false);
            Profile p = shown.get(i);
            ((TextView) v.findViewById(android.R.id.text1)).setText(p.title());
            String warn = p.unsupportedReason();
            String desc = warn == null ? p.describe() : "[!] " + warn;
            if (GROUP_ALL.equals(group) && p.sub.length() > 0 && subs.size() > 1) {
                Subscription s = ProfileStore.findSub(subs, p.sub);
                if (s != null) desc = s.title() + " · " + desc;
            }
            ((TextView) v.findViewById(android.R.id.text2)).setText(desc);

            TextView delay = (TextView) v.findViewById(R.id.delay);
            if (p.delay == Profile.DELAY_TESTING) {
                delay.setText("…");
                delay.setTextColor(getResources().getColor(android.R.color.darker_gray));
            } else if (p.delay == Profile.DELAY_FAILED) {
                delay.setText("×");
                delay.setTextColor(getResources().getColor(android.R.color.holo_red_light));
            } else if (p.delay > 0) {
                delay.setText(p.delay + " мс");
                delay.setTextColor(getResources().getColor(p.delay < 400 ? android.R.color.holo_green_light
                        : p.delay < 1000 ? android.R.color.holo_orange_light : android.R.color.holo_red_light));
            } else {
                delay.setText("");
            }
            boolean active = p.key().equals(VlessService.activeKey());
            ((RadioButton) v.findViewById(R.id.radio)).setChecked(p.key().equals(selectedKey));
            ((TextView) v.findViewById(android.R.id.text1)).setTextColor(getResources().getColor(
                    active ? android.R.color.holo_blue_light : android.R.color.primary_text_dark));
            return v;
        }
    }
}
