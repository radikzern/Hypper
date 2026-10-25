package com.apo.hypper;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.ListActivity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.DialogInterface;
import android.os.Bundle;
import android.view.ContextMenu;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.Window;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.BaseAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

public class SubscriptionsActivity extends ListActivity {
    private List<Subscription> subs = new ArrayList<Subscription>();
    private final Adapter adapter = new Adapter();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        requestWindowFeature(Window.FEATURE_INDETERMINATE_PROGRESS);
        setContentView(R.layout.activity_subs);
        getActionBar().setDisplayHomeAsUpEnabled(true);
        setListAdapter(adapter);
        registerForContextMenu(getListView());
    }

    @Override
    protected void onResume() {
        super.onResume();
        reload();
    }

    private void reload() {
        subs = ProfileStore.loadSubs(this);
        adapter.notifyDataSetChanged();
    }

    @Override
    protected void onListItemClick(ListView l, View v, int position, long id) {
        update(Collections.singletonList(subs.get(position).id));
    }

    private void update(List<String> ids) {
        if (ids.isEmpty()) return;
        setProgressBarIndeterminateVisibility(true);
        Toast.makeText(this, "Обновление…", Toast.LENGTH_SHORT).show();
        SubscriptionUpdater.updateAsync(this, ids, new SubscriptionUpdater.Done() {
            public void onDone(int ok, String errors) {
                if (isFinishing()) return;
                setProgressBarIndeterminateVisibility(false);
                reload();
                report(SubscriptionsActivity.this, ok, errors);
            }
        });
    }

    static void report(Activity a, int ok, String errors) {
        if (errors.length() == 0) {
            Toast.makeText(a, "Подписки обновлены", Toast.LENGTH_SHORT).show();
        } else {
            new AlertDialog.Builder(a)
                    .setTitle(ok > 0 ? "Обновлены не все подписки" : "Не удалось обновить")
                    .setMessage(errors.contains("ертификат")
                            ? errors + "\n\nЕсли вы доверяете этому серверу — откройте подписку и включите «Не проверять сертификат»."
                            : errors)
                    .setPositiveButton(android.R.string.ok, null)
                    .show();
        }
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.subs, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        int id = item.getItemId();
        if (id == android.R.id.home) {
            finish();
        } else if (id == R.id.add) {
            showEditor(this, null, "", new Saved() {
                public void onSaved(Subscription s) {
                    reload();
                    update(Collections.singletonList(s.id));
                }
            });
        } else if (id == R.id.update_all) {
            List<String> ids = new ArrayList<String>();
            for (Subscription s : subs) ids.add(s.id);
            update(ids);
        } else {
            return super.onOptionsItemSelected(item);
        }
        return true;
    }

    @Override
    public void onCreateContextMenu(ContextMenu menu, View v, ContextMenu.ContextMenuInfo info) {
        int pos = ((AdapterView.AdapterContextMenuInfo) info).position;
        menu.setHeaderTitle(subs.get(pos).title());
        getMenuInflater().inflate(R.menu.sub, menu);
    }

    @Override
    public boolean onContextItemSelected(MenuItem item) {
        final Subscription s = subs.get(((AdapterView.AdapterContextMenuInfo) item.getMenuInfo()).position);
        int id = item.getItemId();
        if (id == R.id.update) {
            update(Collections.singletonList(s.id));
        } else if (id == R.id.edit) {
            showEditor(this, s, "", new Saved() {
                public void onSaved(Subscription saved) {
                    reload();
                }
            });
        } else if (id == R.id.copy) {
            ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            cm.setPrimaryClip(ClipData.newPlainText("subscription", s.url));
            Toast.makeText(this, "Ссылка скопирована", Toast.LENGTH_SHORT).show();
        } else if (id == R.id.delete) {
            new AlertDialog.Builder(this)
                    .setTitle(s.title())
                    .setMessage("Удалить подписку и все её серверы?")
                    .setNegativeButton(android.R.string.cancel, null)
                    .setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() {
                        public void onClick(DialogInterface d, int w) {
                            delete(SubscriptionsActivity.this, s.id);
                            reload();
                        }
                    })
                    .show();
        } else {
            return super.onContextItemSelected(item);
        }
        return true;
    }

    static void delete(Context c, String id) {
        List<Subscription> list = ProfileStore.loadSubs(c);
        for (int i = list.size() - 1; i >= 0; i--) if (list.get(i).id.equals(id)) list.remove(i);
        ProfileStore.saveSubs(c, list);
        ProfileStore.replaceSubProfiles(c, id, new ArrayList<Profile>());
    }

    public interface Saved {
        void onSaved(Subscription s);
    }

    /** Диалог добавления/изменения подписки. existing == null — новая. */
    static void showEditor(final Activity a, final Subscription existing, String presetUrl, final Saved cb) {
        View v = a.getLayoutInflater().inflate(R.layout.dialog_sub, null);
        final EditText url = (EditText) v.findViewById(R.id.url);
        final EditText name = (EditText) v.findViewById(R.id.name);
        final CheckBox insecure = (CheckBox) v.findViewById(R.id.insecure);
        if (existing != null) {
            url.setText(existing.url);
            name.setText(existing.name);
            insecure.setChecked(existing.insecure);
        } else {
            url.setText(presetUrl);
        }
        final AlertDialog d = new AlertDialog.Builder(a)
                .setTitle(existing == null ? "Новая подписка" : existing.title())
                .setView(v)
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton(R.string.menu_save, null)
                .create();
        d.setOnShowListener(new DialogInterface.OnShowListener() {
            public void onShow(DialogInterface di) {
                Button ok = d.getButton(AlertDialog.BUTTON_POSITIVE);
                ok.setOnClickListener(new View.OnClickListener() {
                    public void onClick(View view) {
                        String u = url.getText().toString().trim();
                        if (!u.regionMatches(true, 0, "http://", 0, 7) && !u.regionMatches(true, 0, "https://", 0, 8)) {
                            url.setError("Ссылка должна начинаться с http:// или https://");
                            return;
                        }
                        List<Subscription> list = ProfileStore.loadSubs(a);
                        Subscription s = existing != null ? ProfileStore.findSub(list, existing.id) : null;
                        if (s == null) {
                            s = new Subscription();
                            s.id = UUID.randomUUID().toString();
                            list.add(s);
                        }
                        s.url = u;
                        s.name = name.getText().toString().trim();
                        s.insecure = insecure.isChecked();
                        ProfileStore.saveSubs(a, list);
                        d.dismiss();
                        cb.onSaved(s);
                    }
                });
            }
        });
        d.show();
    }

    private class Adapter extends BaseAdapter {
        public int getCount() {
            return subs.size();
        }

        public Object getItem(int i) {
            return subs.get(i);
        }

        public long getItemId(int i) {
            return i;
        }

        public View getView(int i, View v, ViewGroup parent) {
            if (v == null) v = getLayoutInflater().inflate(R.layout.item_sub, parent, false);
            Subscription s = subs.get(i);
            ((TextView) v.findViewById(android.R.id.text1)).setText(s.title());
            String upd = s.updatedText();
            ((TextView) v.findViewById(android.R.id.text2)).setText(s.describe() + (upd.length() > 0 ? "\n" + upd : ""));
            ((TextView) v.findViewById(R.id.text3)).setText(s.url);
            return v;
        }
    }
}
