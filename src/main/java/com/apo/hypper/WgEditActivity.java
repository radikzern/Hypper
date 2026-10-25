package com.apo.hypper;

import android.app.Activity;
import android.app.AlertDialog;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.EditText;
import android.widget.TextView;

import com.apo.hypper.net.wg.WgConfig;

import java.util.List;

/** Редактор WireGuard / AmneziaWG: текст конфигурации в формате .conf. */
public class WgEditActivity extends Activity {
    private static final String TEMPLATE = "[Interface]\n"
            + "PrivateKey = \n"
            + "Address = 10.0.0.2/32\n"
            + "DNS = 1.1.1.1\n"
            + "# Для AmneziaWG добавьте Jc, Jmin, Jmax, S1, S2, H1–H4 (и I1–I5 для AWG 2.0)\n"
            + "\n[Peer]\n"
            + "PublicKey = \n"
            + "Endpoint = example.com:51820\n"
            + "AllowedIPs = 0.0.0.0/0\n"
            + "PersistentKeepalive = 25\n";

    private int index;
    private List<Profile> profiles;
    private Profile profile;
    private EditText name, conf;
    private TextView pubkey;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_wg_edit);
        getActionBar().setDisplayHomeAsUpEnabled(true);
        name = (EditText) findViewById(R.id.name);
        conf = (EditText) findViewById(R.id.conf);
        pubkey = (TextView) findViewById(R.id.pubkey);

        profiles = ProfileStore.load(this);
        index = getIntent().getIntExtra(EditActivity.EXTRA_INDEX, -1);
        if (index >= 0 && index < profiles.size() && profiles.get(index).isWg()) {
            profile = profiles.get(index);
            setTitle(profile.title());
        } else {
            index = -1;
            setTitle("Новый WireGuard");
        }
        if (savedInstanceState == null) {
            if (profile != null) {
                name.setText(profile.name);
                conf.setText(profile.wg.toConf());
            } else {
                conf.setText(TEMPLATE);
            }
        }
        conf.addTextChangedListener(new TextWatcher() {
            public void beforeTextChanged(CharSequence s, int a, int b, int c) {
            }

            public void onTextChanged(CharSequence s, int a, int b, int c) {
            }

            public void afterTextChanged(Editable s) {
                updatePubkey();
            }
        });
        updatePubkey();
    }

    private String privateKey() {
        for (String line : conf.getText().toString().split("\n")) {
            String t = line.trim();
            if (t.toLowerCase().startsWith("privatekey")) {
                int eq = t.indexOf('=');
                if (eq > 0) return t.substring(eq + 1).trim();
            }
        }
        return "";
    }

    private void updatePubkey() {
        String pub = WgConfig.publicFor(privateKey());
        pubkey.setText(pub == null ? "" : "Ваш публичный ключ (добавьте его на сервер):\n" + pub);
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.wg_edit, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        int id = item.getItemId();
        if (id == android.R.id.home) {
            finish();
        } else if (id == R.id.save) {
            save();
        } else if (id == R.id.keygen) {
            String[] kp = WgConfig.generateKeyPair();
            String text = conf.getText().toString();
            String replaced = text.replaceFirst("(?im)^(\\s*PrivateKey\\s*=).*$", "$1 " + java.util.regex.Matcher.quoteReplacement(kp[0]));
            conf.setText(replaced.equals(text) && !text.contains(kp[0]) ? "[Interface]\nPrivateKey = " + kp[0] + "\n" + text : replaced);
        } else {
            return super.onOptionsItemSelected(item);
        }
        return true;
    }

    private void save() {
        WgConfig c;
        try {
            c = WgConfig.parseConf(conf.getText().toString());
        } catch (IllegalArgumentException e) {
            new AlertDialog.Builder(this)
                    .setTitle("Ошибка в конфигурации")
                    .setMessage(e.getMessage())
                    .setPositiveButton(android.R.string.ok, null)
                    .show();
            return;
        }
        Profile p = Profile.fromWg(c, name.getText().toString().trim());
        if (profile != null) p.sub = profile.sub;
        if (index >= 0) profiles.set(index, p);
        else profiles.add(p);
        ProfileStore.save(this, profiles);
        finish();
    }
}
