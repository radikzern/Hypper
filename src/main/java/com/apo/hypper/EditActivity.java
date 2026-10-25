package com.apo.hypper;

import android.app.Activity;
import android.app.AlertDialog;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.AdapterView;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.TextView;

import java.util.List;

public class EditActivity extends Activity {
    public static final String EXTRA_INDEX = "index";

    private int index;
    private List<Profile> profiles;
    private Profile profile;
    private EditText name, address, port, uuid, path, wsHost, sni, pbk, sid, fp, spx;
    private Spinner network, security;
    private CheckBox insecure;
    private View wsGroup, tlsGroup, realityGroup;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_edit);
        getActionBar().setDisplayHomeAsUpEnabled(true);

        name = (EditText) findViewById(R.id.name);
        address = (EditText) findViewById(R.id.address);
        port = (EditText) findViewById(R.id.port);
        uuid = (EditText) findViewById(R.id.uuid);
        path = (EditText) findViewById(R.id.path);
        wsHost = (EditText) findViewById(R.id.ws_host);
        sni = (EditText) findViewById(R.id.sni);
        pbk = (EditText) findViewById(R.id.pbk);
        sid = (EditText) findViewById(R.id.sid);
        fp = (EditText) findViewById(R.id.fp);
        spx = (EditText) findViewById(R.id.spx);
        network = (Spinner) findViewById(R.id.network);
        security = (Spinner) findViewById(R.id.security);
        insecure = (CheckBox) findViewById(R.id.insecure);
        wsGroup = findViewById(R.id.ws_group);
        tlsGroup = findViewById(R.id.tls_group);
        realityGroup = findViewById(R.id.reality_group);

        profiles = ProfileStore.load(this);
        index = getIntent().getIntExtra(EXTRA_INDEX, -1);
        if (index >= 0 && index < profiles.size()) {
            profile = profiles.get(index);
            setTitle(profile.title());
        } else {
            index = -1;
            profile = new Profile();
            setTitle("Новый сервер");
        }

        if (savedInstanceState == null) {
            name.setText(profile.name);
            address.setText(profile.address);
            port.setText(String.valueOf(profile.port));
            uuid.setText(profile.uuid);
            path.setText(profile.path);
            wsHost.setText(profile.wsHost);
            sni.setText(profile.sni);
            pbk.setText(profile.publicKey);
            sid.setText(profile.shortId);
            fp.setText(profile.fingerprint);
            spx.setText(profile.spiderX);
            insecure.setChecked(profile.insecure);
            network.setSelection(Profile.NET_WS.equals(profile.network) ? 1 : 0);
            security.setSelection(Profile.SEC_REALITY.equals(profile.security) ? 2
                    : Profile.SEC_TLS.equals(profile.security) ? 1 : 0);
        }
        String warn = profile.unsupportedReason();
        if (warn != null) {
            TextView w = (TextView) findViewById(R.id.warning);
            w.setText("Профиль импортирован с параметром, который не поддерживается: " + warn
                    + ". При сохранении он будет сброшен.");
            w.setVisibility(View.VISIBLE);
        }

        AdapterView.OnItemSelectedListener l = new AdapterView.OnItemSelectedListener() {
            public void onItemSelected(AdapterView<?> parent, View view, int pos, long id) {
                updateGroups();
            }

            public void onNothingSelected(AdapterView<?> parent) {
            }
        };
        network.setOnItemSelectedListener(l);
        security.setOnItemSelectedListener(l);
        updateGroups();
    }

    private void updateGroups() {
        int sec = security.getSelectedItemPosition();
        wsGroup.setVisibility(network.getSelectedItemPosition() == 1 ? View.VISIBLE : View.GONE);
        sni.setVisibility(sec == 0 ? View.GONE : View.VISIBLE);
        tlsGroup.setVisibility(sec == 1 ? View.VISIBLE : View.GONE);
        realityGroup.setVisibility(sec == 2 ? View.VISIBLE : View.GONE);
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.edit, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        if (item.getItemId() == android.R.id.home) {
            finish();
            return true;
        }
        if (item.getItemId() == R.id.save) {
            save();
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    private void save() {
        Profile p = new Profile();
        p.name = text(name);
        p.address = text(address);
        try {
            p.port = Integer.parseInt(text(port));
        } catch (NumberFormatException e) {
            p.port = 0;
        }
        p.uuid = text(uuid);
        p.network = network.getSelectedItemPosition() == 1 ? Profile.NET_WS : Profile.NET_TCP;
        p.path = text(path).length() > 0 ? text(path) : "/";
        p.wsHost = text(wsHost);
        int sec = security.getSelectedItemPosition();
        p.security = sec == 2 ? Profile.SEC_REALITY : sec == 1 ? Profile.SEC_TLS : Profile.SEC_NONE;
        p.sni = text(sni);
        p.insecure = insecure.isChecked();
        if (Profile.SEC_REALITY.equals(p.security)) {
            p.publicKey = text(pbk);
            p.shortId = text(sid);
            p.fingerprint = text(fp);
            p.spiderX = text(spx);
        }
        // flow не редактируется в UI; сохраняем, если он поддерживается с выбранными параметрами
        Profile probe = new Profile();
        probe.flow = profile.flow;
        probe.network = p.network;
        probe.security = p.security;
        if (profile.flow.length() > 0 && probe.unsupportedReason() == null) p.flow = profile.flow;
        p.sub = profile.sub;
        try {
            p.validate();
        } catch (IllegalArgumentException e) {
            new AlertDialog.Builder(this)
                    .setTitle("Ошибка")
                    .setMessage(e.getMessage())
                    .setPositiveButton(android.R.string.ok, null)
                    .show();
            return;
        }
        if (index >= 0) profiles.set(index, p);
        else profiles.add(p);
        ProfileStore.save(this, profiles);
        finish();
    }

    private static String text(EditText e) {
        return e.getText().toString().trim();
    }
}
