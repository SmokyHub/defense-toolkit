package com.apkdefense.fixture.webview;

import android.app.Activity;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.webkit.WebView;
import android.widget.Button;
import android.widget.LinearLayout;
import android.view.ViewGroup;

/** Benign response-loader test entry. Merge with the original fixture DEX. */
public class ResponseEntry {
    public void run(final Activity host) {
        Log.i("APKDefenseFixture", "ENTRY_CALLED host=" + host.getPackageName()
                + " loader=" + getClass().getClassLoader()
                + " originalFixture=" + MainActivity.class.getName());
        // Let the host finish attaching its initial Flutter view before showing the test UI.
        new Handler(Looper.getMainLooper()).postDelayed(new Runnable() {
            @Override public void run() {
                LinearLayout layout = new LinearLayout(host);
                layout.setOrientation(LinearLayout.VERTICAL);
                layout.setBackgroundColor(0xffffffff);
                // Keep the local test controls clear of edge-to-edge system bars.
                int barPadding = (int) (64 * host.getResources().getDisplayMetrics().density);
                layout.setPadding(0, barPadding, 0, barPadding);
                WebView view = new WebView(host);
                view.loadData("<html><body><h1>APK Defense: DEX executed</h1>"
                        + "<p>Response-provided code is running inside " + host.getPackageName()
                        + ".</p><p>This page is local and makes no network requests.</p></body></html>",
                        "text/html", "UTF-8");
                layout.addView(view, new LinearLayout.LayoutParams(-1, 0, 1));
                Button button = new Button(host);
                button.setText("Test added functionality");
                button.setOnClickListener(v -> {
                    button.setText("DEX button handler executed");
                    Log.i("APKDefenseFixture", "BUTTON_EXECUTED host=" + host.getPackageName());
                });
                layout.addView(button);
                // Preserve Flutter's attached view and its accessibility callbacks.
                host.addContentView(layout, new ViewGroup.LayoutParams(-1, -1));
                Log.i("APKDefenseFixture", "UI_INSTALLED host=" + host.getPackageName());
            }
        }, 3000);
    }
}
