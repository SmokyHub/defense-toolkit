package com.apkdefense.fixture.webview;

import android.app.Activity;
import android.os.Bundle;
import android.webkit.WebView;
import android.webkit.WebViewClient;

public class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        WebView webView = new WebView(this);
        webView.getSettings().setJavaScriptEnabled(true);
        // Keep navigation inside the WebView instead of handing links to the system browser.
        webView.setWebViewClient(new WebViewClient());
        setContentView(webView);
        webView.loadUrl("https://www.google.com");
    }
}
