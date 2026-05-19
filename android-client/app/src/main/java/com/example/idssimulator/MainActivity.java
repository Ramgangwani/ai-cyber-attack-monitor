package com.example.idssimulator;

import android.app.Activity;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.CookieHandler;
import java.net.CookieManager;
import java.net.HttpCookie;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends Activity {
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private CookieManager cookieManager;
    private EditText serverUrl;
    private EditText username;
    private EditText password;
    private TextView statusText;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        cookieManager = new CookieManager();
        CookieHandler.setDefault(cookieManager);

        serverUrl = findViewById(R.id.serverUrl);
        username = findViewById(R.id.username);
        password = findViewById(R.id.password);
        statusText = findViewById(R.id.statusText);

        Button loginButton = findViewById(R.id.loginButton);
        Button dosButton = findViewById(R.id.dosButton);
        Button loginAttemptButton = findViewById(R.id.loginAttemptButton);
        Button scanButton = findViewById(R.id.scanButton);
        Button normalButton = findViewById(R.id.normalButton);

        loginButton.setOnClickListener(view -> login());
        dosButton.setOnClickListener(view -> sendPattern("DoS-like burst", buildDosLikeBurst()));
        loginAttemptButton.setOnClickListener(view -> sendPattern("Repeated login attempts", buildRepeatedLoginAttempts()));
        scanButton.setOnClickListener(view -> sendPattern("Network scan", buildNetworkScan()));
        normalButton.setOnClickListener(view -> sendPattern("Normal traffic", buildNormalTraffic()));
    }

    private void login() {
        setStatus("Logging in...");
        executor.execute(() -> {
            try {
                String body = "username=" + encode(username.getText().toString())
                        + "&password=" + encode(password.getText().toString());
                HttpResult result = request(
                        normalizedBaseUrl() + "/login",
                        "POST",
                        "application/x-www-form-urlencoded",
                        body
                );
                if (result.code >= 200 && result.code < 400 && hasSessionCookie()) {
                    setStatus("Login successful. Ready to send safe simulations.");
                } else {
                    setStatus("Login failed. HTTP " + result.code + "\n" + result.body);
                }
            } catch (Exception error) {
                setStatus("Login error: " + error.getMessage());
            }
        });
    }

    private void sendPattern(String name, JSONObject payload) {
        setStatus("Sending " + name + " simulation...");
        executor.execute(() -> {
            try {
                if (!hasSessionCookie()) {
                    loginBlocking();
                }
                HttpResult result = request(
                        normalizedBaseUrl() + "/api/predict",
                        "POST",
                        "application/json",
                        payload.toString()
                );
                setStatus(name + " result\nHTTP " + result.code + "\n" + result.body);
            } catch (Exception error) {
                setStatus("Send error: " + error.getMessage());
            }
        });
    }

    private void loginBlocking() throws IOException {
        String body = "username=" + encode(username.getText().toString())
                + "&password=" + encode(password.getText().toString());
        request(normalizedBaseUrl() + "/login", "POST", "application/x-www-form-urlencoded", body);
        if (!hasSessionCookie()) {
            throw new IOException("Flask login did not create a session cookie.");
        }
    }

    private HttpResult request(String urlText, String method, String contentType, String body) throws IOException {
        HttpURLConnection connection = (HttpURLConnection) new URL(urlText).openConnection();
        connection.setRequestMethod(method);
        connection.setInstanceFollowRedirects(false);
        connection.setConnectTimeout(10000);
        connection.setReadTimeout(10000);

        if (body != null) {
            byte[] payload = body.getBytes(StandardCharsets.UTF_8);
            connection.setDoOutput(true);
            connection.setRequestProperty("Content-Type", contentType);
            connection.setRequestProperty("Content-Length", String.valueOf(payload.length));
            try (OutputStream stream = connection.getOutputStream()) {
                stream.write(payload);
            }
        }

        int code = connection.getResponseCode();
        String responseBody = readBody(code >= 400 ? connection.getErrorStream() : connection.getInputStream());
        connection.disconnect();
        return new HttpResult(code, responseBody);
    }

    private boolean hasSessionCookie() {
        try {
            List<HttpCookie> cookies = cookieManager.getCookieStore().get(new URI(normalizedBaseUrl()));
            for (HttpCookie cookie : cookies) {
                if ("session".equals(cookie.getName())) {
                    return true;
                }
            }
        } catch (Exception ignored) {
            return false;
        }
        return false;
    }

    private String readBody(InputStream stream) throws IOException {
        if (stream == null) {
            return "";
        }
        StringBuilder builder = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                builder.append(line).append('\n');
            }
        }
        return builder.toString().trim();
    }

    private String normalizedBaseUrl() {
        String value = serverUrl.getText().toString().trim();
        while (value.endsWith("/")) {
            value = value.substring(0, value.length() - 1);
        }
        return value;
    }

    private String encode(String value) throws IOException {
        return URLEncoder.encode(value, "UTF-8");
    }

    private void setStatus(String value) {
        mainHandler.post(() -> statusText.setText(value));
    }

    private JSONObject buildDosLikeBurst() {
        JSONObject record = baseNslKddRecord();
        put(record, "protocol_type", "tcp");
        put(record, "service", "private");
        put(record, "flag", "S0");
        put(record, "src_bytes", 0);
        put(record, "dst_bytes", 0);
        put(record, "count", 240);
        put(record, "srv_count", 12);
        put(record, "serror_rate", 1.0);
        put(record, "srv_serror_rate", 1.0);
        put(record, "same_srv_rate", 0.04);
        put(record, "diff_srv_rate", 0.07);
        put(record, "dst_host_count", 255);
        put(record, "dst_host_srv_count", 12);
        put(record, "dst_host_serror_rate", 1.0);
        put(record, "dst_host_srv_serror_rate", 1.0);
        return record;
    }

    private JSONObject buildRepeatedLoginAttempts() {
        JSONObject record = baseNslKddRecord();
        put(record, "protocol_type", "tcp");
        put(record, "service", "ftp");
        put(record, "flag", "SF");
        put(record, "src_bytes", 120);
        put(record, "dst_bytes", 80);
        put(record, "hot", 6);
        put(record, "num_failed_logins", 12);
        put(record, "logged_in", 0);
        put(record, "count", 42);
        put(record, "srv_count", 8);
        put(record, "dst_host_count", 120);
        put(record, "dst_host_srv_count", 8);
        return record;
    }

    private JSONObject buildNetworkScan() {
        JSONObject record = baseNslKddRecord();
        put(record, "protocol_type", "tcp");
        put(record, "service", "private");
        put(record, "flag", "REJ");
        put(record, "src_bytes", 40);
        put(record, "dst_bytes", 0);
        put(record, "count", 180);
        put(record, "srv_count", 3);
        put(record, "rerror_rate", 1.0);
        put(record, "srv_rerror_rate", 1.0);
        put(record, "same_srv_rate", 0.02);
        put(record, "diff_srv_rate", 0.80);
        put(record, "dst_host_count", 255);
        put(record, "dst_host_srv_count", 3);
        put(record, "dst_host_rerror_rate", 1.0);
        put(record, "dst_host_srv_rerror_rate", 1.0);
        return record;
    }

    private JSONObject buildNormalTraffic() {
        JSONObject record = baseNslKddRecord();
        put(record, "protocol_type", "tcp");
        put(record, "service", "http");
        put(record, "flag", "SF");
        put(record, "src_bytes", 181);
        put(record, "dst_bytes", 5450);
        put(record, "logged_in", 1);
        put(record, "count", 8);
        put(record, "srv_count", 8);
        put(record, "same_srv_rate", 1.0);
        put(record, "dst_host_count", 9);
        put(record, "dst_host_srv_count", 9);
        put(record, "dst_host_same_srv_rate", 1.0);
        put(record, "dst_host_same_src_port_rate", 0.11);
        return record;
    }

    private JSONObject baseNslKddRecord() {
        JSONObject record = new JSONObject();
        try {
            record.put("duration", 0);
            record.put("protocol_type", "tcp");
            record.put("service", "private");
            record.put("flag", "SF");
            record.put("src_bytes", 0);
            record.put("dst_bytes", 0);
            record.put("land", 0);
            record.put("wrong_fragment", 0);
            record.put("urgent", 0);
            record.put("hot", 0);
            record.put("num_failed_logins", 0);
            record.put("logged_in", 0);
            record.put("num_compromised", 0);
            record.put("root_shell", 0);
            record.put("su_attempted", 0);
            record.put("num_root", 0);
            record.put("num_file_creations", 0);
            record.put("num_shells", 0);
            record.put("num_access_files", 0);
            record.put("num_outbound_cmds", 0);
            record.put("is_host_login", 0);
            record.put("is_guest_login", 0);
            record.put("count", 1);
            record.put("srv_count", 1);
            record.put("serror_rate", 0.0);
            record.put("srv_serror_rate", 0.0);
            record.put("rerror_rate", 0.0);
            record.put("srv_rerror_rate", 0.0);
            record.put("same_srv_rate", 1.0);
            record.put("diff_srv_rate", 0.0);
            record.put("srv_diff_host_rate", 0.0);
            record.put("dst_host_count", 1);
            record.put("dst_host_srv_count", 1);
            record.put("dst_host_same_srv_rate", 1.0);
            record.put("dst_host_diff_srv_rate", 0.0);
            record.put("dst_host_same_src_port_rate", 0.0);
            record.put("dst_host_srv_diff_host_rate", 0.0);
            record.put("dst_host_serror_rate", 0.0);
            record.put("dst_host_srv_serror_rate", 0.0);
            record.put("dst_host_rerror_rate", 0.0);
            record.put("dst_host_srv_rerror_rate", 0.0);
        } catch (JSONException error) {
            throw new IllegalStateException(error);
        }
        return record;
    }

    private void put(JSONObject record, String key, Object value) {
        try {
            record.put(key, value);
        } catch (JSONException error) {
            throw new IllegalStateException(error);
        }
    }

    private static class HttpResult {
        final int code;
        final String body;

        HttpResult(int code, String body) {
            this.code = code;
            this.body = body;
        }
    }
}
