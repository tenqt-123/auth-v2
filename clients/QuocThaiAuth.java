package com.quocthai.auth;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * ==============================================================================
 * QUỐC THÁI AUTH CLIENT FOR JAVA & ANDROID (Kotlin / Java)
 * Tương thích 100% với hệ thống QuocThaiAuth
 * Zero external JAR dependencies (hoàn toàn dùng thư viện gốc java.net)
 * Hỗ trợ xác thực bằng Mã Key và Tài Khoản / Mật Khẩu
 * ==============================================================================
 */
public class QuocThaiAuth {
    private final String appId;
    private final String baseUrl;
    private String token = "";
    private final String hwid;
    private String numOnlineUsers = "1";

    public QuocThaiAuth(String appId, String baseUrl) {
        this.appId = appId;
        this.baseUrl = baseUrl.replaceAll("/+$", "");
        this.hwid = generateHwid();
    }

    public QuocThaiAuth(String appId) {
        this(appId, "https://quocthaiauth.onrender.com");
    }

    private String generateHwid() {
        try {
            String raw = System.getProperty("os.name") + "_" + System.getProperty("user.name") + "_" + System.getProperty("os.arch");
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(raw.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder("HWID-");
            for (int i = 0; i < 8; i++) {
                sb.append(String.format("%02X", hash[i]));
            }
            return sb.toString();
        } catch (Exception e) {
            return "HWID-JAVA-CLIENT";
        }
    }

    private String postJson(String endpoint, String jsonPayload) throws Exception {
        URL url = new URL(this.baseUrl + "/api/v1/client" + endpoint);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
        conn.setRequestProperty("x-app-id", this.appId);
        conn.setRequestProperty("x-hwid", this.hwid);
        conn.setRequestProperty("User-Agent", "QuocThaiAuth-Java/1.0");
        if (!this.token.isEmpty()) {
            conn.setRequestProperty("Authorization", "Bearer " + this.token);
        }
        conn.setConnectTimeout(10000);
        conn.setReadTimeout(12000);
        conn.setDoOutput(true);

        try (OutputStream os = conn.getOutputStream()) {
            os.write(jsonPayload.getBytes(StandardCharsets.UTF_8));
        }

        int code = conn.getResponseCode();
        BufferedReader reader;
        if (code >= 200 && code < 300) {
            reader = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8));
        } else {
            reader = new BufferedReader(new InputStreamReader(conn.getErrorStream(), StandardCharsets.UTF_8));
        }

        StringBuilder response = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            response.append(line);
        }
        reader.close();
        return response.toString();
    }

    /**
     * 1. Khởi tạo kết nối máy chủ
     */
    public boolean init() {
        try {
            String payload = String.format("{\"appId\":\"%s\",\"hwid\":\"%s\"}", appId, hwid);
            String res = postJson("/init", payload);
            if (res.contains("\"success\":true")) {
                this.token = extractValue(res, "token");
                this.numOnlineUsers = extractValue(res, "numOnlineUsers");
                return true;
            }
        } catch (Exception ignored) {}
        return false;
    }

    /**
     * 2. Xác thực bằng Mã Key Bản Quyền
     */
    public boolean loginKey(String key) {
        try {
            String payload = String.format("{\"key\":\"%s\",\"hwid\":\"%s\",\"appId\":\"%s\"}", key.trim(), hwid, appId);
            String res = postJson("/login", payload);
            if (res.contains("\"success\":true")) {
                this.token = extractValue(res, "token");
                return true;
            }
        } catch (Exception ignored) {}
        return false;
    }

    /**
     * 3. Xác thực bằng Tài Khoản & Mật Khẩu
     */
    public boolean loginUser(String username, String password) {
        try {
            String payload = String.format("{\"username\":\"%s\",\"password\":\"%s\",\"hwid\":\"%s\",\"appId\":\"%s\"}",
                    username.trim(), password.trim(), hwid, appId);
            String res = postJson("/login-user", payload);
            if (res.contains("\"success\":true")) {
                this.token = extractValue(res, "token");
                return true;
            }
        } catch (Exception ignored) {}
        return false;
    }

    /**
     * 4. Heartbeat session check
     */
    public boolean check() {
        try {
            String payload = String.format("{\"appId\":\"%s\",\"hwid\":\"%s\"}", appId, hwid);
            String res = postJson("/check", payload);
            return res.contains("\"success\":true");
        } catch (Exception ignored) {
            return false;
        }
    }

    public String getHwid() { return this.hwid; }
    public String getNumOnlineUsers() { return this.numOnlineUsers; }

    private String extractValue(String json, String key) {
        String pattern = "\"" + key + "\":\"";
        int idx = json.indexOf(pattern);
        if (idx == -1) return "";
        idx += pattern.length();
        int end = json.indexOf("\"", idx);
        return end != -1 ? json.substring(idx, end) : "";
    }
}
