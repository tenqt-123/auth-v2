<?php
/**
 * ==============================================================================
 * QUỐC THÁI AUTH CLIENT FOR PHP
 * Tương thích 100% với hệ thống QuocThaiAuth
 * Hỗ trợ xác thực bằng Mã Key và Tài Khoản / Mật Khẩu
 * ==============================================================================
 */

class QuocThaiAuthClient {
    private $appId;
    private $baseUrl;
    private $token = "";
    private $hwid;
    private $onlineUsers = "1";

    public function __construct($appId, $baseUrl = "https://quocthaiauth.onrender.com") {
        $this->appId = $appId;
        $this->baseUrl = rtrim($baseUrl, "/");
        $this->hwid = $this->generateHwid();
    }

    private function generateHwid() {
        $serverInfo = php_uname('n') . '_' . php_uname('m') . '_' . get_current_user();
        return "HWID-" . strtoupper(substr(hash('sha256', $serverInfo), 0, 16));
    }

    private function post($endpoint, $payload = []) {
        $url = $this->baseUrl . "/api/v1/client" . $endpoint;
        $ch = curl_init($url);
        $headers = [
            'Content-Type: application/json',
            'x-app-id: ' . $this->appId,
            'x-hwid: ' . $this->hwid,
            'User-Agent: QuocThaiAuth-PHP/1.0'
        ];
        if (!empty($this->token)) {
            $headers[] = 'Authorization: Bearer ' . $this->token;
        }

        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($payload));
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_TIMEOUT, 12);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);

        $response = curl_exec($ch);
        $err = curl_error($ch);
        curl_close($ch);

        if ($err) {
            return ['success' => false, 'error' => 'Lỗi cURL: ' . $err];
        }

        $json = json_decode($response, true);
        return is_array($json) ? $json : ['success' => false, 'error' => 'Phản hồi không hợp lệ'];
    }

    /**
     * 1. Khởi tạo kết nối hệ thống
     */
    public function init() {
        $res = $this->post('/init', ['appId' => $this->appId, 'hwid' => $this->hwid]);
        if (!empty($res['success'])) {
            $this->token = $res['token'] ?? '';
            $this->onlineUsers = (string)($res['numOnlineUsers'] ?? '1');
            return true;
        }
        return false;
    }

    /**
     * 2. Xác thực bằng Mã Key Bản Quyền
     */
    public function loginKey($key) {
        $res = $this->post('/login', [
            'key' => trim($key),
            'hwid' => $this->hwid,
            'appId' => $this->appId
        ]);
        if (!empty($res['success'])) {
            $this->token = $res['token'] ?? '';
            $this->onlineUsers = (string)($res['numOnlineUsers'] ?? '1');
            return $res;
        }
        return $res;
    }

    /**
     * 3. Xác thực bằng Tài Khoản & Mật Khẩu
     */
    public function loginUser($username, $password) {
        $res = $this->post('/login-user', [
            'username' => trim($username),
            'password' => trim($password),
            'hwid' => $this->hwid,
            'appId' => $this->appId
        ]);
        if (!empty($res['success'])) {
            $this->token = $res['token'] ?? '';
            $this->onlineUsers = (string)($res['numOnlineUsers'] ?? '1');
            return $res;
        }
        return $res;
    }

    /**
     * 4. Gửi heartbeat kiểm tra session
     */
    public function check() {
        $res = $this->post('/check', ['appId' => $this->appId, 'hwid' => $this->hwid]);
        return !empty($res['success']);
    }

    public function getHwid() { return $this->hwid; }
    public function getOnlineUsers() { return $this->onlineUsers; }
}
?>
