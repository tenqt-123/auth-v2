/**
 * ==============================================================================
 * QUỐC THÁI AUTH CLIENT FOR JAVASCRIPT / NODE.JS / ELECTRON / BROWSER
 * Tương thích hoàn toàn với server QuocThaiAuth
 * Hỗ trợ 2 phương thức xác thực:
 *   1. Mã Key Bản Quyền: auth.loginKey("VIET-VIP-XXXX-XXXX-XXXX")
 *   2. Tài Khoản & Mật Khẩu: auth.loginUser("username", "password")
 * Zero dependencies (sử dụng fetch chuẩn có sẵn trong Node.js 18+ và Trình duyệt)
 * ==============================================================================
 */

const isNode = typeof process !== 'undefined' && process.versions != null && process.versions.node != null;

class QuocThaiAuthClient {
  /**
   * @param {string} appId - App ID (Public Key) lấy từ web QuocThaiAuth
   * @param {string} baseUrl - Địa chỉ server, mặc định https://quocthaiauth.onrender.com
   */
  constructor(appId, baseUrl = 'https://quocthaiauth.onrender.com') {
    this.appId = appId;
    this.baseUrl = baseUrl.replace(/\/+$/, '');
    this.token = '';
    this.hwid = this.getMachineHwid();
    this.onlineUsers = '1';
    this.userData = null;
  }

  /**
   * Sinh mã phần cứng định danh thiết bị
   */
  getMachineHwid() {
    if (isNode) {
      try {
        const os = require('os');
        const crypto = require('crypto');
        const raw = `${os.hostname()}_${os.platform()}_${os.arch()}_${os.cpus()[0]?.model || ''}`;
        return 'HWID-' + crypto.createHash('sha256').update(raw).digest('hex').substring(0, 16).toUpperCase();
      } catch (e) {
        return 'HWID-NODE-CLIENT';
      }
    } else {
      let saved = localStorage.getItem('quocthai_auth_hwid');
      if (!saved) {
        saved = 'HWID-WEB-' + Math.random().toString(36).substring(2, 10).toUpperCase();
        localStorage.setItem('quocthai_auth_hwid', saved);
      }
      return saved;
    }
  }

  async _post(path, payload) {
    const url = `${this.baseUrl}/api/v1/client${path}`;
    const headers = {
      'Content-Type': 'application/json',
      'x-app-id': this.appId,
      'x-hwid': this.hwid,
      'User-Agent': 'QuocThaiAuth-JS/1.0'
    };

    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }

    try {
      const res = await fetch(url, {
        method: 'POST',
        headers,
        body: JSON.stringify(payload)
      });
      return await res.json();
    } catch (err) {
      return { success: false, error: 'Không thể kết nối tới máy chủ: ' + err.message };
    }
  }

  /**
   * 1. Khởi tạo kết nối hệ thống
   */
  async init() {
    const res = await this._post('/init', { appId: this.appId, hwid: this.hwid });
    if (res.success) {
      this.token = res.token || '';
      this.onlineUsers = String(res.numOnlineUsers || '1');
      return { success: true, numOnlineUsers: this.onlineUsers, version: res.version };
    }
    return { success: false, error: res.error || 'Lỗi khởi tạo' };
  }

  /**
   * 2. Xác thực bằng Mã Key Bản Quyền
   */
  async loginKey(key) {
    const res = await this._post('/login', {
      key: key.trim(),
      hwid: this.hwid,
      appId: this.appId
    });
    if (res.success) {
      this.token = res.token || '';
      this.onlineUsers = String(res.numOnlineUsers || '1');
      this.userData = res;
      return {
        success: true,
        subscription: res.subscription || 'VIP',
        expiresAt: res.expiresAt,
        hwid: res.hwid || this.hwid,
        onlineUsers: this.onlineUsers
      };
    }
    return { success: false, error: res.error || 'Xác thực key thất bại' };
  }

  /**
   * 3. Xác thực bằng Tài Khoản & Mật Khẩu
   */
  async loginUser(username, password) {
    const res = await this._post('/login-user', {
      username: username.trim(),
      password: password.trim(),
      hwid: this.hwid,
      appId: this.appId
    });
    if (res.success) {
      this.token = res.token || '';
      this.onlineUsers = String(res.numOnlineUsers || '1');
      this.userData = res;
      return {
        success: true,
        username: res.username || username,
        subscription: res.subscription || 'VIP',
        expiresAt: res.expiresAt,
        hwid: res.hwid || this.hwid
      };
    }
    return { success: false, error: res.error || 'Sai tài khoản hoặc mật khẩu' };
  }

  /**
   * 4. Gửi heartbeat kiểm tra session
   */
  async check() {
    const res = await this._post('/check', { appId: this.appId, hwid: this.hwid });
    return res.success === true;
  }

  /**
   * 5. Lấy biến từ xa
   */
  async getVariable(varName) {
    const res = await this._post('/var', { varId: varName, appId: this.appId });
    if (res.success) return res.response || res.value;
    return null;
  }
}

// Export cho CommonJS (Node.js) & Browser
if (typeof module !== 'undefined' && module.exports) {
  module.exports = QuocThaiAuthClient;
}
if (typeof window !== 'undefined') {
  window.QuocThaiAuthClient = QuocThaiAuthClient;
}
