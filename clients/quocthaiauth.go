package quocthaiauth

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"
)

// ==============================================================================
// QUỐC THÁI AUTH CLIENT FOR GO (GOLANG)
// Tương thích 100% với server QuocThaiAuth
// Hỗ trợ cả 2 phương thức xác thực:
//   1. Xác thực bằng Mã Key: client.LoginKey("VIET-VIP-...")
//   2. Xác thực bằng User/Pass: client.LoginUser("username", "password")
// Zero external packages (chỉ sử dụng thư viện chuẩn của Go)
// ==============================================================================

type Client struct {
	AppID       string
	BaseURL     string
	HWID        string
	Token       string
	OnlineUsers string
	httpClient  *http.Client
}

type AuthResponse struct {
	Success        bool   `json:"success"`
	Message        string `json:"message"`
	Error          string `json:"error"`
	Token          string `json:"token"`
	Subscription   string `json:"subscription"`
	ExpiresAt      string `json:"expiresAt"`
	HWID           string `json:"hwid"`
	NumOnlineUsers string `json:"numOnlineUsers"`
}

func New(appID string, baseURL ...string) *Client {
	url := "https://quocthaiauth.onrender.com"
	if len(baseURL) > 0 && baseURL[0] != "" {
		url = strings.TrimRight(baseURL[0], "/")
	}

	c := &Client{
		AppID:   appID,
		BaseURL: url,
		httpClient: &http.Client{
			Timeout: 12 * time.Second,
		},
	}
	c.HWID = c.generateHWID()
	return c
}

func (c *Client) generateHWID() string {
	raw := fmt.Sprintf("%s_%s_%s", runtime.GOOS, runtime.GOARCH, os.Getenv("USERNAME"))
	hash := sha256.Sum256([]byte(raw))
	return "HWID-" + strings.ToUpper(hex.EncodeToString(hash[:8]))
}

func (c *Client) post(endpoint string, payload interface{}) (*AuthResponse, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", c.BaseURL+"/api/v1/client"+endpoint, bytes.NewBuffer(data))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-app-id", c.AppID)
	req.Header.Set("x-hwid", c.HWID)
	req.Header.Set("User-Agent", "QuocThaiAuth-Go/1.0")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	if result.Token != "" {
		c.Token = result.Token
	}
	if result.NumOnlineUsers != "" {
		c.OnlineUsers = result.NumOnlineUsers
	}

	return &result, nil
}

// 1. Khởi tạo kết nối hệ thống
func (c *Client) Init() (*AuthResponse, error) {
	return c.post("/init", map[string]string{
		"appId": c.AppID,
		"hwid":  c.HWID,
	})
}

// 2. Xác thực bằng Mã Key Bản Quyền
func (c *Client) LoginKey(licenseKey string) (*AuthResponse, error) {
	return c.post("/login", map[string]string{
		"key":   strings.TrimSpace(licenseKey),
		"hwid":  c.HWID,
		"appId": c.AppID,
	})
}

// 3. Xác thực bằng Tài Khoản & Mật Khẩu
func (c *Client) LoginUser(username, password string) (*AuthResponse, error) {
	return c.post("/login-user", map[string]string{
		"username": strings.TrimSpace(username),
		"password": strings.TrimSpace(password),
		"hwid":     c.HWID,
		"appId":    c.AppID,
	})
}

// 4. Gửi heartbeat duy trì session
func (c *Client) Check() bool {
	res, err := c.post("/check", map[string]string{
		"appId": c.AppID,
		"hwid":  c.HWID,
	})
	return err == nil && res.Success
}
