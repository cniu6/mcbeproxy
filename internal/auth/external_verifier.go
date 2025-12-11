// Package auth provides authentication functionality.
package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"mcpeserverproxy/internal/logger"
)

// ExternalVerifier handles external authentication verification via HTTP.
type ExternalVerifier struct {
	enabled      bool
	url          string
	cacheMinutes int
	cache        map[string]*cacheEntry
	mu           sync.RWMutex
	client       *http.Client
}

type cacheEntry struct {
	allowed   bool
	reason    string
	expiresAt time.Time
}

// VerifyRequest is the request body sent to the external auth URL.
type VerifyRequest struct {
	XUID       string `json:"xuid"`
	UUID       string `json:"uuid"`
	PlayerName string `json:"player_name"`
	ServerID   string `json:"server_id"`
	ClientIP   string `json:"client_ip"`
	ClientPort string `json:"client_port"`
	Timestamp  int64  `json:"timestamp"`
}

// VerifyResponse is the expected response from the external auth URL.
type VerifyResponse struct {
	Code int    `json:"code"` // 0 or 200 = allowed
	Msg  string `json:"msg"`
	Data any    `json:"data,omitempty"`
}

// NewExternalVerifier creates a new external verifier.
// If enabled is false or url is empty, verification is disabled and all requests are allowed.
func NewExternalVerifier(enabled bool, url string, cacheMinutes int) *ExternalVerifier {
	if cacheMinutes <= 0 {
		cacheMinutes = 15
	}

	return &ExternalVerifier{
		enabled:      enabled,
		url:          url,
		cacheMinutes: cacheMinutes,
		cache:        make(map[string]*cacheEntry),
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// IsEnabled returns true if external verification is enabled.
func (v *ExternalVerifier) IsEnabled() bool {
	return v.enabled && v.url != ""
}

// Verify checks if a player is allowed to connect.
// Returns (allowed, reason).
func (v *ExternalVerifier) Verify(xuid, uuid, gamertag, serverID, clientIP string) (bool, string) {
	if !v.IsEnabled() {
		return true, ""
	}

	// Check cache first
	cacheKey := fmt.Sprintf("%s:%s", xuid, serverID)
	if entry := v.getFromCache(cacheKey); entry != nil {
		return entry.allowed, entry.reason
	}

	// Make HTTP request
	allowed, reason := v.doVerify(xuid, uuid, gamertag, serverID, clientIP)

	// Only cache allowed results (denied results should not be cached)
	if allowed {
		v.addToCache(cacheKey, allowed, reason)
	}

	// Log the result
	logger.LogAuthVerify(gamertag, xuid, serverID, allowed, reason)

	return allowed, reason
}

func (v *ExternalVerifier) getFromCache(key string) *cacheEntry {
	v.mu.RLock()
	defer v.mu.RUnlock()

	entry, ok := v.cache[key]
	if !ok {
		return nil
	}

	if time.Now().After(entry.expiresAt) {
		return nil
	}

	return entry
}

func (v *ExternalVerifier) addToCache(key string, allowed bool, reason string) {
	v.mu.Lock()
	defer v.mu.Unlock()

	v.cache[key] = &cacheEntry{
		allowed:   allowed,
		reason:    reason,
		expiresAt: time.Now().Add(time.Duration(v.cacheMinutes) * time.Minute),
	}
}

func (v *ExternalVerifier) doVerify(xuid, uuid, playerName, serverID, clientAddr string) (bool, string) {
	// Split client address into IP and port
	clientIP := clientAddr
	clientPort := ""
	if idx := strings.LastIndex(clientAddr, ":"); idx != -1 {
		clientIP = clientAddr[:idx]
		clientPort = clientAddr[idx+1:]
	}

	req := VerifyRequest{
		XUID:       xuid,
		UUID:       uuid,
		PlayerName: playerName,
		ServerID:   serverID,
		ClientIP:   clientIP,
		ClientPort: clientPort,
		Timestamp:  time.Now().Unix(),
	}

	body, err := json.Marshal(req)
	if err != nil {
		logger.Error("服务器验证玩家接口请求失败：%v", err)
		return false, "验证服务内部错误，请联系管理员"
	}

	httpReq, err := http.NewRequest("POST", v.url, bytes.NewReader(body))
	if err != nil {
		logger.Error("服务器验证玩家接口请求失败：%v", err)
		return false, "验证服务内部错误，请联系管理员"
	}

	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := v.client.Do(httpReq)
	if err != nil {
		logger.Error("服务器验证玩家接口请求失败：%v：%s", err, string(body))
		return false, "验证服务器无法连接，请稍后再试"
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logger.Error("服务器验证玩家接口请求失败：HTTP %d：%s", resp.StatusCode, string(body))
		return false, fmt.Sprintf("验证服务器返回错误 (HTTP %d)，请稍后再试", resp.StatusCode)
	}

	var verifyResp VerifyResponse
	if err := json.NewDecoder(resp.Body).Decode(&verifyResp); err != nil {
		logger.Error("服务器验证玩家接口请求失败：%v：%s", err, string(body))
		return false, "验证服务器响应格式错误，请联系管理员"
	}

	// Code 0 or 200 means allowed
	allowed := verifyResp.Code == 0 || verifyResp.Code == 200
	return allowed, verifyResp.Msg
}

// ClearCache clears the verification cache.
func (v *ExternalVerifier) ClearCache() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.cache = make(map[string]*cacheEntry)
}

// CleanupExpired removes expired cache entries.
func (v *ExternalVerifier) CleanupExpired() {
	v.mu.Lock()
	defer v.mu.Unlock()

	now := time.Now()
	for key, entry := range v.cache {
		if now.After(entry.expiresAt) {
			delete(v.cache, key)
		}
	}
}
