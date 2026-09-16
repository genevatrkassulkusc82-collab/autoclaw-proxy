package main

// ---- 双认证体系（对齐 minimax-2api/dumate-proxy 模式）----
//   - /admin/*（除 /admin/login、/admin/ping）：Web session cookie 认证。
//     会话 token 只存 sha256，DB 持久化（重启不掉线）；登录失败限流 5 次/15min 锁定；
//     密码 bcrypt 存 settings 表，无哈希时回退默认 admin/admin123（面板强烈提示修改）。
//   - /v1/*：API Key 认证（Authorization: Bearer sk-xxx），Key 仅可调用 LLM 接口，
//     不提供管理面访问。Key 生成 sk-<40hex>，DB 只存 sha256 哈希 + 前缀；
//     校验按前缀查候选 → sha256 常量时间比较；支持启停/配额/过期/最后使用时间。

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	sessionCookieName = "acp_session"
	sessionExpiry     = 24 * time.Hour

	maxLoginFailures  = 5
	loginLockDuration = 15 * time.Minute
	loginFailWindow   = 15 * time.Minute
	loginFailDelay    = 500 * time.Millisecond

	settingPasswordHash = "admin_password_hash"
	settingAdminUser    = "admin_username"
)

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// ---- session ----

type sessionEntry struct {
	username  string
	createdAt time.Time
	expiresAt time.Time
}

type loginAttempt struct {
	failures  int
	firstFail time.Time
	lockUntil time.Time
}

// AuthManager 认证管理器（Web session + LLM API Key）
type AuthManager struct {
	mu       sync.RWMutex
	sessions map[string]*sessionEntry
	db       *DB

	attemptMu sync.Mutex
	attempts  map[string]*loginAttempt
}

// NewAuthManager 创建认证管理器（从 DB 恢复未过期会话）
func NewAuthManager(db *DB) *AuthManager {
	am := &AuthManager{
		sessions: make(map[string]*sessionEntry),
		db:       db,
		attempts: make(map[string]*loginAttempt),
	}
	if entries, err := am.loadValidSessions(); err != nil {
		log.Printf("[auth] 会话恢复失败: %v", err)
	} else if len(entries) > 0 {
		am.sessions = entries
		log.Printf("[auth] 恢复 %d 个有效会话", len(entries))
	}
	return am
}

func (am *AuthManager) loadValidSessions() (map[string]*sessionEntry, error) {
	rows, err := am.db.conn.Query(`SELECT token_hash, username, created_at, expires_at FROM sessions WHERE expires_at > ?`,
		time.Now().Format(time.RFC3339))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]*sessionEntry)
	for rows.Next() {
		var hash, username, createdS, expiresS string
		if err := rows.Scan(&hash, &username, &createdS, &expiresS); err != nil {
			return nil, err
		}
		created := parseTimeRFC(createdS)
		expires := parseTimeRFC(expiresS)
		if expires.IsZero() {
			continue
		}
		out[hash] = &sessionEntry{username: username, createdAt: created, expiresAt: expires}
	}
	return out, rows.Err()
}

func parseTimeRFC(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return t
}

func (am *AuthManager) saveSession(tokenHash string, s *sessionEntry) error {
	_, err := am.db.conn.Exec(
		`INSERT OR REPLACE INTO sessions (token_hash, username, created_at, expires_at) VALUES (?,?,?,?)`,
		tokenHash, s.username, s.createdAt.Format(time.RFC3339), s.expiresAt.Format(time.RFC3339))
	return err
}

func (am *AuthManager) deleteSession(tokenHash string) {
	if _, err := am.db.conn.Exec(`DELETE FROM sessions WHERE token_hash=?`, tokenHash); err != nil {
		log.Printf("[auth] 删除会话失败: %v", err)
	}
}

func (am *AuthManager) deleteExpiredSessions() {
	if _, err := am.db.conn.Exec(`DELETE FROM sessions WHERE expires_at <= ?`, time.Now().Format(time.RFC3339)); err != nil {
		log.Printf("[auth] 清理过期会话失败: %v", err)
	}
}

// username 当前管理用户名
func (am *AuthManager) username() string {
	if v, _ := am.db.GetSetting(settingAdminUser); v != "" {
		return v
	}
	return "admin"
}

// verifyPassword bcrypt 优先，无哈希回退默认密码（常量时间比较）
func (am *AuthManager) verifyPassword(password string) bool {
	if hash, _ := am.db.GetSetting(settingPasswordHash); hash != "" {
		return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
	}
	return subtle.ConstantTimeCompare([]byte(password), []byte("admin123")) == 1
}

// isDefaultPassword 是否仍在用默认密码（未设置 bcrypt 哈希）
func (am *AuthManager) isDefaultPassword() bool {
	hash, _ := am.db.GetSetting(settingPasswordHash)
	return hash == ""
}

// SetPassword 修改密码（bcrypt 落库）
func (am *AuthManager) SetPassword(newPassword string) error {
	if len(newPassword) < 6 {
		return fmt.Errorf("密码长度至少 6 位")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	return am.db.SetSetting(settingPasswordHash, string(hash))
}

// ---- 登录限流 ----

func loginAttemptKey(r *http.Request, username string) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return host + "|" + username
}

func (am *AuthManager) loginLockRemaining(key string) time.Duration {
	am.attemptMu.Lock()
	defer am.attemptMu.Unlock()
	a, ok := am.attempts[key]
	if !ok {
		return 0
	}
	now := time.Now()
	if now.Before(a.lockUntil) {
		return a.lockUntil.Sub(now)
	}
	if !a.lockUntil.IsZero() {
		delete(am.attempts, key)
	}
	return 0
}

func (am *AuthManager) recordLoginFailure(key string) {
	am.attemptMu.Lock()
	defer am.attemptMu.Unlock()
	now := time.Now()
	a, ok := am.attempts[key]
	if !ok || now.Sub(a.firstFail) > loginFailWindow {
		a = &loginAttempt{firstFail: now}
		am.attempts[key] = a
	}
	a.failures++
	if a.failures >= maxLoginFailures {
		a.lockUntil = now.Add(loginLockDuration)
		log.Printf("[auth] 登录锁定 %v，连续失败 %d 次 (key=%s)", loginLockDuration, a.failures, key)
	}
}

func (am *AuthManager) clearLoginFailures(key string) {
	am.attemptMu.Lock()
	defer am.attemptMu.Unlock()
	delete(am.attempts, key)
}

// Login 验证用户名密码，创建会话，返回明文 token（仅此次返回）
func (am *AuthManager) Login(username, password string) (string, bool) {
	am.mu.Lock()
	defer am.mu.Unlock()
	if subtle.ConstantTimeCompare([]byte(username), []byte(am.username())) != 1 {
		return "", false
	}
	if !am.verifyPassword(password) {
		return "", false
	}
	now := time.Now()
	for hash, s := range am.sessions {
		if now.After(s.expiresAt) {
			delete(am.sessions, hash)
		}
	}
	am.deleteExpiredSessions()
	token := randomHex(32)
	entry := &sessionEntry{username: username, createdAt: now, expiresAt: now.Add(sessionExpiry)}
	tokenHash := sha256Hex(token)
	am.sessions[tokenHash] = entry
	if err := am.saveSession(tokenHash, entry); err != nil {
		log.Printf("[auth] 会话持久化失败: %v", err)
	}
	log.Printf("[auth] 登录成功: user=%s", username)
	return token, true
}

// Logout 注销会话
func (am *AuthManager) Logout(token string) {
	hash := sha256Hex(token)
	am.mu.Lock()
	delete(am.sessions, hash)
	am.mu.Unlock()
	am.deleteSession(hash)
}

// IsValidSession 检查会话有效性
func (am *AuthManager) IsValidSession(token string) bool {
	if token == "" {
		return false
	}
	am.mu.RLock()
	defer am.mu.RUnlock()
	s, ok := am.sessions[sha256Hex(token)]
	if !ok {
		return false
	}
	return !time.Now().After(s.expiresAt)
}

// extractSessionToken 从 Cookie 或 Bearer 头提取 session token
func extractSessionToken(r *http.Request) string {
	if cookie, err := r.Cookie(sessionCookieName); err == nil && cookie.Value != "" {
		return cookie.Value
	}
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return ""
}

// ---- HTTP 处理：登录/登出/me/改密 ----

// HandleLogin POST /admin/login（公开）
func (am *AuthManager) HandleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体不合法")
		return
	}
	attemptKey := loginAttemptKey(r, body.Username)
	if remaining := am.loginLockRemaining(attemptKey); remaining > 0 {
		retryAfter := int(remaining.Seconds()) + 1
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
		writeErr(w, http.StatusTooManyRequests, fmt.Sprintf("失败次数过多，请 %d 秒后再试", retryAfter))
		return
	}
	token, ok := am.Login(body.Username, body.Password)
	if !ok {
		am.recordLoginFailure(attemptKey)
		time.Sleep(loginFailDelay)
		writeErr(w, http.StatusUnauthorized, "用户名或密码错误")
		return
	}
	am.clearLoginFailures(attemptKey)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   int(sessionExpiry.Seconds()),
		SameSite: http.SameSiteStrictMode,
	})
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":             true,
		"username":            body.Username,
		"is_default_password": am.isDefaultPassword(),
	})
}

// HandleLogout POST /admin/logout
func (am *AuthManager) HandleLogout(w http.ResponseWriter, r *http.Request) {
	if token := extractSessionToken(r); token != "" {
		am.Logout(token)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", HttpOnly: true, MaxAge: -1})
	writeJSON(w, http.StatusOK, map[string]string{"message": "已退出登录"})
}

// HandleMe GET /admin/me（会话状态探测）
func (am *AuthManager) HandleMe(w http.ResponseWriter, r *http.Request) {
	token := extractSessionToken(r)
	if !am.IsValidSession(token) {
		writeErr(w, http.StatusUnauthorized, "未登录或会话已过期")
		return
	}
	am.mu.RLock()
	entry := am.sessions[sha256Hex(token)]
	am.mu.RUnlock()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"username":            entry.username,
		"expires_at":          entry.expiresAt.Format(time.RFC3339),
		"is_default_password": am.isDefaultPassword(),
	})
}

// HandleChangePassword POST /admin/password（需会话）
func (am *AuthManager) HandleChangePassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体不合法")
		return
	}
	if !am.verifyPassword(body.OldPassword) {
		writeErr(w, http.StatusUnauthorized, "当前密码不正确")
		return
	}
	if err := am.SetPassword(body.NewPassword); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	log.Printf("[auth] 管理密码已修改")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// WrapSession /admin/* 会话保护中间件
func (am *AuthManager) WrapSession(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !am.IsValidSession(extractSessionToken(r)) {
			writeErr(w, http.StatusUnauthorized, "未登录或会话已过期")
			return
		}
		h(w, r)
	}
}

// ---- API Key（仅 LLM 端点）----

// APIKey api_keys 表行
type APIKey struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	KeyHash      string `json:"-"`
	KeyPrefix    string `json:"key_prefix"`
	IsEnabled    bool   `json:"is_enabled"`
	MaxRequests  int64  `json:"max_requests"`
	UsedRequests int64  `json:"used_requests"`
	ExpiresAt    string `json:"expires_at"`
	LastUsedAt   string `json:"last_used_at"`
	CreatedAt    string `json:"created_at"`
}

func generateAPIKey() string { return "sk-" + randomHex(20) }

func keyPrefixOf(key string) string {
	if len(key) >= 11 {
		return key[:11]
	}
	return key
}

// SeedDefaultAPIKey 迁移旧 settings.api_key 为首个 Key；全部为空则新建随机 Key
func (am *AuthManager) SeedDefaultAPIKey() (plain string) {
	if keys, err := am.ListAPIKeys(); err == nil && len(keys) > 0 {
		return ""
	}
	legacy, _ := am.db.GetSetting("api_key")
	if legacy != "" {
		row := &APIKey{
			ID:        "key_default",
			Name:      "默认密钥（旧版迁移）",
			KeyHash:   sha256Hex(legacy),
			KeyPrefix: keyPrefixOf(legacy),
			IsEnabled: true,
			CreatedAt: time.Now().Format(time.RFC3339),
		}
		am.db.conn.Exec(`INSERT OR REPLACE INTO api_keys (id,name,key_hash,key_prefix,is_enabled,max_requests,used_requests,expires_at,last_used_at,created_at)
			VALUES(?,?,?,?,1,0,0,'','',?)`,
			row.ID, row.Name, row.KeyHash, row.KeyPrefix, row.CreatedAt)
		log.Printf("[auth] 已迁移旧 API Key → api_keys 表 (%s…)", row.KeyPrefix)
		return legacy
	}
	plain = generateAPIKey()
	am.db.conn.Exec(`INSERT OR REPLACE INTO api_keys (id,name,key_hash,key_prefix,is_enabled,max_requests,used_requests,expires_at,last_used_at,created_at)
		VALUES(?,?,?,?,1,0,0,'','',?)`,
		"key_default", "默认密钥", sha256Hex(plain), keyPrefixOf(plain), time.Now().Format(time.RFC3339))
	log.Printf("[auth] 已生成初始 API Key: %s", plain)
	return plain
}

// CreateAPIKey 创建 Key，返回明文（仅此一次）
func (am *AuthManager) CreateAPIKey(name string, maxRequests int64, expiresDays int) (string, *APIKey, error) {
	if strings.TrimSpace(name) == "" {
		return "", nil, fmt.Errorf("名称不能为空")
	}
	plain := generateAPIKey()
	row := &APIKey{
		ID:        "key_" + randomHex(6),
		Name:      strings.TrimSpace(name),
		KeyHash:   sha256Hex(plain),
		KeyPrefix: keyPrefixOf(plain),
		IsEnabled: true,
		MaxRequests: maxRequests,
		CreatedAt: time.Now().Format(time.RFC3339),
	}
	if expiresDays > 0 {
		row.ExpiresAt = time.Now().Add(time.Duration(expiresDays) * 24 * time.Hour).Format(time.RFC3339)
	}
	if _, err := am.db.conn.Exec(`INSERT INTO api_keys (id,name,key_hash,key_prefix,is_enabled,max_requests,used_requests,expires_at,last_used_at,created_at)
		VALUES(?,?,?,?,?,?,0,?, '', ?)`,
		row.ID, row.Name, row.KeyHash, row.KeyPrefix, boolToInt(row.IsEnabled), row.MaxRequests, row.ExpiresAt, row.CreatedAt); err != nil {
		return "", nil, err
	}
	log.Printf("[auth] 新建 API Key: id=%s prefix=%s name=%s", row.ID, row.KeyPrefix, row.Name)
	return plain, row, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ListAPIKeys 列出全部 Key（不含哈希）
func (am *AuthManager) ListAPIKeys() ([]*APIKey, error) {
	rows, err := am.db.conn.Query(`SELECT id,name,key_hash,key_prefix,is_enabled,max_requests,used_requests,expires_at,last_used_at,created_at
		FROM api_keys ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*APIKey
	for rows.Next() {
		var k APIKey
		var enabled int
		if err := rows.Scan(&k.ID, &k.Name, &k.KeyHash, &k.KeyPrefix, &enabled,
			&k.MaxRequests, &k.UsedRequests, &k.ExpiresAt, &k.LastUsedAt, &k.CreatedAt); err != nil {
			return nil, err
		}
		k.IsEnabled = enabled != 0
		out = append(out, &k)
	}
	return out, rows.Err()
}

// DeleteAPIKey 删除 Key
func (am *AuthManager) DeleteAPIKey(id string) error {
	_, err := am.db.conn.Exec(`DELETE FROM api_keys WHERE id=?`, id)
	return err
}

// ToggleAPIKey 启停 Key
func (am *AuthManager) ToggleAPIKey(id string, enabled bool) error {
	_, err := am.db.conn.Exec(`UPDATE api_keys SET is_enabled=? WHERE id=?`, boolToInt(enabled), id)
	return err
}

// ValidateAPIKey 校验明文 Key：前缀查候选 → sha256 常量时间比较 → 启停/过期/配额
func (am *AuthManager) ValidateAPIKey(plain string) (*APIKey, error) {
	cands := []string{plain}
	if strings.HasPrefix(plain, "sk-") {
		cands = append(cands, plain[3:])
	} else {
		cands = append(cands, "sk-"+plain)
	}
	for _, c := range cands {
		if k, err := am.validateKeyExact(c); err == nil {
			return k, nil
		}
	}
	return nil, fmt.Errorf("invalid api key")
}

func (am *AuthManager) validateKeyExact(plain string) (*APIKey, error) {
	if !strings.HasPrefix(plain, "sk-") {
		return nil, fmt.Errorf("invalid api key")
	}
	rows, err := am.db.conn.Query(`SELECT id,name,key_hash,key_prefix,is_enabled,max_requests,used_requests,expires_at,last_used_at,created_at
		FROM api_keys WHERE key_prefix=?`, keyPrefixOf(plain))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	hash := sha256Hex(plain)
	for rows.Next() {
		var k APIKey
		var enabled int
		if err := rows.Scan(&k.ID, &k.Name, &k.KeyHash, &k.KeyPrefix, &enabled,
			&k.MaxRequests, &k.UsedRequests, &k.ExpiresAt, &k.LastUsedAt, &k.CreatedAt); err != nil {
			return nil, err
		}
		k.IsEnabled = enabled != 0
		if subtle.ConstantTimeCompare([]byte(hash), []byte(k.KeyHash)) != 1 {
			continue
		}
		if !k.IsEnabled {
			return nil, fmt.Errorf("api key disabled")
		}
		if t := parseTimeRFC(k.ExpiresAt); !t.IsZero() && time.Now().After(t) {
			return nil, fmt.Errorf("api key expired")
		}
		if k.MaxRequests > 0 && k.UsedRequests >= k.MaxRequests {
			return nil, fmt.Errorf("api key quota exceeded")
		}
		return &k, nil
	}
	return nil, fmt.Errorf("invalid api key")
}

// TouchAPIKey 使用后计数 + 最后使用时间
func (am *AuthManager) TouchAPIKey(id string) {
	if _, err := am.db.conn.Exec(`UPDATE api_keys SET used_requests=used_requests+1, last_used_at=? WHERE id=?`,
		time.Now().Format(time.RFC3339), id); err != nil {
		log.Printf("[auth] key 计数失败: %v", err)
	}
}

// ---- LLM 端点鉴权（仅 API Key）----

// WrapAPIKey /v1/* 鉴权：仅 API Key（Key 不提供管理面访问）
func (am *AuthManager) WrapAPIKey(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if auth == "" {
			auth = strings.TrimSpace(r.Header.Get("X-Api-Key"))
		}
		if auth == "" {
			openaiError(w, http.StatusUnauthorized, "invalid_request_error", "缺少 API Key（Authorization: Bearer sk-…）")
			return
		}
		key, err := am.ValidateAPIKey(auth)
		if err != nil {
			openaiError(w, http.StatusUnauthorized, "invalid_request_error", "API Key 无效、已停用或已过期")
			return
		}
		am.TouchAPIKey(key.ID)
		h(w, r)
	}
}

// FirstAPIKey 启动时打印用：返回首个可用 Key 的前缀（-show-key 返回明文，仅无 Key 生成时）
func (am *AuthManager) FirstAPIKey() string {
	if keys, err := am.ListAPIKeys(); err == nil && len(keys) > 0 {
		return keys[0].KeyPrefix + "…（完整 Key 仅创建时显示，可在面板新建）"
	}
	return ""
}
