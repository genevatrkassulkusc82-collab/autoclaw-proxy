package main

// ---- 管理 API ----
// 鉴权: /admin/* 走 Web session（登录页账号密码，见 auth.go）；
//       /v1/* 走 LLM API Key（WrapAPIKey）。两套凭据互不通。

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"
)

// AdminHandler 管理面
type AdminHandler struct {
	db      *DB
	pool    *AccountPool
	llm     *LLMCaller
	login   *LoginManager
	browser *BrowserService
	auth    *AuthManager
}

// NewAdminHandler 创建
func NewAdminHandler(db *DB, pool *AccountPool, llm *LLMCaller, login *LoginManager, browser *BrowserService, auth *AuthManager) *AdminHandler {
	return &AdminHandler{db: db, pool: pool, llm: llm, login: login, browser: browser, auth: auth}
}

// Register 注册管理路由（除 ping/login 外全部需会话）
func (h *AdminHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin/ping", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]interface{}{"ok": true, "time": time.Now().Unix()})
	})
	// 认证接口
	mux.HandleFunc("POST /admin/login", h.auth.HandleLogin)
	mux.HandleFunc("POST /admin/logout", h.auth.HandleLogout)
	mux.HandleFunc("GET /admin/me", h.auth.HandleMe)

	a := h.auth.WrapSession
	mux.HandleFunc("POST /admin/password", a(h.auth.HandleChangePassword))
	mux.HandleFunc("GET /admin/stats", a(h.handleStats))
	mux.HandleFunc("GET /admin/accounts", a(h.handleListAccounts))
	mux.HandleFunc("POST /admin/accounts/import-local", a(h.handleImportLocal))
	mux.HandleFunc("GET /admin/accounts/import-local/preview", a(h.handleImportPreview))
	mux.HandleFunc("POST /admin/accounts/{id}/refresh", a(h.handleRefreshAccount))
	mux.HandleFunc("POST /admin/accounts/{id}/enable", a(h.handleEnableAccount))
	mux.HandleFunc("POST /admin/accounts/{id}/disable", a(h.handleDisableAccount))
	mux.HandleFunc("DELETE /admin/accounts/{id}", a(h.handleDeleteAccount))
	mux.HandleFunc("POST /admin/login/send-code", a(h.handleSendCode))
	mux.HandleFunc("POST /admin/login/verify", a(h.handleLoginVerify))
	mux.HandleFunc("GET /admin/models", a(h.handleModels))
	mux.HandleFunc("POST /admin/models/sync", a(h.handleModelsSync))
	mux.HandleFunc("GET /admin/proxies", a(h.handleListProxies))
	mux.HandleFunc("POST /admin/proxies", a(h.handleSaveProxy))
	mux.HandleFunc("DELETE /admin/proxies/{id}", a(h.handleDeleteProxy))
	mux.HandleFunc("POST /admin/proxies/test", a(h.handleTestProxy))
	mux.HandleFunc("POST /admin/proxies/detect", a(h.handleDetectProxy))
	mux.HandleFunc("GET /admin/settings", a(h.handleGetSettings))
	mux.HandleFunc("POST /admin/settings", a(h.handleSaveSettings))
	mux.HandleFunc("GET /admin/usage", a(h.handleUsage))
	mux.HandleFunc("GET /admin/browser/status", a(h.handleBrowserStatus))
	mux.HandleFunc("POST /admin/browser/fingerprint-check", a(h.handleBrowserCheck))
	mux.HandleFunc("POST /admin/test/chat", a(h.handleTestChat))
	// LLM API Key 管理（Key 仅用于 /v1/*，不提供管理面访问）
	mux.HandleFunc("GET /admin/keys", a(h.handleListKeys))
	mux.HandleFunc("POST /admin/keys", a(h.handleCreateKey))
	mux.HandleFunc("POST /admin/keys/{id}/toggle", a(h.handleToggleKey))
	mux.HandleFunc("DELETE /admin/keys/{id}", a(h.handleDeleteKey))
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]interface{}{"error": msg})
}

func pathID(r *http.Request) int64 {
	id, _ := parseInt(r.PathValue("id"))
	return int64(id)
}

// accountView 账号脱敏视图
func accountView(a *Account) map[string]interface{} {
	v := map[string]interface{}{
		"id": a.ID, "user_id": a.UserID, "phone": maskPhone(a.Phone),
		"device_id": a.DeviceID, "device_spoofed": a.DeviceSpoofed == 1,
		"group": a.AccountGroup, "status": a.Status, "enabled": a.Enabled == 1,
		"at_exp": a.AtExp, "rt_exp": a.RtExp, "cooldown_until": a.CooldownUntil,
		"last_error": a.LastError, "total_requests": a.TotalRequests,
		"total_tokens": a.TotalTokens, "failed_streak": a.FailedStreak,
		"source": a.Source, "created_at": a.CreatedAt, "updated_at": a.UpdatedAt,
	}
	if a.AtExp > 0 {
		v["at_remaining_h"] = float64(a.AtExp-time.Now().Unix()) / 3600
	}
	if a.RtExp > 0 {
		v["rt_remaining_d"] = float64(a.RtExp-time.Now().Unix()) / 86400
	}
	v["has_at"] = a.AccessToken != ""
	v["has_rt"] = a.RefreshToken != ""
	return v
}

func (h *AdminHandler) handleStats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, h.db.Stats())
}

func (h *AdminHandler) handleListAccounts(w http.ResponseWriter, r *http.Request) {
	accounts, err := h.db.ListAccounts()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	out := make([]map[string]interface{}, 0, len(accounts))
	for _, a := range accounts {
		out = append(out, accountView(a))
	}
	writeJSON(w, 200, map[string]interface{}{"accounts": out})
}

func (h *AdminHandler) handleImportPreview(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, PreviewLocalImport())
}

func (h *AdminHandler) handleImportLocal(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Group string `json:"group"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	a, err := ImportLocalAccount(h.db, req.Group)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{"account": accountView(a)})
}

func (h *AdminHandler) handleRefreshAccount(w http.ResponseWriter, r *http.Request) {
	a, err := h.db.GetAccount(pathID(r))
	if err != nil {
		writeErr(w, 404, err.Error())
		return
	}
	at, err := h.pool.RefreshAccount(a, true)
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{
		"ok": true, "at_exp": TokenExpiresAt(at),
		"remaining_h": TokenRemaining(at).Hours(),
	})
}

func (h *AdminHandler) handleEnableAccount(w http.ResponseWriter, r *http.Request) {
	if err := h.db.SetAccountEnabled(pathID(r), true); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{"ok": true})
}

func (h *AdminHandler) handleDisableAccount(w http.ResponseWriter, r *http.Request) {
	if err := h.db.SetAccountEnabled(pathID(r), false); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{"ok": true})
}

func (h *AdminHandler) handleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	if err := h.db.DeleteAccount(pathID(r)); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{"ok": true})
}

// ---- 在线验证码登录（SMS）----

func (h *AdminHandler) handleSendCode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Phone         string `json:"phone"`
		Group         string `json:"group"`
		UseRealDevice bool   `json:"use_real_device"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "请求体解析失败")
		return
	}
	flowID, err := h.login.StartLogin(req.Phone, req.Group, req.UseRealDevice)
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{"flow_id": flowID, "msg": "验证码已发送（60s 内有效）"})
}

func (h *AdminHandler) handleLoginVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		FlowID string `json:"flow_id"`
		Code   string `json:"code"`
		Group  string `json:"group"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "请求体解析失败")
		return
	}
	a, err := h.login.CompleteLogin(req.FlowID, req.Code, req.Group)
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{"account": accountView(a)})
}

// ---- 模型 ----

func (h *AdminHandler) handleModels(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]interface{}{"models": h.llm.Catalog()})
}

func (h *AdminHandler) handleModelsSync(w http.ResponseWriter, r *http.Request) {
	models, err := h.llm.SyncCatalog()
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{"models": models, "count": len(models)})
}

// ---- 代理 ----

func (h *AdminHandler) handleListProxies(w http.ResponseWriter, r *http.Request) {
	nodes, err := h.db.ListProxyNodes()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	for _, n := range nodes {
		n.Password = maskSecret(n.Password)
	}
	writeJSON(w, 200, map[string]interface{}{"nodes": nodes})
}

func maskSecret(s string) string {
	if s == "" {
		return ""
	}
	if len(s) <= 3 {
		return "***"
	}
	return s[:2] + "***"
}

func (h *AdminHandler) handleSaveProxy(w http.ResponseWriter, r *http.Request) {
	var n ProxyNode
	if err := json.NewDecoder(r.Body).Decode(&n); err != nil {
		writeErr(w, 400, "请求体解析失败")
		return
	}
	if n.Host == "" || n.Port <= 0 {
		writeErr(w, 400, "host/port 必填")
		return
	}
	// 密码留空 = 保留旧值
	if n.ID > 0 && n.Password == "" {
		if nodes, err := h.db.ListProxyNodes(); err == nil {
			for _, old := range nodes {
				if old.ID == n.ID {
					n.Password = old.Password
				}
			}
		}
	}
	id, err := h.db.UpsertProxyNode(&n)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	CloseIdleClients()
	writeJSON(w, 200, map[string]interface{}{"id": id})
}

func (h *AdminHandler) handleDeleteProxy(w http.ResponseWriter, r *http.Request) {
	if err := h.db.DeleteProxyNode(pathID(r)); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	CloseIdleClients()
	writeJSON(w, 200, map[string]interface{}{"ok": true})
}

func (h *AdminHandler) handleTestProxy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL string `json:"url"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	ip, elapsed, err := TestProxyExitIP(strings.TrimSpace(req.URL))
	if err != nil {
		writeJSON(w, 200, map[string]interface{}{"ok": false, "error": err.Error(), "elapsed_ms": elapsed.Milliseconds()})
		return
	}
	writeJSON(w, 200, map[string]interface{}{"ok": true, "exit_ip": ip, "elapsed_ms": elapsed.Milliseconds()})
}

func (h *AdminHandler) handleDetectProxy(w http.ResponseWriter, r *http.Request) {
	enabled, sysURL := DetectSystemProxy()
	writeJSON(w, 200, map[string]interface{}{
		"system_proxy": map[string]interface{}{"enabled": enabled, "url": sysURL},
		"local_ports":  ProbeLocalProxyPorts(),
	})
}

// ---- 设置 ----

var editableSettings = []string{
	"upstream_host", "upstream_proxy", "pool_strategy", "tls_mode", "tls_ja3",
	"captcha_enabled", "captcha_prefix", "captcha_region", "captcha_scene_id", "captcha_page_url",
	"listen_addr", "login_proxy",
}

func (h *AdminHandler) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	out := map[string]interface{}{}
	for _, k := range editableSettings {
		v, _ := h.db.GetSetting(k)
		out[k] = v
	}
	// 非敏感运行时信息
	out["fingerprint_presets"] = tlsFingerprintPresets
	out["browser"] = h.browser.Status()
	writeJSON(w, 200, out)
}

func (h *AdminHandler) handleSaveSettings(w http.ResponseWriter, r *http.Request) {
	var req map[string]string
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "请求体解析失败")
		return
	}
	allowed := map[string]bool{}
	for _, k := range editableSettings {
		allowed[k] = true
	}
	for k, v := range req {
		if !allowed[k] {
			continue
		}
		if err := h.db.SetSetting(k, strings.TrimSpace(v)); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	CloseIdleClients()
	writeJSON(w, 200, map[string]interface{}{"ok": true})
}

func (h *AdminHandler) handleUsage(w http.ResponseWriter, r *http.Request) {
	logs, err := h.db.RecentUsage(100)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{"logs": logs})
}

// ---- 浏览器 ----

func (h *AdminHandler) handleBrowserStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, h.browser.Status())
}

func (h *AdminHandler) handleBrowserCheck(w http.ResponseWriter, r *http.Request) {
	res, err := h.browser.FingerprintCheck("")
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, res)
}

// ---- 在线 LLM 测试 ----

func (h *AdminHandler) handleTestChat(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Model    string `json:"model"`
		Prompt   string `json:"prompt"`
		Stream   bool   `json:"stream"`
		AccountID int64 `json:"account_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "请求体解析失败")
		return
	}
	if req.Prompt == "" {
		req.Prompt = "回复 OK 两个字母即可"
	}
	if req.Model == "" {
		req.Model = "auto"
	}
	body := map[string]interface{}{
		"model":    req.Model,
		"messages": []map[string]string{{"role": "user", "content": req.Prompt}},
		"stream":   false, // 管理端测试统一非流式，简化展示
	}
	start := time.Now()
	result, err := h.llm.ChatCompletions(r.Context(), body, req.AccountID, "round_robin")
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	defer result.Resp.Body.Close()
	var resp map[string]interface{}
	if err := json.NewDecoder(result.Resp.Body).Decode(&resp); err != nil {
		writeErr(w, 502, "上游响应解析失败: "+err.Error())
		return
	}
	content := ""
	reasoning := ""
	if choices, ok := resp["choices"].([]interface{}); ok && len(choices) > 0 {
		if c, ok := choices[0].(map[string]interface{}); ok {
			if msg, ok := c["message"].(map[string]interface{}); ok {
				content, _ = msg["content"].(string)
				reasoning, _ = msg["reasoning_content"].(string)
			}
		}
	}
	writeJSON(w, 200, map[string]interface{}{
		"ok": true, "status": result.Resp.StatusCode,
		"route": result.Route, "account_id": result.Account.ID,
		"upstream_model": resp["model"], "content": content,
		"reasoning_preview": truncate(reasoning, 200),
		"usage": resp["usage"], "elapsed_ms": time.Since(start).Milliseconds(),
	})
}

// logRequest 简单访问日志
func logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/admin/ping") {
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("[http] %s %s %s", r.Method, r.URL.Path, time.Since(start).Round(time.Millisecond))
	})
}

// ---- LLM API Key 管理 ----

func (h *AdminHandler) handleListKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := h.auth.ListAPIKeys()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{"keys": keys})
}

func (h *AdminHandler) handleCreateKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		MaxRequests int64  `json:"max_requests"`
		ExpiresDays int    `json:"expires_days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "请求体解析失败")
		return
	}
	plain, row, err := h.auth.CreateAPIKey(req.Name, req.MaxRequests, req.ExpiresDays)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{
		"key":  plain, // 仅此一次返回明文
		"meta": row,
		"msg":  "Key 仅创建时完整显示一次，请立即保存",
	})
}

func (h *AdminHandler) handleToggleKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "请求体解析失败")
		return
	}
	if err := h.auth.ToggleAPIKey(r.PathValue("id"), req.Enabled); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{"ok": true})
}

func (h *AdminHandler) handleDeleteKey(w http.ResponseWriter, r *http.Request) {
	if err := h.auth.DeleteAPIKey(r.PathValue("id")); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{"ok": true})
}
