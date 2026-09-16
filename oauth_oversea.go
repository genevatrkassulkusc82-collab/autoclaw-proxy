package main

// ---- 海外 OAuth 登录（Z.ai / Google）----
// 半自动流程（用户在自己浏览器完成登录，网关只负责"生成链接"与"收口换 token"）：
//  1. StartOverseaOAuth(vendor)：过阿里云验证码 → 调 {vendor}-oauth-url 拿到后端签名的授权链接
//  2. 用户用浏览器打开链接登录 → 浏览器跳转 http://localhost:18432/auth/callback-{vendor}?code=..&state=..
//     （网关不监听该端口，页面打不开属正常）
//  3. 用户把地址栏那条 localhost 回调链接粘回 → CompleteOverseaOAuth(flowID, callbackURL)
//  4. 解析 code+state → 调 {vendor}-oauth-login 换 token → 导入为海外账号（region=oversea）
//
// 协议来源：海外版 AutoClaw 1.18.5 bundle 逆向 + 生产端点实测（docs/04）。
// vendor ∈ {zai, google}，两者完全对称：仅端点名与回调路径不同。

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	neturl "net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

// OAuthVendor 海外登录方式
type OAuthVendor string

const (
	OAuthZai    OAuthVendor = "zai"
	OAuthGoogle OAuthVendor = "google"
)

// overseaOAuthCallbackPort 官方客户端 loopback 回调端口（ALL_PORTS=[18432,…] 首选）
const overseaOAuthCallbackPort = 18432

// OverseaOAuthFlow 一次海外 OAuth 登录流程（生成链接 → 等待用户粘贴回调）
type OverseaOAuthFlow struct {
	Vendor       OAuthVendor
	Device       *DeviceIdentity // 设备身份（deviceId=state.dh + Ed25519 keys）；oauth-login 须用同一 device_id
	NavigateURI  string          // http://localhost:18432/auth/callback-{vendor}
	Group        string
	AuthorizeURL string
	CreatedAt    time.Time
}

func overseaCallbackPath(v OAuthVendor) string { return "/auth/callback-" + string(v) }

func overseaNavigateURI(v OAuthVendor) string {
	return fmt.Sprintf("http://localhost:%d%s", overseaOAuthCallbackPort, overseaCallbackPath(v))
}

// ===================== userapi：海外 OAuth 三接口 =====================

// OverseaOAuthCaptchaConfig POST /userapi/overseasv1/oauth-captcha-config
// 返回 {enabled, region, prefix, scene_id, captcha_supplier}
func (c *UserAPIClient) OverseaOAuthCaptchaConfig() (map[string]interface{}, error) {
	env, err := c.post("/userapi/overseasv1/oauth-captcha-config", map[string]interface{}{}, "")
	if err != nil {
		return nil, err
	}
	if env.Code != 0 {
		return nil, fmt.Errorf("oauth-captcha-config code=%d msg=%s", env.Code, env.Msg)
	}
	var m map[string]interface{}
	if len(env.Data) > 0 {
		_ = json.Unmarshal(env.Data, &m)
	}
	return m, nil
}

// OverseaOAuthURL POST /userapi/overseasv1/{vendor}-oauth-url
// 带 device_id + navigate_uri(+验证码) → 后端返回签名授权链接。
// 实测：缺验证码参数时返回 631002（文案是"version no longer supported"，实为缺验证码）。
func (c *UserAPIClient) OverseaOAuthURL(vendor, deviceID, navigateURI, captchaParam string) (string, error) {
	params := map[string]interface{}{"navigate_uri": navigateURI}
	if captchaParam != "" {
		params["ali_captcha_verify_param"] = captchaParam
	}
	env, err := c.post("/userapi/overseasv1/"+vendor+"-oauth-url", withWebInfo(deviceID, params), "")
	if err != nil {
		return "", err
	}
	if env.Code != 0 {
		return "", fmt.Errorf("%s-oauth-url code=%d msg=%s", vendor, env.Code, env.Msg)
	}
	u := parseAuthorizeURL(env.Data)
	if u == "" {
		return "", fmt.Errorf("%s-oauth-url 未返回授权链接（data=%s）", vendor, truncate(string(env.Data), 200))
	}
	return u, nil
}

// OverseaOAuthLogin POST /userapi/overseasv1/{vendor}-oauth-login
// 用回调 code+state 换 token（响应结构同短信登录 LoginResult：access_token/refresh_token/user_id…）
func (c *UserAPIClient) OverseaOAuthLogin(vendor, deviceID, code, state, navigateURI string) (*LoginResult, error) {
	env, err := c.post("/userapi/overseasv1/"+vendor+"-oauth-login", withWebInfo(deviceID, map[string]interface{}{
		"code":         code,
		"state":        state,
		"navigate_uri": navigateURI,
	}), "")
	if err != nil {
		return nil, err
	}
	if env.Code != 0 || len(env.Data) == 0 {
		return nil, fmt.Errorf("%s-oauth-login code=%d msg=%s trace=%s", vendor, env.Code, env.Msg, env.Trace)
	}
	var lr LoginResult
	if err := json.Unmarshal(env.Data, &lr); err != nil {
		return nil, fmt.Errorf("%s-oauth-login 响应解析失败: %w", vendor, err)
	}
	if lr.AccessToken == "" || lr.RefreshToken == "" {
		return nil, fmt.Errorf("%s-oauth-login 响应缺少 token (code=%d)", vendor, env.Code)
	}
	return &lr, nil
}

// parseAuthorizeURL 从 oauth-url 响应 data 容错提取授权链接（data 可能是字符串或含 url 字段的对象）
func parseAuthorizeURL(data json.RawMessage) string {
	if len(data) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(data, &s) == nil && strings.HasPrefix(s, "http") {
		return s
	}
	keys := []string{"url", "authorize_url", "oauth_url", "navigate_url", "auth_url", "redirect_url", "link"}
	var walk func(m map[string]interface{}) string
	walk = func(m map[string]interface{}) string {
		for _, k := range keys {
			if v, ok := m[k].(string); ok && strings.HasPrefix(v, "http") {
				return v
			}
		}
		for _, v := range m {
			if sub, ok := v.(map[string]interface{}); ok {
				if u := walk(sub); u != "" {
					return u
				}
			}
		}
		return ""
	}
	var m map[string]interface{}
	if json.Unmarshal(data, &m) == nil {
		return walk(m)
	}
	return ""
}

// ===================== LoginManager：海外 OAuth 流程编排 =====================

// overseaClient 海外 userapi 客户端（host=autoglm-api.autoglm.ai，X-Lang=en，按组绑定出口代理）
func (lm *LoginManager) overseaClient(group string) *UserAPIClient {
	acct := &Account{Region: string(RegionOversea), AccountGroup: group}
	c := NewUserAPIClient(RegionHost(lm.db, acct), lm.pool.egress.ProxyURLForAccount(acct))
	c.Lang = RegionLang(acct)
	return c
}

// overseaCaptchaPage 验证码求解所用页面（海外默认 chat.z.ai；可用 settings.captcha_page_url 覆盖）
func (lm *LoginManager) overseaCaptchaPage() string {
	if v, _ := lm.db.GetSetting("captcha_page_url"); strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return "https://chat.z.ai/"
}

// StartOverseaOAuth 生成授权链接（含过验证码）。返回 flowID 与授权 URL。
func (lm *LoginManager) StartOverseaOAuth(vendor OAuthVendor, group string) (flowID, authorizeURL string, err error) {
	if vendor != OAuthZai && vendor != OAuthGoogle {
		return "", "", errors.New("vendor 必须是 zai 或 google")
	}
	client := lm.overseaClient(group)

	// 1) 验证码（海外 OAuth 实测强制启用阿里云无痕验证）
	var captchaParam string
	cc, cerr := client.OverseaOAuthCaptchaConfig()
	if cerr != nil {
		return "", "", fmt.Errorf("获取验证码配置失败: %w", cerr)
	}
	if enabled, _ := cc["enabled"].(bool); enabled {
		if lm.browser == nil {
			return "", "", errors.New("海外登录需过阿里云验证码，但浏览器服务不可用，无法求解")
		}
		cfg := &CaptchaConfig{
			Enabled: true,
			Prefix:  oauthStr(cc["prefix"]),
			Region:  oauthStr(cc["region"]),
			SceneID: oauthStr(cc["scene_id"]),
			PageURL: lm.overseaCaptchaPage(),
		}
		captchaParam, err = lm.browser.SolveCaptcha(cfg, client.ProxyURL)
		if err != nil {
			return "", "", fmt.Errorf("阿里云验证码求解失败: %w", err)
		}
	}

	// 2) 设备身份（deviceId 会进 state.dh；oauth-login 须用同一 device_id）
	dev, err := GenerateDeviceIdentity()
	if err != nil {
		return "", "", fmt.Errorf("生成设备身份失败: %w", err)
	}

	// 3) 授权链接
	navURI := overseaNavigateURI(vendor)
	authURL, err := client.OverseaOAuthURL(string(vendor), dev.DeviceID, navURI, captchaParam)
	if err != nil {
		return "", "", err
	}

	// 4) 存流程（一次性，30min 过期由 gcLoop 清理）
	id := uuid.NewString()
	lm.mu.Lock()
	if lm.overseaFlows == nil {
		lm.overseaFlows = map[string]*OverseaOAuthFlow{}
	}
	lm.overseaFlows[id] = &OverseaOAuthFlow{
		Vendor: vendor, Device: dev, NavigateURI: navURI, Group: group,
		AuthorizeURL: authURL, CreatedAt: time.Now(),
	}
	lm.mu.Unlock()
	log.Printf("[oauth-oversea] flow=%s vendor=%s device=%s 授权链接已生成", id[:8], vendor, dev.DeviceID[:12])
	return id, authURL, nil
}

// CompleteOverseaOAuth 用用户粘回的 localhost 回调链接完成登录并入库。
func (lm *LoginManager) CompleteOverseaOAuth(flowID, callbackURL string) (*Account, error) {
	lm.mu.Lock()
	flow := lm.overseaFlows[flowID]
	delete(lm.overseaFlows, flowID) // 一次性
	lm.mu.Unlock()
	if flow == nil {
		return nil, errors.New("OAuth 流程不存在或已过期，请重新生成链接")
	}
	code, state, err := parseOAuthCallback(callbackURL)
	if err != nil {
		return nil, err
	}
	// 校验回调 state 的设备与本次流程一致（防串号/粘错链接）
	if dh := stateDeviceID(state); dh != "" && dh != flow.Device.DeviceID {
		return nil, errors.New("回调 state 的设备与本次流程不一致，请确认粘贴的是本次链接登录后的回调")
	}
	client := lm.overseaClient(flow.Group)
	lr, err := client.OverseaOAuthLogin(string(flow.Vendor), flow.Device.DeviceID, code, state, flow.NavigateURI)
	if err != nil {
		return nil, err
	}
	a := &Account{
		UserID:        lr.UserID.String(),
		AccessToken:   StripBearer(lr.AccessToken),
		RefreshToken:  StripBearer(lr.RefreshToken),
		DeviceID:      flow.Device.DeviceID,
		PublicKeyPem:  flow.Device.PublicKeyPem,
		PrivateKeyPem: flow.Device.PrivateKeyPem,
		DeviceSpoofed: 1, // 网关现场生成的设备身份
		AccountGroup:  flow.Group,
		Status:        "active",
		Enabled:       1,
		AtExp:         TokenExpiresAt(lr.AccessToken),
		RtExp:         TokenExpiresAt(lr.RefreshToken),
		Source:        "oauth_" + string(flow.Vendor),
		Region:        string(RegionOversea),
	}
	id, err := lm.db.UpsertAccount(a)
	if err != nil {
		return nil, fmt.Errorf("账号入库失败: %w", err)
	}
	a.ID = id
	log.Printf("[oauth-oversea] 登录成功 account=%d user=%s vendor=%s device=%s", id, a.UserID, flow.Vendor, a.DeviceID[:12])
	return a, nil
}

// ===================== helpers =====================

// parseOAuthCallback 从用户粘贴的回调链接里取 code/state（容错：允许只粘 query 或带 error）
func parseOAuthCallback(raw string) (code, state string, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", errors.New("回调链接为空")
	}
	if !strings.Contains(raw, "?") && strings.Contains(raw, "code=") {
		raw = "http://localhost/?" + raw // 用户只粘了 query
	}
	u, e := neturl.Parse(raw)
	if e != nil {
		return "", "", fmt.Errorf("回调链接解析失败: %w", e)
	}
	q := u.Query()
	code = strings.TrimSpace(q.Get("code"))
	state = strings.TrimSpace(q.Get("state"))
	if code == "" {
		if er := q.Get("error"); er != "" {
			return "", "", fmt.Errorf("OAuth 被拒: %s %s", er, q.Get("error_description"))
		}
		return "", "", errors.New("回调链接里没有 code 参数（请复制浏览器地址栏完整的 localhost 链接）")
	}
	return code, state, nil
}

// stateDeviceID 解码 aosi.<b64u>.<sig> 的 payload，取 dh(=device_id)
func stateDeviceID(state string) string {
	parts := strings.Split(strings.TrimSpace(state), ".")
	if len(parts) < 2 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		if payload, err = base64.URLEncoding.DecodeString(parts[1]); err != nil {
			return ""
		}
	}
	var p struct {
		DH string `json:"dh"`
	}
	if json.Unmarshal(payload, &p) != nil {
		return ""
	}
	return p.DH
}

func oauthStr(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// ===================== 管理面 HTTP 处理（路由在 handlers_admin.go 注册）=====================

// handleOverseaOAuthStart POST /admin/login/oversea/start  {vendor:zai|google, group}
// 过验证码 + 生成授权链接，返回 flow_id 与 authorize_url 供用户在自己浏览器打开。
func (h *AdminHandler) handleOverseaOAuthStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Vendor string `json:"vendor"`
		Group  string `json:"group"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "请求体解析失败")
		return
	}
	vendor := OAuthVendor(strings.ToLower(strings.TrimSpace(req.Vendor)))
	flowID, authURL, err := h.login.StartOverseaOAuth(vendor, req.Group)
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{
		"flow_id":       flowID,
		"authorize_url": authURL,
		"vendor":        string(vendor),
		"callback_uri":  overseaNavigateURI(vendor),
		"msg":           "在浏览器打开授权链接完成登录，再把跳转到的 localhost 回调链接粘回",
	})
}

// handleOverseaOAuthComplete POST /admin/login/oversea/complete  {flow_id, callback_url}
// 解析用户粘回的 localhost 回调链接 → 换 token → 入库为海外账号。
func (h *AdminHandler) handleOverseaOAuthComplete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		FlowID      string `json:"flow_id"`
		CallbackURL string `json:"callback_url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "请求体解析失败")
		return
	}
	a, err := h.login.CompleteOverseaOAuth(req.FlowID, req.CallbackURL)
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{"account": accountView(a)})
}
