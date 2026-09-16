package main

// ---- AutoClaw userapi 客户端 ----
// 协议来源: app.asar /out/main/index.js 逆向 + 生产端点实测（docs/03）
//   签名:  X-Auth-Sign = md5hex("{APP_ID}&{unix秒}&{APP_KEY}")
//   登录:  POST /userapi/v1/agent-send-code {source_id, device_id, phone}
//          POST /userapi/v1/agent-login/    {source_id, device_id, phone, code}
//   刷新:  POST /userapi/v1/refresh         {source_id, device_id, refresh_token}
//          400002(验签失败) → 降级 POST /userapi/v1/agent-refresh
//   模型:  GET  {proxy}/autoclaw-model-config → {"models":[{id,name,...}]}
//   信封:  {code:0, msg, data, trace, time}

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	// 主进程硬编码常量（bundle 提取）
	userapiAppID  = "100003"
	userapiAppKey = "38d2391985e2369a5fb8227d8e6cd5e5"

	autoclawAppVersion = "1.18.4" // X-Version，与官方客户端一致
	autoclawChannel    = "official"
	autoclawLang       = "zh-CN"
	autoclawSourceID   = "autoclaw"
	autoclawPlatformTm = "win" // X-Tm

	defaultUserapiHost = "https://autoglm-acceleration-api.zhipuai.cn"
	preUserapiHost     = "https://autoglm-pre-api.zhipuai.cn"

	llmProxyPath   = "/autoclaw-proxy/proxy/autoclaw"
	configBasePath = "/autoclaw-proxy/proxy/"
)

// UserAPIClient 封装签名与主机选择；每个账号组可绑定不同出口代理
type UserAPIClient struct {
	Host     string // userapi/代理主机（默认生产加速域名）
	ProxyURL string // 出口代理（空=直连）
	Timeout  time.Duration
	Lang     string // X-Lang（空=默认 zh-CN；海外账号传 "en"）
	// Bridge 可选：真实浏览器 HTTP 桥（go-rod 页面内 fetch），借用浏览器真实
	// TLS/HTTP2/TCP/cookie 指纹。用于被风控仅认官方客户端指纹的高风险端点（login）。
	Bridge func(method, url string, headers map[string]string, body string) (int, string, error)
}

// NewUserAPIClient 创建客户端
func NewUserAPIClient(host, proxyURL string) *UserAPIClient {
	if host == "" {
		host = defaultUserapiHost
	}
	return &UserAPIClient{Host: strings.TrimSuffix(host, "/"), ProxyURL: proxyURL, Timeout: 30 * time.Second}
}

// LLMBaseURL LLM 代理 base（{host}/autoclaw-proxy/proxy/autoclaw）
func (c *UserAPIClient) LLMBaseURL() string { return c.Host + llmProxyPath }

// authSign md5("{APP_ID}&{ts}&{APP_KEY}")
func authSign(ts string) string {
	sum := md5.Sum([]byte(userapiAppID + "&" + ts + "&" + userapiAppKey))
	return hex.EncodeToString(sum[:])
}

// commonHeaders 官方 commonHeaders() 等价头集合
// accessToken 可空（登录/发码接口无需登录态）
// autoclawUserAgent 官方 Electron 客户端 UA。阿里云 WAF(acw_tc) 与高风险 login 端点
// 按 UA 区分会话/风控；Go 默认 UA(Go-http-client) 会被拒(400001)。
const autoclawUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) AutoClaw/1.18.4 Chrome/120.0.6099.291 Electron/28.3.1 Safari/537.36"

func commonHeaders(accessToken string) map[string]string {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	h := map[string]string{
		"Content-Type":     "application/json",
		"Accept":           "*/*",
		"User-Agent":       autoclawUserAgent,
		"X-Version":        autoclawAppVersion,
		"X-Tm":             autoclawPlatformTm,
		"X-Product":        "autoclaw",
		"X-Auth-Appid":     userapiAppID,
		"X-Auth-TimeStamp": ts,
		"X-Auth-Sign":      authSign(ts),
		"X-Trace-Id":       uuid.NewString(),
		"X-Lang":           autoclawLang,
		"X-Channel":        autoclawChannel,
	}
	if tok := StripBearer(accessToken); tok != "" {
		h["authorization"] = "Bearer " + tok
	}
	return h
}

// headers 在 commonHeaders 基础上按客户端区域覆盖 X-Lang（海外=en，国内=zh-CN）
func (c *UserAPIClient) headers(accessToken string) map[string]string {
	h := commonHeaders(accessToken)
	if c.Lang != "" {
		h["X-Lang"] = c.Lang
	}
	return h
}

// APIEnvelope userapi 统一响应信封
type APIEnvelope struct {
	Code    int             `json:"code"`
	Msg     string          `json:"msg"`
	Data    json.RawMessage `json:"data"`
	Trace   string          `json:"trace"`
	Time    int64           `json:"time"`
	HTTPSta int             `json:"-"`
}

func (e *APIEnvelope) OK() bool { return e.Code == 0 && len(e.Data) > 0 }

// postRaw 原始 POST：自定义头+body，返回响应体字节（跟随重定向、带 cookie jar）
func (c *UserAPIClient) postRaw(path string, headers map[string]string, body []byte) ([]byte, error) {
	client := PlainClientForProxy(c.ProxyURL, c.Timeout)
	req, err := http.NewRequest(http.MethodPost, c.Host+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, sanitizeUpstreamError(resp.StatusCode, extractUpstreamReqID(raw))
	}
	return raw, nil
}

// post JSON POST 到 {host}{path}
// 重定向策略: 307/308（保留 method+body）手动跟随最多 3 次 —— 官方部分端点
// 有斜杠→无斜杠规范化重定向（如 /agent-login/ → /agent-login）；
// 301/302 不跟随（WAF 挑战/登录页交由调用方分类，沿用 zcode-proxy 语义）。
func (c *UserAPIClient) post(path string, body interface{}, accessToken string) (*APIEnvelope, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	url := c.Host + path

	// 浏览器桥：真实 Chrome 网络栈（fetch 自动跟随 307 并携带 cookie），单跳即可
	if c.Bridge != nil {
		hdrs := c.headers(accessToken)
		status, text, berr := c.Bridge("POST", url, hdrs, string(payload))
		if berr != nil {
			return nil, berr
		}
		env := &APIEnvelope{HTTPSta: status}
		if err := json.Unmarshal([]byte(text), env); err != nil {
			return nil, fmt.Errorf("响应非 JSON (HTTP %d): %s", status, truncate(text, 200))
		}
		return env, nil
	}

	client := FingerprintH2ClientForProxy(c.ProxyURL, c.Timeout)

	for redirects := 0; ; redirects++ {
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
		if err != nil {
			return nil, err
		}
		for k, v := range c.headers(accessToken) {
			req.Header.Set(k, v)
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		// 观测上游 Set-Cookie（风控/会话 cookie 是 login 400001 的常见根因；只记名不记值）
		if cs := resp.Cookies(); len(cs) > 0 {
			names := make([]string, 0, len(cs))
			for _, c := range cs {
				names = append(names, c.Name)
			}
			log.Printf("[userapi] %s Set-Cookie: %v", path, names)
		}
		if (resp.StatusCode == http.StatusTemporaryRedirect || resp.StatusCode == http.StatusPermanentRedirect) && redirects < 3 {
			loc := resp.Header.Get("Location")
			if loc != "" {
				target, err := req.URL.Parse(loc) // 支持相对 Location
				resp.Body.Close()
				if err != nil {
					return nil, fmt.Errorf("重定向目标解析失败: %w", err)
				}
				url = target.String()
				continue
			}
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		env := &APIEnvelope{HTTPSta: resp.StatusCode}
		if err := json.Unmarshal(raw, env); err != nil {
			return nil, fmt.Errorf("响应非 JSON (HTTP %d): %s", resp.StatusCode, truncate(string(raw), 200))
		}
		return env, nil
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// withWebInfo 官方 withWebInfo(): 注入 source_id + device_id
func withWebInfo(deviceID string, params map[string]interface{}) map[string]interface{} {
	body := map[string]interface{}{
		"source_id": autoclawSourceID,
		"device_id": deviceID,
	}
	for k, v := range params {
		body[k] = v
	}
	return body
}

// ---- 业务接口 ----

// SendCode 发送短信验证码（CN 通道无验证码参数；若风控要求会返回非 0 code）
func (c *UserAPIClient) SendCode(deviceID, phone string) (*APIEnvelope, error) {
	return c.post("/userapi/v1/agent-send-code", withWebInfo(deviceID, map[string]interface{}{
		"phone": phone,
	}), "")
}

// FlexID 兼容 user_id 既可能是数字(短信登录)也可能是字符串(Google/Z.ai OAuth 返回 hex 串)
type FlexID string

func (f *FlexID) UnmarshalJSON(b []byte) error {
	s := strings.Trim(strings.TrimSpace(string(b)), `"`)
	if s == "null" {
		s = ""
	}
	*f = FlexID(s)
	return nil
}

func (f FlexID) String() string { return string(f) }

// LoginResult agent-login / 海外 oauth-login 的 data
type LoginResult struct {
	AccessToken   string `json:"access_token"`
	RefreshToken  string `json:"refresh_token"`
	UserID        FlexID `json:"user_id"`
	UserName      string `json:"user_name"`
	FirstLogin    bool   `json:"first_login"`
	WebFirstLogin bool   `json:"web_first_login"`
}

// Login 短信验证码登录
// 必须 POST 带斜杠的 /agent-login/：该端点 307 跳转时 Set-Cookie acw_tc（阿里云 WAF 会话），
// 无斜杠端点校验该 cookie。官方 Electron 有 cookie jar 且自动跟随 307，故两跳都带 acw_tc；
// 我们依赖 post() 的 307/308 跟随 + 共享 cookie jar 复刻同一行为。直连无斜杠会因缺 acw_tc 得 400001。
func (c *UserAPIClient) Login(deviceID, phone, code string) (*APIEnvelope, *LoginResult, error) {
	env, err := c.post("/userapi/v1/agent-login/", withWebInfo(deviceID, map[string]interface{}{
		"phone": phone,
		"code":  code,
	}), "")
	if err != nil {
		return env, nil, err
	}
	if !env.OK() {
		return env, nil, nil
	}
	var lr LoginResult
	if err := json.Unmarshal(env.Data, &lr); err != nil {
		return env, nil, fmt.Errorf("登录响应解析失败: %w", err)
	}
	return env, &lr, nil
}

// RefreshResult refresh data
type RefreshResult struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// Refresh rt→at 刷新（含 400002 降级 agent-refresh，与官方 doRefreshToken 一致）
// 返回新 at/rt（裸 JWT）。调用方必须立即持久化（rt 轮换，旧 rt 作废）。
func (c *UserAPIClient) Refresh(deviceID, refreshToken, currentAT string) (*RefreshResult, error) {
	body := withWebInfo(deviceID, map[string]interface{}{
		"refresh_token": StripBearer(refreshToken),
	})
	env, err := c.post("/userapi/v1/refresh", body, currentAT)
	if err != nil {
		return nil, err
	}
	if env.Code == 400002 {
		// 签名校验失败 → 降级 agent-refresh（官方同款）
		env, err = c.post("/userapi/v1/agent-refresh", body, currentAT)
		if err != nil {
			return nil, err
		}
	}
	if !env.OK() {
		return nil, fmt.Errorf("刷新失败 code=%d msg=%s trace=%s", env.Code, env.Msg, env.Trace)
	}
	var rr RefreshResult
	if err := json.Unmarshal(env.Data, &rr); err != nil {
		return nil, fmt.Errorf("刷新响应解析失败: %w", err)
	}
	if rr.AccessToken == "" || rr.RefreshToken == "" {
		return nil, fmt.Errorf("刷新响应缺少 token (code=%d)", env.Code)
	}
	return &rr, nil
}

// UserProfile user-profile data（账号信息展示）
func (c *UserAPIClient) UserProfile(deviceID, accessToken string) (map[string]interface{}, error) {
	env, err := c.post("/userapi/v1/user-profile", withWebInfo(deviceID, map[string]interface{}{}), accessToken)
	if err != nil {
		return nil, err
	}
	if !env.OK() {
		return nil, fmt.Errorf("user-profile code=%d msg=%s", env.Code, env.Msg)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(env.Data, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// ---- 远端模型目录 ----

// RemoteModel 远端 autoclaw-model-config 的模型条目（截取关心字段）
type RemoteModel struct {
	ID                     string                 `json:"id"`
	Name                   string                 `json:"name"`
	Reasoning              bool                   `json:"reasoning"`
	Input                  []string               `json:"input"`
	ContextWindow          int64                  `json:"contextWindow"`
	MaxTokens              int64                  `json:"maxTokens"`
	Tooltip                string                 `json:"tooltip"`
	CreditConsumptionLevel string                 `json:"creditConsumptionLevel"`
	Metadata               map[string]interface{} `json:"metadata"`
}

// FetchModelCatalog GET {host}/autoclaw-proxy/proxy/autoclaw-model-config
func (c *UserAPIClient) FetchModelCatalog(accessToken string) ([]RemoteModel, error) {
	url := c.Host + configBasePath + "autoclaw-model-config"
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range c.headers(accessToken) {
		req.Header.Set(k, v)
	}
	client := ClientForProxy(c.ProxyURL, 15*time.Second)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("模型配置 HTTP %d: %s", resp.StatusCode, truncate(string(raw), 160))
	}
	var payload struct {
		Models []RemoteModel `json:"models"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, fmt.Errorf("模型配置解析失败: %w", err)
	}
	if len(payload.Models) == 0 {
		return nil, fmt.Errorf("模型配置为空")
	}
	return payload.Models, nil
}
