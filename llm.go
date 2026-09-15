package main

// ---- 上游 LLM 调用（智谱 autoclaw 代理，OpenAI Chat Completions wire format）----
// 协议要点（docs/01 实测）:
//   POST {host}/autoclaw-proxy/proxy/autoclaw/chat/completions
//   必带头: X-Authorization(JWT) / X-Harness-Type: zcode / X-Request-Model(路由ID) / X-Request-Id
//   body.model = 路由ID去前缀 (zai_auto → auto)，但路由实际由 X-Request-Model 头决定
//   401 → 刷新 token 重试一次；429/5xx → 账号冷却 + 换号

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// LLMCaller 上游 LLM 调用器
type LLMCaller struct {
	db   *DB
	pool *AccountPool
}

// NewLLMCaller 创建调用器
func NewLLMCaller(db *DB, pool *AccountPool) *LLMCaller {
	return &LLMCaller{db: db, pool: pool}
}

var modelPrefixRe = regexp.MustCompile(`^[a-z]+_`)

// stripModelPrefix normalizeAutoClawRequestBodyModel: "zai_auto" → "auto"
func stripModelPrefix(id string) string { return modelPrefixRe.ReplaceAllString(id, "") }

// llmHeaders 组装上游请求头（openclaw.json 静态头 + 动态头，与网关 buildAutoClawRequestHeaders 对齐）
func llmHeaders(at, routeModel string) map[string]string {
	return map[string]string{
		"Content-Type":    "application/json",
		"Accept":          "*/*",
		"X-Authorization": "Bearer " + StripBearer(at),
		"X-Request-Id":    uuid.NewString(),
		"X-Request-Model": routeModel,
		"X-Harness-Type":  "zcode", // 必带！缺失 → 500 invalid request body
		"X-Tm":            autoclawPlatformTm,
		"X-Version":       autoclawAppVersion,
		"X-Product":       "autoclaw",
		"X-Channel":       autoclawChannel,
		"X-Lang":          autoclawLang,
		"X-Client-Type":   "pc",
	}
}

// LLMResult 一次上游调用结果
type LLMResult struct {
	Resp     *http.Response // 调用方负责 Close（流式时为 SSE 管道）
	Account  *Account
	Route    string // 实际路由 ID
	Attempts int
}

// errAccountCooldown 触发换号重试的内部错误
type errAccountCooldown struct{ reason string }

func (e *errAccountCooldown) Error() string { return e.reason }

// ChatCompletions 发起对话补全。
// requestBody 为客户端原始 OpenAI 请求体（model 字段会被替换为上游 body model）。
// 内部处理: 账号选取 → 401 刷新重试 → 429/5xx 冷却换号（最多 maxAccounts 个账号）。
func (c *LLMCaller) ChatCompletions(ctx context.Context, requestBody map[string]interface{}, accountID int64, strategy string) (*LLMResult, error) {
	reqModel, _ := requestBody["model"].(string)
	tried := map[int64]bool{}
	var lastErr error

	for attempt := 0; attempt < 4; attempt++ {
		var a *Account
		var err error
		if accountID > 0 {
			a, err = c.pool.PickByRoute(accountID)
			if err != nil {
				return nil, err
			}
			if tried[a.ID] {
				break // 指定账号不轮换
			}
		} else {
			a, err = c.pool.Pick(strategy)
			if err != nil {
				if lastErr != nil {
					return nil, lastErr
				}
				return nil, err
			}
			// 跳过本轮已试过的账号
			if tried[a.ID] {
				all, _ := c.pool.db.ListAccounts()
				found := false
				for _, other := range all {
					if !tried[other.ID] && other.Enabled == 1 && other.Status != "needs_login" && other.Status != "disabled" {
						found = true
						break
					}
				}
				if !found {
					break
				}
				continue
			}
		}
		tried[a.ID] = true

		res, err := c.callWithAccount(ctx, a, reqModel, requestBody)
		if err == nil {
			return res, nil
		}
		lastErr = err
		var cd *errAccountCooldown
		if ok := asCooldownErr(err, &cd); ok {
			log.Printf("[llm] account=%d 冷却换号: %s", a.ID, cd.reason)
			continue // 换下一个账号
		}
		if accountID > 0 {
			return nil, err // 指定账号模式不轮换
		}
		// 其他错误（网络等）也尝试换号一次
	}
	if lastErr == nil {
		lastErr = errNoAccount
	}
	return nil, lastErr
}

func asCooldownErr(err error, target **errAccountCooldown) bool {
	if e, ok := err.(*errAccountCooldown); ok {
		*target = e
		return true
	}
	return false
}

// callWithAccount 单账号调用（含 401 刷新重试一次）
func (c *LLMCaller) callWithAccount(ctx context.Context, a *Account, reqModel string, requestBody map[string]interface{}) (*LLMResult, error) {
	route, err := c.ResolveRoute(reqModel)
	if err != nil {
		return nil, err
	}
	at, err := c.pool.EnsureValidToken(a)
	if err != nil {
		return nil, err
	}

	doCall := func(token string) (*http.Response, error) {
		body := make(map[string]interface{}, len(requestBody))
		for k, v := range requestBody {
			body[k] = v
		}
		body["model"] = stripModelPrefix(route) // 上游 body model 去前缀
		payload, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		base := strings.TrimSuffix(hostSetting(c.db), "/") + llmProxyPath
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/chat/completions", bytes.NewReader(payload))
		if err != nil {
			return nil, err
		}
		for k, v := range llmHeaders(token, route) {
			req.Header.Set(k, v)
		}
		stream, _ := body["stream"].(bool)
		timeout := 10 * time.Minute // 流式长连接；非流式也足够
		if !stream {
			timeout = 5 * time.Minute
		}
		client := ClientForProxy(c.pool.egress.ProxyURLForAccount(a), timeout)
		return client.Do(req)
	}

	resp, err := doCall(at)
	if err != nil {
		_ = c.db.BumpAccountFailure(a.ID, err.Error())
		return nil, err
	}

	if resp.StatusCode == http.StatusUnauthorized {
		// 401 → 强制刷新后重放一次（复刻 AutoClawZai401Retry 语义）
		resp.Body.Close()
		log.Printf("[llm] account=%d 401, refreshing token", a.ID)
		newAT, rerr := c.pool.RefreshAccount(a, true)
		if rerr != nil {
			return nil, &errAccountCooldown{reason: "401 且刷新失败: " + rerr.Error()}
		}
		resp, err = doCall(newAT)
		if err != nil {
			return nil, err
		}
	}

	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		defer resp.Body.Close()
		ra := resp.Header.Get("Retry-After")
		d := 60 * time.Second
		if n, err := parseInt(ra); err == nil && n > 0 && n < 3600 {
			d = time.Duration(n) * time.Second
		}
		c.pool.MarkCooldown(a, d, fmt.Sprintf("429 限流 (retry-after=%s)", ra))
		return nil, &errAccountCooldown{reason: "429"}
	case resp.StatusCode == 500 && isInvalidBodyRejection(resp):
		// 500 invalid request body：多半是风控/头问题，冷却该账号换号
		c.pool.MarkCooldown(a, 5*time.Minute, "500 invalid request body（疑似风控）")
		return nil, &errAccountCooldown{reason: "500 invalid request body"}
	case resp.StatusCode >= 500:
		defer resp.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		_ = c.db.BumpAccountFailure(a.ID, fmt.Sprintf("HTTP %d: %s", resp.StatusCode, truncate(string(raw), 200)))
		c.pool.MarkCooldown(a, 30*time.Second, fmt.Sprintf("上游 HTTP %d", resp.StatusCode))
		return nil, &errAccountCooldown{reason: fmt.Sprintf("上游 HTTP %d", resp.StatusCode)}
	}

	return &LLMResult{Resp: resp, Account: a, Route: route, Attempts: 1}, nil
}

func parseInt(s string) (int, error) {
	var n int
	_, err := fmt.Sscan(strings.TrimSpace(s), &n)
	return n, err
}

// isInvalidBodyRejection 探测 500 是否为 "invalid request body"（需读 body，读后需重建）
// 简化实现：只在 Content-Length 较小时读取判断；调用方在判定后会关闭响应。
func isInvalidBodyRejection(resp *http.Response) bool {
	if resp.ContentLength > 512 {
		return false
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 512))
	if err != nil {
		return false
	}
	// 读掉的 body 塞回，供上层日志（简化：直接判断）
	resp.Body = io.NopCloser(bytes.NewReader(raw))
	return strings.Contains(string(raw), "invalid request body")
}

// ---- 模型路由解析 ----

// ResolveRoute 把客户端请求的 model 名解析为上游路由 ID（X-Request-Model）
// 规则:
//  1. 精确命中远端目录/内置目录的 id（如 "zai_auto"）→ 原样
//  2. 命中去前缀名（如 "auto"、"glm-5.3-flash"）→ 对应完整 id
//  3. 命中别名（auto-fast/glm5.3 等宽松匹配）
//  4. 都不中 → 报 404 model not found
func (c *LLMCaller) ResolveRoute(model string) (string, error) {
	model = strings.TrimSpace(model)
	if model == "" {
		return "", fmt.Errorf("model 不能为空")
	}
	catalog := c.Catalog()
	// 1 精确
	for _, m := range catalog {
		if m.ID == model {
			return m.ID, nil
		}
	}
	// 2 去前缀
	for _, m := range catalog {
		if stripModelPrefix(m.ID) == model {
			return m.ID, nil
		}
	}
	// 3 宽松: 忽略大小写/连字符差异
	norm := func(s string) string {
		return strings.ToLower(strings.NewReplacer("-", "", "_", "", ".", "").Replace(s))
	}
	for _, m := range catalog {
		if norm(stripModelPrefix(m.ID)) == norm(model) || norm(m.ID) == norm(model) {
			return m.ID, nil
		}
	}
	return "", &ModelError{Model: model}
}

// ModelError 404 model not found（OpenAI 风格错误）
type ModelError struct{ Model string }

func (e *ModelError) Error() string {
	return fmt.Sprintf("The model `%s` does not exist", e.Model)
}

// Catalog 当前模型目录（远端缓存 + 内置兜底）
func (c *LLMCaller) Catalog() []RemoteModel {
	if raw := c.db.LoadModelCatalog(); len(raw) > 0 {
		var models []RemoteModel
		if json.Unmarshal(raw, &models) == nil && len(models) > 0 {
			return models
		}
	}
	return builtinCatalog()
}

// SyncCatalog 从上游同步模型目录（用任一健康账号的 token）
func (c *LLMCaller) SyncCatalog() ([]RemoteModel, error) {
	a, err := c.pool.Pick("round_robin")
	if err != nil {
		// 无账号也允许同步：模型配置接口实测需要登录头，但可先试匿名
		a = &Account{}
	}
	at := a.AccessToken
	if at != "" && TokenRemaining(at) < 2*time.Minute && a.ID > 0 {
		if fresh, ferr := c.pool.EnsureValidToken(a); ferr == nil {
			at = fresh
		}
	}
	client := NewUserAPIClient(hostSetting(c.db), c.pool.egress.ProxyURLForAccount(a))
	models, err := client.FetchModelCatalog(at)
	if err != nil {
		return nil, err
	}
	raw, _ := json.Marshal(models)
	if err := c.db.SaveModelCatalog(raw); err != nil {
		log.Printf("[models] 目录缓存写入失败: %v", err)
	}
	log.Printf("[models] 同步成功: %d 个模型", len(models))
	return models, nil
}

// builtinCatalog 内置兜底目录（2026-09-15 实测下发内容的快照）
func builtinCatalog() []RemoteModel {
	return []RemoteModel{
		{ID: "zai_auto", Name: "Auto", Reasoning: true, Input: []string{"text"}, ContextWindow: 1048576, MaxTokens: 393216, Tooltip: "根据任务自动选择合适模型"},
		{ID: "zai_auto-fast", Name: "Auto-Fast", Reasoning: true, Input: []string{"text", "image"}, ContextWindow: 1048576, MaxTokens: 393216, Tooltip: "智能匹配可用模型，速度优先"},
		{ID: "zaicoding_glm-5.3", Name: "GLM-5.3", Reasoning: true, Input: []string{"text"}, ContextWindow: 1048576, MaxTokens: 307200, Tooltip: "全新旗舰，Coding 与安全能力升级"},
		{ID: "zai_glm-5.3-flash", Name: "GLM-5.3-Flash", Reasoning: true, Input: []string{"text"}, ContextWindow: 200000, MaxTokens: 128000, Tooltip: "轻量快速"},
	}
}
