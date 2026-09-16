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
	"sync"
	"time"

	"github.com/google/uuid"
)

// LLMCaller 上游 LLM 调用器
type LLMCaller struct {
	comboMu    sync.Mutex
	comboCache map[int64]string
	db         *DB
	pool       *AccountPool
}

// NewLLMCaller 创建调用器
func NewLLMCaller(db *DB, pool *AccountPool) *LLMCaller {
	return &LLMCaller{comboCache: map[int64]string{}, db: db, pool: pool}
}

var modelPrefixRe = regexp.MustCompile(`^[a-z]+_`)

// stripModelPrefix normalizeAutoClawRequestBodyModel: "zai_auto" → "auto"
func stripModelPrefix(id string) string { return modelPrefixRe.ReplaceAllString(id, "") }

// llmHeaders 组装上游请求头（openclaw.json 静态头 + 动态头，与网关 buildAutoClawRequestHeaders 对齐）
// lang 为空时回退默认 zh-CN（海外账号传 "en"）
func llmHeaders(at, routeModel, lang string) map[string]string {
	if lang == "" {
		lang = autoclawLang
	}
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
		"X-Lang":          lang,
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

	// 预计算"哪些区域的目录能解析该模型"（国内/海外清单可能不同）：
	// 调度时只在支持该模型的区域内选账号。只算一次，避免每账号重复查目录。
	servableRegions := map[Region]bool{}
	if accountID == 0 {
		for _, rg := range c.pool.RegionsWithAccounts() {
			if _, rerr := c.ResolveRoute(reqModel, rg); rerr == nil {
				servableRegions[rg] = true
			}
		}
	}

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
			// 只在"区域目录能解析该模型"的账号中选（国内/海外模型清单可能不同）
			a, err = c.pool.PickFiltered(strategy, func(acc *Account) bool {
				return servableRegions[accountRegion(acc)]
			})
			if err != nil {
				if err == errNoAccountForFilter {
					return nil, &ModelError{Model: reqModel} // 有账号但其区域目录无此模型
				}
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
	route, err := c.ResolveRoute(reqModel, accountRegion(a))
	if err != nil {
		return nil, err
	}
	at, err := c.pool.EnsureValidToken(a)
	if err != nil {
		return nil, err
	}

	tryCombos := func(token string) (*http.Response, string, error) {
		var lastResp *http.Response
		var lastCombo string
		for _, cb := range c.combosFor(a) {
			resp, terr := c.doCombo(ctx, a, route, requestBody, token, cb)
			if terr != nil {
				return nil, cb, terr
			}
			// 405/404=路径不匹配，401=token 对该区域无效 → 均试下一组合
			if resp.StatusCode == http.StatusMethodNotAllowed || resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusUnauthorized {
				lastResp, lastCombo = resp, cb
				continue
			}
			c.cacheCombo(a.ID, cb)
			return resp, cb, nil
		}
		if lastResp != nil {
			return lastResp, lastCombo, nil // 全部组合均 401/404/405 → 返回最后一个交由上层处理
		}
		return nil, "", nil
	}

	resp, combo, err := tryCombos(at)
	if err != nil {
		log.Printf("[llm] account=%d transport error: %v", a.ID, err)
		_ = c.db.BumpAccountFailure(a.ID, "transport: "+err.Error())
		return nil, sanitizeUpstreamError(0, "")
	}
	if resp == nil {
		return nil, sanitizeUpstreamError(http.StatusNotFound, "")
	}

	if resp.StatusCode == http.StatusUnauthorized {
		resp.Body.Close()
		log.Printf("[llm] account=%d 401, refreshing token", a.ID)
		newAT, rerr := c.pool.RefreshAccount(a, true)
		if rerr != nil {
			return nil, &errAccountCooldown{reason: "401 且刷新失败: " + rerr.Error()}
		}
		resp, combo, err = tryCombos(newAT)
		if err != nil {
			log.Printf("[llm] account=%d transport error (after refresh): %v", a.ID, err)
			return nil, sanitizeUpstreamError(0, "")
		}
		if resp == nil {
			return nil, sanitizeUpstreamError(http.StatusNotFound, "")
		}
	}
	_ = combo

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
		c.pool.MarkCooldown(a, 5*time.Minute, "500 invalid request body（疑似风控）")
		return nil, &errAccountCooldown{reason: "500 invalid request body"}
	case resp.StatusCode >= 500:
		defer resp.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		_ = c.db.BumpAccountFailure(a.ID, fmt.Sprintf("HTTP %d: %s", resp.StatusCode, truncate(string(raw), 200)))
		c.pool.MarkCooldown(a, 30*time.Second, fmt.Sprintf("上游 HTTP %d", resp.StatusCode))
		return nil, &errAccountCooldown{reason: fmt.Sprintf("上游 HTTP %d", resp.StatusCode)}
	case resp.StatusCode != http.StatusOK:
		defer resp.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		reqID := extractUpstreamReqID(raw)
		log.Printf("[llm] account=%d upstream %d reqID=%s: %s", a.ID, resp.StatusCode, reqID, truncate(string(raw), 300))
		_ = c.db.BumpAccountFailure(a.ID, fmt.Sprintf("HTTP %d reqID=%s", resp.StatusCode, reqID))
		return nil, sanitizeUpstreamError(resp.StatusCode, reqID)
	}

	return &LLMResult{Resp: resp, Account: a, Route: route, Attempts: 1}, nil
}

// combosFor 返回该账号的 (host, chatPath) 候选组合（缓存组合优先），用于自动匹配区域/路径
func (c *LLMCaller) combosFor(a *Account) []string {
	rg := accountRegion(a)
	other := RegionCN
	if rg == RegionCN {
		other = RegionOversea
	}
	hosts := []string{RegionHost(c.db, a), other.Profile().Host}
	paths := []string{"/chat/completions", "/v1/chat/completions"}
	var out []string
	c.comboMu.Lock()
	cached := c.comboCache[a.ID]
	c.comboMu.Unlock()
	if cached != "" {
		out = append(out, cached)
	}
	for _, h := range hosts {
		for _, p := range paths {
			cb := strings.TrimSuffix(h, "/") + llmProxyPath + p
			if cb != cached {
				out = append(out, cb)
			}
		}
	}
	return out
}

func (c *LLMCaller) cacheCombo(id int64, cb string) {
	c.comboMu.Lock()
	c.comboCache[id] = cb
	c.comboMu.Unlock()
}

func (c *LLMCaller) doCombo(ctx context.Context, a *Account, route string, requestBody map[string]interface{}, token, url string) (*http.Response, error) {
	body := make(map[string]interface{}, len(requestBody))
	for k, v := range requestBody {
		body[k] = v
	}
	body["model"] = stripModelPrefix(route)
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	for k, v := range llmHeaders(token, route, RegionLang(a)) {
		req.Header.Set(k, v)
	}
	stream, _ := body["stream"].(bool)
	timeout := 10 * time.Minute
	if !stream {
		timeout = 5 * time.Minute
	}
	client := ClientForProxy(c.pool.egress.ProxyURLForAccount(a), timeout)
	return client.Do(req)
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
func (c *LLMCaller) ResolveRoute(model string, region Region) (string, error) {
	model = strings.TrimSpace(model)
	if model == "" {
		return "", fmt.Errorf("model 不能为空")
	}
	catalog := c.Catalog(region)
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

// Catalog 指定区域的模型目录（远端缓存 + 内置兜底）
func (c *LLMCaller) Catalog(region Region) []RemoteModel {
	var models []RemoteModel
	if raw := c.db.LoadModelCatalog(region); len(raw) > 0 {
		json.Unmarshal(raw, &models)
	}
	if len(models) == 0 && region == DefaultRegion {
		models = builtinCatalog()
	}
	// 过滤该区域被禁用的模型 + 应用显示名覆盖
	overrides := c.db.ModelNameOverrides()
	out := models[:0]
	for _, m := range models {
		if c.db.IsModelDisabled(region, m.ID) {
			continue
		}
		if n, ok := overrides[m.ID]; ok && n != "" {
			m.Name = n
		}
		out = append(out, m)
	}
	return out
}

// RegionState 某模型在某区域的可用/启用状态
type RegionState struct {
	Region  string `json:"region"`
	Enabled bool   `json:"enabled"`
}

// ModelWithState 模型 + 各区域启用状态（含被禁用的区域，供 UI 展示/切换）
type ModelWithState struct {
	RemoteModel
	Regions []RegionState `json:"regions"`
}

// CatalogWithState 全区域目录聚合（含禁用状态）
func (c *LLMCaller) CatalogWithState() []ModelWithState {
	state := c.db.ModelToggleState()
	byID := map[string]*ModelWithState{}
	var order []string
	for _, rg := range AllRegionValues() {
		raw := c.db.LoadModelCatalog(rg)
		var models []RemoteModel
		if len(raw) > 0 {
			json.Unmarshal(raw, &models)
		}
		if len(models) == 0 && rg == DefaultRegion {
			models = builtinCatalog()
		}
		overrides := c.db.ModelNameOverrides()
		for _, m := range models {
			if n, ok := overrides[m.ID]; ok && n != "" {
				m.Name = n
			}
			if _, ok := byID[m.ID]; !ok {
				byID[m.ID] = &ModelWithState{RemoteModel: m}
				order = append(order, m.ID)
			}
			en := true
			if v, ok := state[string(rg)][m.ID]; ok {
				en = v
			}
			byID[m.ID].Regions = append(byID[m.ID].Regions, RegionState{Region: string(rg), Enabled: en})
		}
	}
	var out []ModelWithState
	for _, id := range order {
		out = append(out, *byID[id])
	}
	return out
}
// CatalogUnion 所有"有账号的区域"目录的并集（按 ID 去重），用于 /v1/models 默认列表。
// 同一 ID 在多区域都存在时只列一次——调度时再按账号区域各自解析路由。
func (c *LLMCaller) CatalogUnion() []RemoteModel {
	regions := c.pool.RegionsWithAccounts()
	if len(regions) == 0 {
		regions = []Region{DefaultRegion}
	}
	seen := map[string]bool{}
	var out []RemoteModel
	for _, rg := range regions {
		for _, m := range c.Catalog(rg) {
			if seen[m.ID] {
				continue
			}
			seen[m.ID] = true
			out = append(out, m)
		}
	}
	return out
}

// SyncCatalog 同步指定区域的模型目录（用该区域任一健康账号的 token）
func (c *LLMCaller) SyncCatalog(region Region) ([]RemoteModel, error) {
	a, err := c.pool.PickInRegion("round_robin", region)
	if err != nil {
		// 该区域无账号：用空账号匿名尝试（多半失败，保留兜底语义）
		a = &Account{Region: string(region)}
	}
	at := a.AccessToken
	if at != "" && TokenRemaining(at) < 2*time.Minute && a.ID > 0 {
		if fresh, ferr := c.pool.EnsureValidToken(a); ferr == nil {
			at = fresh
		}
	}
	client := NewUserAPIClient(RegionHost(c.db, a), c.pool.egress.ProxyURLForAccount(a))
	client.Lang = RegionLang(a)
	models, err := client.FetchModelCatalog(at)
	if err != nil {
		return nil, err
	}
	raw, _ := json.Marshal(models)
	if err := c.db.SaveModelCatalog(region, raw); err != nil {
		log.Printf("[models] %s 目录缓存写入失败: %v", region, err)
	}
	log.Printf("[models] %s 同步成功: %d 个模型", region, len(models))
	return models, nil
}

// SyncAllCatalogs 对所有"有账号的区域"分别同步目录；返回各区域同步到的模型数
func (c *LLMCaller) SyncAllCatalogs() map[string]int {
	out := map[string]int{}
	regions := c.pool.RegionsWithAccounts()
	if len(regions) == 0 {
		regions = []Region{DefaultRegion}
	}
	for _, rg := range regions {
		if ms, err := c.SyncCatalog(rg); err != nil {
			log.Printf("[models] %s 同步失败: %v", rg, err)
		} else {
			out[string(rg)] = len(ms)
		}
	}
	return out
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
// ModelWithRegions 模型 + 可用区域（同一模型可能国内/海外都有）
type ModelWithRegions struct {
	RemoteModel
	Regions []string `json:"regions"`
}

// CatalogWithRegions 全部区域目录聚合，标注每个模型的可用区域
func (c *LLMCaller) CatalogWithRegions() []ModelWithRegions {
	byID := map[string]*ModelWithRegions{}
	var order []string
	for _, rg := range AllRegionValues() {
		for _, m := range c.Catalog(rg) {
			if _, ok := byID[m.ID]; !ok {
				byID[m.ID] = &ModelWithRegions{RemoteModel: m}
				order = append(order, m.ID)
			}
			byID[m.ID].Regions = append(byID[m.ID].Regions, string(rg))
		}
	}
	var out []ModelWithRegions
	for _, id := range order {
		out = append(out, *byID[id])
	}
	return out
}

// SyncAllRegions 同步所有区域模型目录
func (c *LLMCaller) SyncAllRegions() map[Region]int {
	out := map[Region]int{}
	for _, rg := range AllRegionValues() {
		if models, err := c.SyncCatalog(rg); err == nil {
			out[rg] = len(models)
		} else {
			log.Printf("[models] 同步失败 region=%s: %v", rg, err)
			out[rg] = -1
		}
	}
	return out
}
