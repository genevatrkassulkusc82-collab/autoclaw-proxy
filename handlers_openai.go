package main

// ---- OpenAI 兼容网关端点 ----
//   POST /v1/chat/completions  流式(SSE 透传)/非流式，usage 落库
//   GET  /v1/models            模型目录（远端同步 + 内置兜底）
//   GET  /v1/models?sync=1     强制从上游同步
//   鉴权: Authorization: Bearer <gateway-key>（管理端同一把 key）

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// OpenAIHandler OpenAI 兼容层
type OpenAIHandler struct {
	db   *DB
	llm  *LLMCaller
	pool *AccountPool
	auth *AuthManager
}

// NewOpenAIHandler 创建
func NewOpenAIHandler(db *DB, llm *LLMCaller, pool *AccountPool, auth *AuthManager) *OpenAIHandler {
	return &OpenAIHandler{db: db, llm: llm, pool: pool, auth: auth}
}

// Register 注册路由（仅 LLM API Key，不提供管理面访问）
func (h *OpenAIHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/chat/completions", h.auth.WrapAPIKey(h.handleChatCompletions))
	mux.HandleFunc("GET /v1/models", h.auth.WrapAPIKey(h.handleModels))
	mux.HandleFunc("GET /models", h.auth.WrapAPIKey(h.handleModels)) // 便捷别名
}

// openaiError OpenAI 风格错误响应
func openaiError(w http.ResponseWriter, status int, errType, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error": map[string]interface{}{
			"message": msg,
			"type":    errType,
			"code":    nil,
		},
	})
}

func (h *OpenAIHandler) handleModels(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("sync") == "1" {
		if _, err := h.llm.SyncCatalog(); err != nil {
			log.Printf("[openai] models 同步失败: %v", err)
			// 同步失败回退缓存/内置
		}
	}
	catalog := h.llm.Catalog()
	type modelObj struct {
		ID       string `json:"id"`
		Object   string `json:"object"`
		Created  int64  `json:"created"`
		OwnedBy  string `json:"owned_by"`
		Reasoning bool  `json:"reasoning,omitempty"`
		ContextWindow int64 `json:"context_window,omitempty"`
		MaxTokens     int64 `json:"max_tokens,omitempty"`
	}
	now := time.Now().Unix()
	out := make([]modelObj, 0, len(catalog)*2)
	for _, m := range catalog {
		out = append(out, modelObj{ID: m.ID, Object: "model", Created: now, OwnedBy: "autoclaw",
			Reasoning: m.Reasoning, ContextWindow: m.ContextWindow, MaxTokens: m.MaxTokens})
		// 同时暴露去前缀短名（OpenAI 客户端习惯 "auto" 而非 "zai_auto"）
		if short := stripModelPrefix(m.ID); short != m.ID {
			out = append(out, modelObj{ID: short, Object: "model", Created: now, OwnedBy: "autoclaw",
				Reasoning: m.Reasoning, ContextWindow: m.ContextWindow, MaxTokens: m.MaxTokens})
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"object": "list",
		"data":   out,
	})
}

func (h *OpenAIHandler) handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	rawBody, err := io.ReadAll(io.LimitReader(r.Body, 32<<20))
	if err != nil {
		openaiError(w, 400, "invalid_request_error", "读取请求体失败")
		return
	}
	var body map[string]interface{}
	if err := json.Unmarshal(rawBody, &body); err != nil {
		openaiError(w, 400, "invalid_request_error", "请求体不是合法 JSON")
		return
	}
	reqModel, _ := body["model"].(string)
	stream, _ := body["stream"].(bool)

	// 账号指定（可选扩展头，管理端测试用）: X-Account-Id
	var accountID int64
	if v := r.Header.Get("X-Account-Id"); v != "" {
		n, _ := parseInt(v)
		accountID = int64(n)
	}
	strategy := "round_robin"
	if v, _ := h.db.GetSetting("pool_strategy"); v != "" {
		strategy = v
	}

	start := time.Now()
	result, err := h.llm.ChatCompletions(r.Context(), body, accountID, strategy)
	if err != nil {
		status := 502
		errType := "upstream_error"
		msg := err.Error()
		if me, ok := err.(*ModelError); ok {
			status, errType, msg = 404, "invalid_request_error", me.Error()
		} else if err == errNoAccount {
			status, errType = 429, "no_available_account"
		} else if strings.Contains(msg, "需要重新登录") || strings.Contains(msg, "needs_login") {
			status, errType = 401, "account_unavailable"
		}
		h.db.InsertUsage(&UsageLog{Model: reqModel, Status: status, Error: truncate(msg, 400),
			LatencyMs: time.Since(start).Milliseconds()})
		openaiError(w, status, errType, msg)
		return
	}
	defer result.Resp.Body.Close()

	usage := &UsageLog{
		AccountID:  result.Account.ID,
		Model:      reqModel,
		RouteModel: result.Route,
		Status:     result.Resp.StatusCode,
		LatencyMs:  time.Since(start).Milliseconds(),
	}
	if stream {
		usage.Stream = 1
	}

	if result.Resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(result.Resp.Body, 64<<10))
		usage.Error = truncate(string(raw), 400)
		h.db.InsertUsage(usage)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(result.Resp.StatusCode)
		w.Write(raw)
		return
	}

	// 透传上游响应头（内容类型/缓存控制等）
	for _, k := range []string{"Content-Type", "Cache-Control"} {
		if v := result.Resp.Header.Get(k); v != "" {
			w.Header().Set(k, v)
		}
	}
	w.Header().Set("X-Account-Id", fmt.Sprintf("%d", result.Account.ID))
	w.Header().Set("X-Route-Model", result.Route)

	if !stream {
		raw, _ := io.ReadAll(io.LimitReader(result.Resp.Body, 64<<20))
		var parsed struct {
			Usage struct {
				PromptTokens     int64 `json:"prompt_tokens"`
				CompletionTokens int64 `json:"completion_tokens"`
			} `json:"usage"`
		}
		if json.Unmarshal(raw, &parsed) == nil {
			usage.PromptTok = parsed.Usage.PromptTokens
			usage.CompleteTok = parsed.Usage.CompletionTokens
		}
		usage.LatencyMs = time.Since(start).Milliseconds()
		h.db.InsertUsage(usage)
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(raw)))
		w.WriteHeader(http.StatusOK)
		w.Write(raw)
		return
	}

	// ---- SSE 流式透传 + usage 旁路采集 ----
	flusher, ok := w.(http.Flusher)
	if !ok {
		openaiError(w, 500, "streaming_unsupported", "响应器不支持流式")
		return
	}
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	scanner := bufio.NewScanner(result.Resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	ttft := false
	for scanner.Scan() {
		line := scanner.Bytes()
		// 原样转发（含空行分隔符）
		w.Write(line)
		w.Write([]byte("\n"))
		flusher.Flush()
		if !ttft && len(line) > 6 {
			ttft = true
			usage.TtftMs = time.Since(start).Milliseconds()
		}
		// 旁路解析 usage（stream_options.include_usage 末段 chunk）
		if len(line) > 6 && string(line[:6]) == "data: " {
			payload := strings.TrimSpace(string(line[6:]))
			if payload != "" && payload != "[DONE]" {
				var chunk struct {
					Usage *struct {
						PromptTokens     int64 `json:"prompt_tokens"`
						CompletionTokens int64 `json:"completion_tokens"`
					} `json:"usage"`
				}
				if json.Unmarshal([]byte(payload), &chunk) == nil && chunk.Usage != nil {
					usage.PromptTok = chunk.Usage.PromptTokens
					usage.CompleteTok = chunk.Usage.CompletionTokens
				}
			}
		}
	}
	usage.LatencyMs = time.Since(start).Milliseconds()
	h.db.InsertUsage(usage)
}
