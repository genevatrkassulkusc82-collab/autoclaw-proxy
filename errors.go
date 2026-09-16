package main

// ---- 上游错误屏蔽（参考 dumate-proxy sanitizeUpstreamError）----
// 原则：上游 4xx/5xx/网络异常的**原文与内部细节只进服务端日志**；
// 客户端只收到规范化的通用错误（OpenAI 错误体格式），不泄漏上游地址/错误体/trace/拨号信息。

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// upstreamError 面向客户端的屏蔽版上游错误
type upstreamError struct {
	code  int    // 上游状态码（0=传输层错误）
	msg   string // 客户端可见的通用提示
	reqID string // 上游请求关联 ID（仅用于日志/客户端提示后缀，非敏感）
}

func (e *upstreamError) Error() string { return e.msg }

// sanitizeUpstreamError 上游状态码 → 客户端安全错误
func sanitizeUpstreamError(code int, reqID string) *upstreamError {
	suffix := ""
	if reqID != "" {
		suffix = " (req " + truncateID(reqID, 16) + ")"
	}
	switch {
	case code == 0:
		return &upstreamError{code: 0, msg: "upstream temporarily unreachable" + suffix, reqID: reqID}
	case code == http.StatusUnauthorized:
		return &upstreamError{code: code, msg: "upstream authentication failed" + suffix, reqID: reqID}
	case code == http.StatusForbidden:
		return &upstreamError{code: code, msg: "upstream access denied" + suffix, reqID: reqID}
	case code == http.StatusTooManyRequests:
		return &upstreamError{code: code, msg: "upstream rate limited or quota exhausted" + suffix, reqID: reqID}
	case code >= 500:
		return &upstreamError{code: code, msg: fmt.Sprintf("upstream server error (%d)%s", code, suffix), reqID: reqID}
	default:
		return &upstreamError{code: code, msg: fmt.Sprintf("upstream request failed (%d)%s", code, suffix), reqID: reqID}
	}
}

// clientStatusForUpstream 上游状态码 → 返回给客户端的 HTTP 状态码（不直接透传上游码）
func clientStatusForUpstream(code int) int {
	switch {
	case code == http.StatusTooManyRequests:
		return http.StatusTooManyRequests // 429 语义对客户端有用（重试退避）
	case code == http.StatusUnauthorized, code == http.StatusForbidden:
		return http.StatusServiceUnavailable // 503：上游鉴权问题对客户端无意义，触发换号/重试
	case code >= 500:
		return http.StatusBadGateway // 502
	case code == 0:
		return http.StatusServiceUnavailable // 503 传输层
	default:
		return http.StatusBadGateway // 其它 4xx 统一 502，不暴露上游细分码
	}
}

// extractUpstreamReqID 从上游错误体提取请求关联 ID（logId/requestId/id/trace），用于日志关联
func extractUpstreamReqID(body []byte) string {
	var probe map[string]interface{}
	if err := json.Unmarshal(body, &probe); err != nil {
		return ""
	}
	for _, k := range []string{"requestId", "request_id", "logId", "log_id", "trace", "traceId", "id"} {
		if v, ok := probe[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

func truncateID(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
