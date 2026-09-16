package main

// ---- 海外活动积分领取（复刻官方 grantPromotionReward）----
// 官方 App 登录后会拉 autoclaw-promotion-config，并对"进行中"的活动弹窗调 promotion-reward 领取
// "活动积分(campaign)"。本网关复刻该流程：对每个进行中的 modal 用 sendReward / timingReward 各试一次，
// 累计实际到账 points（服务端幂等：已领过/不符合条件返回 points:0，不会重复发放）。
//
// 端点（host = 账号区域主机，海外为 autoglm-api.autoglm.ai）：
//   GET  /autoclaw-proxy/proxy/autoclaw-promotion-config   （Authorization 头，commonHeaders）
//   POST /autoclaw-proxy/proxy/autoclaw-promotion-reward    （X-Authorization 头）body {modal_id, reward_type}
//
// 实测响应：{"data":{"points":<int>,"reward_type":"sendReward|timingReward"}}

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// promoModal promotion-config 里的活动弹窗（只取关心的字段）
type promoModal struct {
	ModalID   string `json:"modal_id"`
	ID        string `json:"id"`
	Name      string `json:"name"`
	StartTime int64  `json:"startTime"` // ms
	EndTime   int64  `json:"endTime"`   // ms
}

// promoHeaders promotion 接口请求头：commonHeaders（authorization + MD5 签名 + 静态头）+ 区域 X-Lang；
// grant 接口官方额外带 X-Authorization（getNewbieGuideAuthHeaders），这里一并加上。
func promoHeaders(tok, lang string, withXAuth bool) map[string]string {
	h := commonHeaders(tok)
	if lang != "" {
		h["X-Lang"] = lang
	}
	if withXAuth {
		h["X-Authorization"] = "Bearer " + StripBearer(tok)
	}
	return h
}

func promoDo(client *http.Client, method, url string, headers map[string]string, body []byte) ([]byte, int, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		return nil, 0, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return raw, resp.StatusCode, nil
}

// ClaimPromotionRewards 领取该账号当前可领的活动积分。
// 返回 {total_points, claimed:[{modal_id,name,reward_type,points}], modals_seen, active_modals}。
func ClaimPromotionRewards(db *DB, egress *EgressResolver, a *Account) (map[string]interface{}, error) {
	if a == nil || strings.TrimSpace(a.AccessToken) == "" {
		return nil, fmt.Errorf("账号无 access_token")
	}
	host := strings.TrimSuffix(RegionHost(db, a), "/")
	lang := RegionLang(a)
	tok := a.AccessToken
	client := ClientForProxy(egress.ProxyURLForAccount(a), 30*time.Second)
	proxyBase := host + "/autoclaw-proxy/proxy/"

	// 1) 拉活动配置
	raw, st, err := promoDo(client, "GET", proxyBase+"autoclaw-promotion-config", promoHeaders(tok, lang, false), nil)
	if err != nil {
		return nil, err
	}
	if st != http.StatusOK {
		return nil, fmt.Errorf("promotion-config HTTP %d: %s", st, truncate(string(raw), 160))
	}
	var cfg struct {
		Code int `json:"code"`
		Data struct {
			Modals []promoModal `json:"modals"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil || cfg.Code != 0 {
		return nil, fmt.Errorf("promotion-config 解析失败: %s", truncate(string(raw), 160))
	}

	// 2) 对进行中的 modal 逐个尝试领取（sendReward / timingReward）
	now := time.Now().UnixMilli()
	total := 0
	active := 0
	claimed := []map[string]interface{}{}
	for _, m := range cfg.Data.Modals {
		mid := m.ModalID
		if mid == "" {
			mid = m.ID
		}
		if mid == "" {
			continue
		}
		if m.StartTime > 0 && now < m.StartTime {
			continue
		}
		if m.EndTime > 0 && now > m.EndTime {
			continue
		}
		active++
		for _, rt := range []string{"sendReward", "timingReward"} {
			body, _ := json.Marshal(map[string]string{"modal_id": mid, "reward_type": rt})
			rb, rst, gerr := promoDo(client, "POST", proxyBase+"autoclaw-promotion-reward", promoHeaders(tok, lang, true), body)
			if gerr != nil || rst != http.StatusOK {
				continue
			}
			var gr struct {
				Data struct {
					Points     int    `json:"points"`
					RewardType string `json:"reward_type"`
				} `json:"data"`
			}
			if json.Unmarshal(rb, &gr) == nil && gr.Data.Points > 0 {
				total += gr.Data.Points
				claimed = append(claimed, map[string]interface{}{
					"modal_id": mid, "name": m.Name, "reward_type": rt, "points": gr.Data.Points,
				})
			}
		}
	}
	return map[string]interface{}{
		"total_points":  total,
		"claimed":       claimed,
		"modals_seen":   len(cfg.Data.Modals),
		"active_modals": active,
	}, nil
}

// handleClaimRewards POST /admin/accounts/{id}/claim-rewards —— 手动「一键领取活动积分」
func (h *AdminHandler) handleClaimRewards(w http.ResponseWriter, r *http.Request) {
	a, err := h.db.GetAccount(pathID(r))
	if err != nil {
		writeErr(w, 404, err.Error())
		return
	}
	tok, err := h.pool.EnsureValidToken(a)
	if err != nil {
		writeErr(w, 502, "token 无效/刷新失败: "+err.Error())
		return
	}
	a.AccessToken = tok
	res, err := ClaimPromotionRewards(h.db, h.pool.egress, a)
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, res)
}
