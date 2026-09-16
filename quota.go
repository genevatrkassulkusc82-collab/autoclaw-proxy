package main

// ---- 账户额度/用量查询（复刻官方「积分详情」「用量统计」两界面）----
// 上游无单一"剩余积分"数值端点；官方积分详情 = 会员/订阅状态(subscribe-info) + 套餐额度目录(product-info)。
// 用量统计 = 网关本地 usage_logs 聚合（真实经过本网关的用量）。
// 本模块：per-account 额度（上游会员信息 + 本地用量汇总）与用量明细/聚合接口。

import (
	"fmt"
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

// WalletBrief 积分钱包明细
type WalletBrief struct {
	WalletID    string `json:"wallet_id"`
	Type        string `json:"wallet_type"`
	Name        string `json:"wallet_name"`
	Scope       string `json:"wallet_scope"`
	Balance     int64  `json:"balance"`
	BalanceView string `json:"balance_view"`
	EffectiveAt string `json:"effective_at"`
	ExpiresAt   string `json:"expires_at"`
	Status      string `json:"status"`
}

// QuotaInfo 单账号额度视图
type QuotaInfo struct {
	AccountID    int64           `json:"account_id"`
	TotalBalance int64           `json:"total_balance"` // 剩余积分（上游 wallet-instances）
	Wallets      []WalletBrief   `json:"wallets"`
	IsMember     bool            `json:"is_member"`
	HasCodePlan  bool            `json:"has_code_plan"`
	Subscribe    json.RawMessage `json:"subscribe_list"`
	Plans        []PlanBrief     `json:"plans"`
	LocalUsage   UsageSummary    `json:"local_usage"`
	FetchedAt    int64           `json:"fetched_at"`
	UpstreamErr  string          `json:"upstream_error,omitempty"`
}

// PlanBrief 套餐额度摘要
type PlanBrief struct {
	Name        string `json:"name"`
	Level       int    `json:"level"`
	SendScoreDay  int64 `json:"send_score_day"`
	SendScoreMonth int64 `json:"send_score_month"`
	Price       int64  `json:"price"`
}

// UsageSummary 本地用量汇总
type UsageSummary struct {
	TotalRequests int64            `json:"total_requests"`
	OkRequests    int64            `json:"ok_requests"`
	TotalTokens   int64            `json:"total_tokens"`
	PromptTokens  int64            `json:"prompt_tokens"`
	CompTokens    int64            `json:"completion_tokens"`
	ByModel       map[string]int64 `json:"by_model"`
	LastUsedAt    int64            `json:"last_used_at"`
}

// fetchUpstreamQuota 用账号 token 调上游 subscribe-info + product-info
func (h *AdminHandler) fetchUpstreamQuota(a *Account) (totalBalance int64, wallets []WalletBrief, isMember, hasCodePlan bool, subscribe json.RawMessage, plans []PlanBrief, upErr string) {
	rg := accountRegion(a)
	other := RegionCN
	if rg == RegionCN {
		other = RegionOversea
	}
	hosts := []string{RegionHost(h.db, a), other.Profile().Host}
	hdrs := commonHeaders("Bearer " + a.AccessToken)

	// 自动匹配区域 host：逐个尝试，取第一个 code==0 的响应
	call := func(path string) ([]byte, error) {
		var lastErr error
		for _, host := range hosts {
			client := NewUserAPIClient(host, h.pool.egress.ProxyURLForAccount(a))
			raw, err := client.postRaw(path, hdrs, []byte("{}"))
			if err != nil {
				lastErr = err
				continue
			}
			var probe struct {
				Code int `json:"code"`
			}
			if json.Unmarshal(raw, &probe) == nil && probe.Code == 0 {
				return raw, nil
			}
			lastErr = fmt.Errorf("host=%s code!=0", host)
		}
		if lastErr == nil {
			lastErr = fmt.Errorf("无可用 host")
		}
		return nil, lastErr
	}
	if raw, err := call("/agent-assetmgr/api/v1/wallet-instances"); err == nil {
		var out struct {
			Code int `json:"code"`
			Data struct {
				TotalBalance   int64 `json:"total_balance"`
				WalletInstances []struct {
					WalletID    string `json:"wallet_id"`
					WalletType  string `json:"wallet_type"`
					WalletName  string `json:"wallet_name"`
					WalletScope string `json:"wallet_scope"`
					Balance     int64  `json:"balance"`
					BalanceView string `json:"balance_view"`
					EffectiveAt string `json:"effective_at"`
					ExpiresAt   string `json:"expires_at"`
					Status      string `json:"status"`
				} `json:"wallet_instances"`
			} `json:"data"`
		}
		if json.Unmarshal(raw, &out) == nil && out.Code == 0 {
			totalBalance = out.Data.TotalBalance
			for _, w := range out.Data.WalletInstances {
				wallets = append(wallets, WalletBrief{WalletID: w.WalletID, Type: w.WalletType, Name: w.WalletName,
					Scope: w.WalletScope, Balance: w.Balance, BalanceView: w.BalanceView,
					EffectiveAt: w.EffectiveAt, ExpiresAt: w.ExpiresAt, Status: w.Status})
			}
		}
	} else if upErr == "" {
		upErr = "wallet-instances: " + err.Error()
	}
	if raw, err := call("/agentpay/v1/assistant/subscribe-info"); err == nil {
		var out struct {
			Code int `json:"code"`
			Data struct {
				IsMember    bool            `json:"is_member"`
				HasCodePlan bool            `json:"has_code_plan"`
				Subscribe   json.RawMessage `json:"subscribe_list"`
			} `json:"data"`
		}
		if json.Unmarshal(raw, &out) == nil && out.Code == 0 {
			isMember = out.Data.IsMember
			hasCodePlan = out.Data.HasCodePlan
			subscribe = out.Data.Subscribe
		}
	} else {
		upErr = "subscribe-info: " + err.Error()
	}
	if raw, err := call("/agentpay/v1/assistant/product-info"); err == nil {
		var out struct {
			Code int `json:"code"`
			Data struct {
				MemberList []struct {
					ProductName     string `json:"product_name"`
					ProductLevel    int    `json:"product_level"`
					ProductPrice    int64  `json:"product_price"`
					SendScoreDay    int64  `json:"product_send_score_day"`
					SendScoreMonth  int64  `json:"product_send_score_month"`
				} `json:"member_list"`
			} `json:"data"`
		}
		if json.Unmarshal(raw, &out) == nil && out.Code == 0 {
			for _, m := range out.Data.MemberList {
				plans = append(plans, PlanBrief{Name: m.ProductName, Level: m.ProductLevel,
					SendScoreDay: m.SendScoreDay, SendScoreMonth: m.SendScoreMonth, Price: m.ProductPrice})
			}
		}
	} else if upErr == "" {
		upErr = "product-info: " + err.Error()
	}
	return
}

// localUsageSummary 本地 usage_logs 聚合
func (h *AdminHandler) localUsageSummary(accountID int64) UsageSummary {
	s := UsageSummary{ByModel: map[string]int64{}}
	row := h.db.conn.QueryRow(`SELECT COUNT(*), COALESCE(SUM(CASE WHEN status=200 THEN 1 ELSE 0 END),0),
		COALESCE(SUM(prompt_tokens+completion_tokens),0), COALESCE(SUM(prompt_tokens),0), COALESCE(SUM(completion_tokens),0),
		COALESCE(MAX(created_at),0) FROM usage_logs WHERE account_id=?`, accountID)
	var last int64
	_ = row.Scan(&s.TotalRequests, &s.OkRequests, &s.TotalTokens, &s.PromptTokens, &s.CompTokens, &last)
	s.LastUsedAt = last
	rows, err := h.db.conn.Query(`SELECT model, COALESCE(SUM(prompt_tokens+completion_tokens),0) FROM usage_logs WHERE account_id=? GROUP BY model ORDER BY 2 DESC`, accountID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var m string
			var t int64
			if rows.Scan(&m, &t) == nil {
				s.ByModel[m] = t
			}
		}
	}
	return s
}

// ---- handlers ----

func (h *AdminHandler) handleAccountQuota(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	a, err := h.db.GetAccount(id)
	if err != nil {
		writeErr(w, 404, err.Error())
		return
	}
	totalBalance, wallets, isMember, hasCodePlan, subscribe, plans, upErr := h.fetchUpstreamQuota(a)
	q := QuotaInfo{
		AccountID: id, TotalBalance: totalBalance, Wallets: wallets,
		IsMember: isMember, HasCodePlan: hasCodePlan,
		Subscribe: subscribe, Plans: plans,
		LocalUsage: h.localUsageSummary(id),
		FetchedAt:  time.Now().Unix(),
		UpstreamErr: upErr,
	}
	writeJSON(w, 200, q)
}

func (h *AdminHandler) handleAccountsQuotaAll(w http.ResponseWriter, r *http.Request) {
	accounts, err := h.db.ListAccounts()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	out := make([]QuotaInfo, 0, len(accounts))
	for _, a := range accounts {
		totalBalance, wallets, isMember, hasCodePlan, _, plans, upErr := h.fetchUpstreamQuota(a)
		out = append(out, QuotaInfo{
			AccountID: a.ID, TotalBalance: totalBalance, Wallets: wallets,
			IsMember: isMember, HasCodePlan: hasCodePlan,
			Plans: plans, LocalUsage: h.localUsageSummary(a.ID),
			FetchedAt: time.Now().Unix(), UpstreamErr: upErr,
		})
	}
	writeJSON(w, 200, map[string]interface{}{"quotas": out})
}

func (h *AdminHandler) handleAccountUsage(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	rows, err := h.db.conn.Query(`SELECT id,model,route_model,status,stream,prompt_tokens,completion_tokens,latency_ms,ttft_ms,created_at
		FROM usage_logs WHERE account_id=? ORDER BY id DESC LIMIT ?`, id, limit)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	type rec struct {
		ID int64 `json:"id"`; Model string `json:"model"`; Route string `json:"route"`
		Status int `json:"status"`; Stream int `json:"stream"`
		Prompt int64 `json:"prompt_tokens"`; Comp int64 `json:"completion_tokens"`
		Latency int64 `json:"latency_ms"`; Ttft int64 `json:"ttft_ms"`; At int64 `json:"created_at"`
	}
	list := []rec{}
	for rows.Next() {
		var x rec
		if rows.Scan(&x.ID, &x.Model, &x.Route, &x.Status, &x.Stream, &x.Prompt, &x.Comp, &x.Latency, &x.Ttft, &x.At) == nil {
			list = append(list, x)
		}
	}
	writeJSON(w, 200, map[string]interface{}{
		"summary": h.localUsageSummary(id),
		"records": list,
	})
}
