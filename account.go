package main

// ---- 账号池：选择策略 / 状态机 / 每账号刷新锁 ----
// 状态机:
//   active      可用
//   cooldown    429/5xx 退避（cooldown_until 到期自动回 active）
//   refreshing  正在刷新（瞬态）
//   needs_login rt 失效/刷新失败（需重新登录）
//   disabled    手动停用

import (
	"errors"
	"fmt"
	"log"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// AccountPool 账号池
type AccountPool struct {
	db   *DB
	egress *EgressResolver

	mu        sync.Mutex
	rrIndex   int
	refreshMu sync.Map // accountID → *sync.Mutex（刷新串行化）
}

// EgressResolver 账号组 → 出口代理 URL
type EgressResolver struct {
	db *DB
}

// ProxyURLForAccount 组绑定节点 → 默认节点 → 全局设置 upstream_proxy → 直连
func (e *EgressResolver) ProxyURLForAccount(a *Account) string {
	if a != nil {
		if node, err := e.db.ProxyNodeForGroup(a.AccountGroup); err == nil && node != nil {
			if u := ProxyURLForNode(node); u != "" {
				return u
			}
		}
	}
	if v, _ := e.db.GetSetting("upstream_proxy"); strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return ""
}

// NewAccountPool 创建账号池
func NewAccountPool(db *DB) *AccountPool {
	return &AccountPool{db: db, egress: &EgressResolver{db: db}}
}

// Egress 暴露出口解析器（userapi/llm 客户端构造用）
func (p *AccountPool) Egress() *EgressResolver { return p.egress }

// accountLock 每账号互斥（刷新串行）
func (p *AccountPool) accountLock(id int64) *sync.Mutex {
	v, _ := p.refreshMu.LoadOrStore(id, &sync.Mutex{})
	return v.(*sync.Mutex)
}

var errNoAccount = errors.New("无可用账号（全部冷却/失效/未添加）")

// Pick 按策略选取可用账号；cooldown 到期自动复活
// strategy: round_robin(默认) | random | least_used
func (p *AccountPool) Pick(strategy string) (*Account, error) {
	all, err := p.db.ListAccounts()
	if err != nil {
		return nil, err
	}
	now := time.Now().UnixMilli()
	var usable []*Account
	for _, a := range all {
		if a.Enabled != 1 || a.Status == "disabled" || a.Status == "needs_login" {
			continue
		}
		if a.Status == "cooldown" {
			if a.CooldownUntil > 0 && now >= a.CooldownUntil {
				// 冷却到期自动复活
				_ = p.db.SetAccountStatus(a.ID, "active", "")
				a.Status = "active"
			} else {
				continue
			}
		}
		usable = append(usable, a)
	}
	if len(usable) == 0 {
		return nil, errNoAccount
	}
	switch strategy {
	case "random":
		return usable[rand.Intn(len(usable))], nil
	case "least_used":
		sort.Slice(usable, func(i, j int) bool { return usable[i].TotalRequests < usable[j].TotalRequests })
		return usable[0], nil
	default: // round_robin
		p.mu.Lock()
		idx := p.rrIndex % len(usable)
		p.rrIndex++
		p.mu.Unlock()
		return usable[idx], nil
	}
}

// PickByRoute 指定账号（管理端测试用）
func (p *AccountPool) PickByRoute(id int64) (*Account, error) {
	return p.db.GetAccount(id)
}

// MarkCooldown 429/5xx 退避
func (p *AccountPool) MarkCooldown(a *Account, d time.Duration, reason string) {
	until := time.Now().Add(d)
	if err := p.db.SetAccountCooldown(a.ID, until, reason); err != nil {
		log.Printf("[pool] cooldown 写入失败 account=%d: %v", a.ID, err)
	}
	log.Printf("[pool] account=%d cooldown %s reason=%s", a.ID, d, reason)
}

// MarkNeedsLogin rt 失效
func (p *AccountPool) MarkNeedsLogin(a *Account, reason string) {
	_ = p.db.SetAccountStatus(a.ID, "needs_login", reason)
	log.Printf("[pool] account=%d needs_login: %s", a.ID, reason)
}

// RefreshAccount rt→at 刷新（每账号串行；成功后立即持久化）
// force=false 时若 at 仍有效（>5min）直接返回当前 at
func (p *AccountPool) RefreshAccount(a *Account, force bool) (string, error) {
	if !force && a.AccessToken != "" && TokenRemaining(a.AccessToken) > 5*time.Minute {
		return a.AccessToken, nil
	}
	lock := p.accountLock(a.ID)
	lock.Lock()
	defer lock.Unlock()

	// 双检：等锁期间可能已被其他请求刷新
	fresh, err := p.db.GetAccount(a.ID)
	if err != nil {
		return "", err
	}
	if !force && fresh.AccessToken != "" && TokenRemaining(fresh.AccessToken) > 5*time.Minute {
		return fresh.AccessToken, nil
	}
	if fresh.RefreshToken == "" {
		p.MarkNeedsLogin(fresh, "无 refresh_token")
		return "", errors.New("账号缺少 refresh_token，需要重新登录")
	}

	client := NewUserAPIClient(hostSetting(p.db), p.egress.ProxyURLForAccount(fresh))
	rr, err := client.Refresh(fresh.DeviceID, fresh.RefreshToken, fresh.AccessToken)
	if err != nil {
		msg := err.Error()
		// 400000/rt 过期 → needs_login；网络错误保持原状态待重试
		if strings.Contains(msg, "code=400000") || strings.Contains(msg, "code=400001") ||
			strings.Contains(msg, "code=400003") || strings.Contains(msg, "未登录") {
			p.MarkNeedsLogin(fresh, msg)
		} else {
			_ = p.db.BumpAccountFailure(fresh.ID, msg)
		}
		return "", err
	}
	newAT, newRT := StripBearer(rr.AccessToken), StripBearer(rr.RefreshToken)
	if err := p.db.UpdateAccountTokens(fresh.ID, newAT, newRT); err != nil {
		return "", fmt.Errorf("刷新成功但持久化失败（新 rt 未落库，立即重试！）: %w", err)
	}
	log.Printf("[pool] account=%d token refreshed, at_exp=%d", fresh.ID, TokenExpiresAt(newAT))
	return newAT, nil
}

// EnsureValidToken 返回有效 at（必要时刷新）
func (p *AccountPool) EnsureValidToken(a *Account) (string, error) {
	if a.AccessToken != "" && TokenRemaining(a.AccessToken) > 2*time.Minute {
		return a.AccessToken, nil
	}
	return p.RefreshAccount(a, true)
}

// hostSetting userapi/LLM 主机（settings 可覆盖，默认生产加速域名）
func hostSetting(db *DB) string {
	if v, _ := db.GetSetting("upstream_host"); strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return defaultUserapiHost
}

// SMSLoginFlow 在线验证码登录流程状态（phone → 会话）
type SMSLoginFlow struct {
	Device    *DeviceIdentity
	Spoofed   int // 1=伪造新设备 0=复用本机真实设备
	Phone     string
	CreatedAt time.Time
	SentAt    time.Time
	ProxyURL  string
}

// LoginManager 在线验证码登录管理（每流程伪造新设备身份）
type LoginManager struct {
	mu       sync.Mutex
	flows    map[string]*SMSLoginFlow // flowID → flow
	db       *DB
	pool     *AccountPool
	browser  *BrowserService // 浏览器 HTTP 桥（真实指纹），nil 则用 Go 客户端
}

// NewLoginManager 创建登录管理器
func NewLoginManager(db *DB, pool *AccountPool, browser *BrowserService) *LoginManager {
	lm := &LoginManager{flows: map[string]*SMSLoginFlow{}, db: db, pool: pool, browser: browser}
	go lm.gcLoop()
	return lm
}

// newLoginClient 登录专用客户端：优先浏览器桥（真实 TLS/HTTP2 指纹），否则 Go utls+h2
func (lm *LoginManager) newLoginClient(proxyURL string) *UserAPIClient {
	c := NewUserAPIClient(hostSetting(lm.db), proxyURL)
	if lm.browser != nil {
		c.Bridge = lm.browser.HTTPJSON
	}
	return c
}

func (lm *LoginManager) gcLoop() {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for range t.C {
		lm.mu.Lock()
		for id, f := range lm.flows {
			if time.Since(f.CreatedAt) > 30*time.Minute {
				delete(lm.flows, id)
			}
		}
		lm.mu.Unlock()
	}
}

// StartLogin 创建登录流程并发送短信验证码。
// useRealDevice=true 时复用本机 AutoClaw 真实设备身份（绕过"换设备"风控，推荐用于已绑定账号）；
// false 时现场伪造全新 Ed25519 设备身份（与官方客户端设备隔离）。
func (lm *LoginManager) StartLogin(phone string, group string, useRealDevice bool) (flowID string, err error) {
	phone = normalizePhone(phone)
	if phone == "" {
		return "", errors.New("手机号格式不正确")
	}
	var dev *DeviceIdentity
	spoofed := 1
	if useRealDevice {
		dev, err = LoadLocalDeviceIdentity()
		if err != nil {
			return "", fmt.Errorf("加载本机真实设备身份失败（可改用伪造新设备）: %w", err)
		}
		spoofed = 0
	} else {
		dev, err = GenerateDeviceIdentity()
		if err != nil {
			return "", fmt.Errorf("生成设备身份失败: %w", err)
		}
	}
	flow := &SMSLoginFlow{Device: dev, Spoofed: spoofed, Phone: phone, CreatedAt: time.Now(), ProxyURL: lm.pool.egress.ProxyURLForAccount(&Account{AccountGroup: group})}
	client := lm.newLoginClient(flow.ProxyURL)
	env, err := client.SendCode(dev.DeviceID, phone)
	if err != nil {
		return "", fmt.Errorf("发送验证码失败: %w", err)
	}
	if env.Code != 0 {
		return "", fmt.Errorf("发送验证码被拒 code=%d msg=%s trace=%s", env.Code, env.Msg, env.Trace)
	}
	flow.SentAt = time.Now()
	id := uuid.NewString()
	lm.mu.Lock()
	lm.flows[id] = flow
	lm.mu.Unlock()
	tag := "伪造新设备"
	if spoofed == 0 {
		tag = "本机真实设备"
	}
	log.Printf("[login] flow=%s phone=%s device=%s (%s) code sent", id[:8], maskPhone(phone), dev.DeviceID[:12], tag)
	return id, nil
}

// CompleteLogin 提交短信验证码完成登录并入库
func (lm *LoginManager) CompleteLogin(flowID, code string, group string) (*Account, error) {
	lm.mu.Lock()
	flow := lm.flows[flowID]
	delete(lm.flows, flowID) // 一次性
	lm.mu.Unlock()
	if flow == nil {
		return nil, errors.New("登录流程不存在或已过期，请重新发送验证码")
	}
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return nil, errors.New("验证码格式有误，请填写6位数字验证码")
	}
	client := lm.newLoginClient(flow.ProxyURL)
	env, lr, err := client.Login(flow.Device.DeviceID, flow.Phone, code)
	if err != nil {
		return nil, fmt.Errorf("登录请求失败: %w", err)
	}
	if lr == nil {
		elapsed := time.Since(flow.SentAt).Round(time.Second)
		log.Printf("[login] verify failed code=%d msg=%s elapsed_since_send=%s device=%s",
			env.Code, env.Msg, elapsed, flow.Device.DeviceID[:12])
		hint := ""
		if env.Code == 400001 {
			hint = fmt.Sprintf("（距发码 %s；400001 通常=验证码过期/输错/被更新的发码覆盖，请重发后立即提交最新一条）", elapsed)
		}
		return nil, fmt.Errorf("登录失败 code=%d msg=%s trace=%s%s", env.Code, env.Msg, env.Trace, hint)
	}
	a := &Account{
		UserID:        lr.UserID.String(),
		Phone:         flow.Phone,
		AccessToken:   StripBearer(lr.AccessToken),
		RefreshToken:  StripBearer(lr.RefreshToken),
		DeviceID:      flow.Device.DeviceID,
		PublicKeyPem:  flow.Device.PublicKeyPem,
		PrivateKeyPem: flow.Device.PrivateKeyPem,
		DeviceSpoofed: flow.Spoofed,
		AccountGroup:  group,
		Status:        "active",
		Enabled:       1,
		AtExp:         TokenExpiresAt(lr.AccessToken),
		RtExp:         TokenExpiresAt(lr.RefreshToken),
		Source:        "sms_login",
	}
	id, err := lm.db.UpsertAccount(a)
	if err != nil {
		return nil, fmt.Errorf("账号入库失败: %w", err)
	}
	a.ID = id
	tag := "伪造设备"
	if flow.Spoofed == 0 {
		tag = "真实设备"
	}
	log.Printf("[login] account=%d user=%s phone=%s 登录成功（%s %s…）",
		id, a.UserID, maskPhone(a.Phone), tag, a.DeviceID[:12])
	return a, nil
}

func normalizePhone(p string) string {
	p = strings.TrimSpace(p)
	p = strings.TrimPrefix(p, "+86")
	if len(p) != 11 || p[0] != '1' {
		return ""
	}
	for _, c := range p {
		if c < '0' || c > '9' {
			return ""
		}
	}
	return p
}

func maskPhone(p string) string {
	if len(p) != 11 {
		return p
	}
	return p[:3] + "****" + p[7:]
}
