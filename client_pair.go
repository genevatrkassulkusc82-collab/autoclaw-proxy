package main

// ---- 客户端远程导入（配对码机制，参考 dumate-proxy login-client）----
// 场景：autoclaw-proxy 部署在无 AutoClaw 的服务器上时，由用户在自己 Windows 电脑运行
// autoclaw-client：配对码握手 → 本机读取/重置 AutoClaw 登录态 → 账号回传服务器入池。
// 服务端只负责：生成配对码（管理面会话鉴权）、校验配对码、接收账号并 upsert 入池。

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const pairCodeTTL = 10 * time.Minute

type pairCode struct {
	Code      string
	CreatedAt time.Time
	ExpiresAt time.Time
}

type pairStore struct {
	mu      sync.Mutex
	current *pairCode
}

var pairs = &pairStore{}

func generatePairCode() string {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // 去易混字符
	n, _ := rand.Int(rand.Reader, big.NewInt(1<<31))
	x := n.Int64()
	out := make([]byte, 6)
	for i := range out {
		out[i] = alphabet[(x>>uint(i*5))%int64(len(alphabet))]
		// 简单混合：再掺入随机
		r, _ := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		_ = r
		out[i] = alphabet[(x+int64(i)*7+r.Int64())%int64(len(alphabet))]
	}
	return string(out)
}

func (p *pairStore) issue() *pairCode {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	p.current = &pairCode{Code: generatePairCode(), CreatedAt: now, ExpiresAt: now.Add(pairCodeTTL)}
	return p.current
}

func (p *pairStore) valid(code string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.current == nil || time.Now().After(p.current.ExpiresAt) {
		return false
	}
	return p.current.Code == code
}

// ---- 管理面：配对码 ----

func (h *AdminHandler) handleClientCodeIssue(w http.ResponseWriter, r *http.Request) {
	pc := pairs.issue()
	writeJSON(w, 200, map[string]interface{}{
		"code":        pc.Code,
		"expires_at":  pc.ExpiresAt.Unix(),
		"ttl_seconds": int(time.Until(pc.ExpiresAt).Seconds()),
	})
}

func (h *AdminHandler) handleClientCodeCurrent(w http.ResponseWriter, r *http.Request) {
	pairs.mu.Lock()
	pc := pairs.current
	pairs.mu.Unlock()
	if pc == nil || time.Now().After(pc.ExpiresAt) {
		writeJSON(w, 200, map[string]interface{}{"code": ""})
		return
	}
	writeJSON(w, 200, map[string]interface{}{
		"code":        pc.Code,
		"expires_at":  pc.ExpiresAt.Unix(),
		"ttl_seconds": int(time.Until(pc.ExpiresAt).Seconds()),
	})
}

// ---- 客户端：握手 + 回传账号 ----

type clientPushAccount struct {
	UserID        string `json:"user_id"`
	Phone         string `json:"phone"`
	AccessToken   string `json:"access_token"`
	RefreshToken  string `json:"refresh_token"`
	DeviceID      string `json:"device_id"`
	PublicKeyPem  string `json:"public_key_pem"`
	PrivateKeyPem string `json:"private_key_pem"`
	DeviceSpoofed int    `json:"device_spoofed"`
	Group         string `json:"group"`
	Source        string `json:"source"`
	Region        string `json:"region"` // cn|oversea（空=按国内）
}

func clientCodeFromRequest(r *http.Request) string {
	var body struct {
		Code string `json:"code"`
	}
	// 允许 body 或 header
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	if body.Code == "" {
		body.Code = r.Header.Get("X-Pair-Code")
	}
	return normalizePairCode(body.Code)
}

func normalizePairCode(s string) string {
	out := []byte{}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' {
			c -= 32
		}
		out = append(out, c)
	}
	return string(out)
}

func handleClientHello(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code    string `json:"code"`
		Version string `json:"version"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	code := normalizePairCode(body.Code)
	if code == "" {
		code = normalizePairCode(r.Header.Get("X-Pair-Code"))
	}
	if code == "" || !pairs.valid(code) {
		writeErr(w, http.StatusUnauthorized, "配对码无效或已过期")
		return
	}
	cv := body.Version
	outdated := cv != Version
	disp := cv
	if disp == "" {
		disp = "旧版/未知"
	}
	resp := map[string]interface{}{
		"ok": true, "server": "autoclaw-proxy",
		"server_version": Version, "client_version": cv, "outdated": outdated,
	}
	if outdated {
		resp["msg"] = fmt.Sprintf("客户端版本(%s) ≠ 服务端(%s)，请重新下载最新客户端再使用", disp, Version)
	}
	writeJSON(w, 200, resp)
}

func (h *AdminHandler) handleClientPush(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	var req struct {
		Code    string            `json:"code"`
		Account clientPushAccount `json:"account"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		writeErr(w, 400, "请求体解析失败")
		return
	}
	code := normalizePairCode(req.Code)
	if code == "" {
		code = normalizePairCode(r.Header.Get("X-Pair-Code"))
	}
	if code == "" || !pairs.valid(code) {
		writeErr(w, http.StatusUnauthorized, "配对码无效或已过期")
		return
	}
	a := req.Account
	if a.AccessToken == "" || a.RefreshToken == "" || a.DeviceID == "" {
		writeErr(w, 400, "账号缺少 access_token/refresh_token/device_id")
		return
	}
	src := a.Source
	if src == "" {
		src = "client_import"
	}
	acct := &Account{
		UserID:        a.UserID,
		Phone:         a.Phone,
		AccessToken:   StripBearer(a.AccessToken),
		RefreshToken:  StripBearer(a.RefreshToken),
		DeviceID:      a.DeviceID,
		PublicKeyPem:  a.PublicKeyPem,
		PrivateKeyPem: a.PrivateKeyPem,
		DeviceSpoofed: a.DeviceSpoofed,
		AccountGroup:  a.Group,
		Region:        string(NormalizeRegion(a.Region)),
		Status:        "active",
		Enabled:       1,
		AtExp:         TokenExpiresAt(a.AccessToken),
		RtExp:         TokenExpiresAt(a.RefreshToken),
		Source:        src,
	}
	id, err := h.db.UpsertAccount(acct)
	if err != nil {
		writeErr(w, 500, "账号入库失败: "+err.Error())
		return
	}
	log.Printf("[client] 远程导入账号 id=%d user=%s source=%s region=%s", id, acct.UserID, src, acct.Region)
	resp := map[string]interface{}{"ok": true, "account_id": id}
	// 海外账号：自动补领活动积分（官方 App 登录会领，OAuth/导入流程不会，这里补上；幂等，已领返回 0）
	if NormalizeRegion(acct.Region) == RegionOversea {
		acct.ID = id
		if res, cerr := ClaimPromotionRewards(h.db, h.pool.egress, acct); cerr == nil {
			resp["promotion"] = res
			log.Printf("[client] 海外账号 %d 活动积分领取 total=%v", id, res["total_points"])
		} else {
			log.Printf("[client] 海外账号 %d 活动积分领取失败: %v", id, cerr)
		}
	}
	writeJSON(w, 200, resp)
}

// ---- 客户端下载（下载时把服务器地址写入 exe 地址槽，免配置） ----

const clientSlotMarker = "<<AUTOCLAW_SERVER_URL>>"
const clientSlotPad = 96

// Version 服务端版本。下载客户端(/client/download)时写入客户端的"版本槽"，
// 配对(hello)时客户端回报该版本，与服务端当前 Version 比对——不一致即提示重新下载（防止用旧 exe）。
const Version = "1.0.1"

const clientVersionMarker = "<<AUTOCLAW_CLIENT_VERSION>>"
const clientVersionPad = 32

// clientExeCandidates 客户端二进制候选路径（相对服务端可执行目录）
func clientExeCandidates() []string {
	exe, err := os.Executable()
	if err != nil {
		return nil
	}
	dir := filepath.Dir(exe)
	return []string{
		filepath.Join(dir, "clients", "autoclaw-client-windows-amd64.exe"),
		filepath.Join(dir, "autoclaw-client-windows-amd64.exe"),
	}
}

// patchClientBinary 将 origin 写入客户端二进制的地址槽
func patchClientBinary(origin string) ([]byte, error) {
	var raw []byte
	var err error
	for _, p := range clientExeCandidates() {
		raw, err = os.ReadFile(p)
		if err == nil {
			break
		}
	}
	if raw == nil {
		return nil, fmt.Errorf("未找到客户端二进制（clients/autoclaw-client-windows-amd64.exe）")
	}
	// 地址槽（必需）
	out, err := patchSlot(raw, clientSlotMarker, clientSlotPad, origin)
	if err != nil {
		return nil, err
	}
	// 版本槽（可选：老客户端无此槽则跳过，不影响下载）
	if patched, verr := patchSlot(out, clientVersionMarker, clientVersionPad, Version); verr == nil {
		out = patched
	}
	return out, nil
}

// patchSlot 把二进制里 marker+pad 的槽位替换为 value（不足补 \x00）
func patchSlot(raw []byte, marker string, pad int, value string) ([]byte, error) {
	idx := bytes.Index(raw, []byte(marker))
	if idx < 0 {
		return nil, fmt.Errorf("客户端二进制缺少槽 %s", marker)
	}
	if len(value) > pad {
		return nil, fmt.Errorf("槽 %s 值过长（>%d）", marker, pad)
	}
	slotEnd := idx + len(marker) + pad
	if slotEnd > len(raw) {
		return nil, fmt.Errorf("槽 %s 越界", marker)
	}
	out := make([]byte, len(raw))
	copy(out, raw)
	region := make([]byte, slotEnd-idx)
	copy(region, []byte(value)) // 其余保持 \x00
	copy(out[idx:slotEnd], region)
	return out, nil
}

func (h *AdminHandler) handleClientDownload(w http.ResponseWriter, r *http.Request) {
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	origin := scheme + "://" + r.Host
	blob, err := patchClientBinary(origin)
	if err != nil {
		writeErr(w, 404, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="autoclaw-client-windows-amd64.exe"`)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(blob)))
	w.Write(blob)
}
