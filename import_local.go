package main

// ---- 本地账号导入：从已登录的 AutoClaw 客户端提取凭证 ----
// 读取（全部只读，不修改官方文件）:
//   %APPDATA%\AutoClaw\Local State          → os_crypt.encrypted_key（DPAPI → AES key）
//   %APPDATA%\AutoClaw\auth.json            → token/refreshToken(enc:v10)、deviceId、userInfo
//   %APPDATA%\AutoClaw\identity\device.json → Ed25519 设备密钥对（导入真实设备身份）
// 注意: 导入的账号与官方客户端共享同一 rt。若两边同时触发刷新会互相踢
//       （rt 轮换单次有效）。建议导入后在网关侧禁用自动刷新竞争：
//       官方客户端运行期间网关只消费 at，401 时优先重读客户端文件而不是自行刷新。

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// LocalAutoClawPaths 官方客户端数据目录探测
type LocalAutoClawPaths struct {
	AppDataDir string // %APPDATA%\AutoClaw
	StateDir   string // %USERPROFILE%\.openclaw-autoclaw
}

// DetectLocalAutoClaw 探测本机 AutoClaw 安装数据
func DetectLocalAutoClaw() (*LocalAutoClawPaths, error) {
	appdata := os.Getenv("APPDATA")
	home := os.Getenv("USERPROFILE")
	if appdata == "" || home == "" {
		return nil, errors.New("非 Windows 用户环境或缺少 APPDATA/USERPROFILE")
	}
	p := &LocalAutoClawPaths{
		AppDataDir: filepath.Join(appdata, "AutoClaw"),
		StateDir:   filepath.Join(home, ".openclaw-autoclaw"),
	}
	if _, err := os.Stat(filepath.Join(p.AppDataDir, "auth.json")); err != nil {
		return nil, fmt.Errorf("未找到 AutoClaw 登录数据（%s）: %w", p.AppDataDir, err)
	}
	return p, nil
}

// LocalImportPreview 导入预览（脱敏，不含 token）
type LocalImportPreview struct {
	Found     bool   `json:"found"`
	AppData   string `json:"app_data_dir"`
	StateDir  string `json:"state_dir"`
	UserID    string `json:"user_id,omitempty"`
	Phone     string `json:"phone,omitempty"`
	DeviceID  string `json:"device_id,omitempty"`
	AtExp     int64  `json:"at_exp,omitempty"`
	RtExp     int64  `json:"rt_exp,omitempty"`
	HasDevice bool   `json:"has_device_identity"`
	Error     string `json:"error,omitempty"`
}

// PreviewLocalImport 只读探测本机登录态（供 UI 展示）
func PreviewLocalImport() *LocalImportPreview {
	out := &LocalImportPreview{}
	paths, err := DetectLocalAutoClaw()
	if err != nil {
		out.Error = err.Error()
		return out
	}
	out.Found = true
	out.AppData = paths.AppDataDir
	out.StateDir = paths.StateDir

	var auth struct {
		Token        string `json:"token"`
		RefreshToken string `json:"refreshToken"`
		DeviceID     string `json:"deviceId"`
		UserInfo     struct {
			ID    json.Number `json:"id"`
			Phone string      `json:"phone"`
		} `json:"userInfo"`
	}
	raw, err := os.ReadFile(filepath.Join(paths.AppDataDir, "auth.json"))
	if err != nil {
		out.Error = err.Error()
		return out
	}
	if err := json.Unmarshal(raw, &auth); err != nil {
		out.Error = "auth.json 解析失败: " + err.Error()
		return out
	}
	out.UserID = auth.UserInfo.ID.String()
	out.Phone = auth.UserInfo.Phone
	out.DeviceID = auth.DeviceID

	cipher, err := LoadV10CipherFromApp(paths.AppDataDir)
	if err == nil {
		if at, derr := cipher.Decrypt(auth.Token); derr == nil {
			out.AtExp = TokenExpiresAt(at)
		}
		if rt, derr := cipher.Decrypt(auth.RefreshToken); derr == nil {
			out.RtExp = TokenExpiresAt(rt)
		}
	} else {
		out.Error = "v10 密钥加载失败: " + err.Error()
	}
	if _, err := os.Stat(filepath.Join(paths.AppDataDir, "identity", "device.json")); err == nil {
		out.HasDevice = true
	}
	return out
}

// ImportLocalAccount 从本机 AutoClaw 导入账号（真实设备身份，device_spoofed=0）
// region 为空时自动从 ~/.openclaw-autoclaw/openclaw.json 的 provider baseUrl 识别（国内/海外）
func ImportLocalAccount(db *DB, group, region string) (*Account, error) {
	paths, err := DetectLocalAutoClaw()
	if err != nil {
		return nil, err
	}
	reg := DefaultRegion
	if strings.TrimSpace(region) != "" {
		reg = NormalizeRegion(region)
	} else {
		reg = detectRegionFromOpenclaw(paths)
	}
	var auth struct {
		Token        string `json:"token"`
		RefreshToken string `json:"refreshToken"`
		DeviceID     string `json:"deviceId"`
		UserInfo     struct {
			ID    json.Number `json:"id"`
			Phone string      `json:"phone"`
		} `json:"userInfo"`
	}
	raw, err := os.ReadFile(filepath.Join(paths.AppDataDir, "auth.json"))
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &auth); err != nil {
		return nil, fmt.Errorf("auth.json 解析失败: %w", err)
	}
	cipher, err := LoadV10CipherFromApp(paths.AppDataDir)
	if err != nil {
		return nil, err
	}
	at, err := cipher.Decrypt(auth.Token)
	if err != nil {
		return nil, fmt.Errorf("token 解密失败: %w", err)
	}
	rt, err := cipher.Decrypt(auth.RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("refreshToken 解密失败: %w", err)
	}
	at, rt = StripBearer(at), StripBearer(rt)
	if at == "" || rt == "" {
		return nil, errors.New("解密结果为空（可能未登录）")
	}

	a := &Account{
		UserID:        auth.UserInfo.ID.String(),
		Phone:         auth.UserInfo.Phone,
		AccessToken:   at,
		RefreshToken:  rt,
		DeviceID:      auth.DeviceID,
		DeviceSpoofed: 0, // 导入的是真实设备身份
		AccountGroup:  group,
		Status:        "active",
		Enabled:       1,
		AtExp:         TokenExpiresAt(at),
		RtExp:         TokenExpiresAt(rt),
		Source:        "local_import",
		Region:        string(reg),
	}

	// 设备密钥对（identity/device.json，若存在且自洽则一并导入）
	devRaw, err := os.ReadFile(filepath.Join(paths.AppDataDir, "identity", "device.json"))
	if err == nil {
		var dev struct {
			DeviceID      string `json:"deviceId"`
			PublicKeyPem  string `json:"publicKeyPem"`
			PrivateKeyPem string `json:"privateKeyPem"`
		}
		if json.Unmarshal(devRaw, &dev) == nil && dev.PublicKeyPem != "" {
			if fp, ferr := FingerprintFromPublicPem(dev.PublicKeyPem); ferr == nil && fp == dev.DeviceID {
				a.PublicKeyPem = dev.PublicKeyPem
				a.PrivateKeyPem = dev.PrivateKeyPem
				if a.DeviceID == "" {
					a.DeviceID = dev.DeviceID
				}
			} else {
				log.Printf("[import] 设备密钥对指纹不自洽，跳过导入密钥对")
			}
		}
	}

	// 校验 JWT device_id 与 auth.deviceId 一致
	if claims, cerr := ParseJWTClaims(rt); cerr == nil && claims.DeviceID != "" && claims.DeviceID != a.DeviceID {
		log.Printf("[import] 警告: rt.device_id(%s…) ≠ auth.deviceId(%s…)，刷新可能被拒",
			truncID(claims.DeviceID), truncID(a.DeviceID))
	}

	id, err := db.UpsertAccount(a)
	if err != nil {
		return nil, fmt.Errorf("账号入库失败: %w", err)
	}
	a.ID = id
	remain := time.Until(time.Unix(a.RtExp, 0))
	log.Printf("[import] 导入成功 account=%d user=%s phone=%s region=%s rt剩余=%.1f天",
		id, a.UserID, maskPhone(a.Phone), reg, remain.Hours()/24)
	return a, nil
}

// detectRegionFromOpenclaw 从 ~/.openclaw-autoclaw/openclaw.json 的 provider baseUrl 推断区域：
// 含 autoglm.ai / z.ai → 海外，否则国内。读不到/解析失败 → 默认国内。
func detectRegionFromOpenclaw(paths *LocalAutoClawPaths) Region {
	raw, err := os.ReadFile(filepath.Join(paths.StateDir, "openclaw.json"))
	if err != nil {
		return DefaultRegion
	}
	var cfg struct {
		Models struct {
			Providers map[string]struct {
				BaseURL string `json:"baseUrl"`
			} `json:"providers"`
		} `json:"models"`
	}
	if json.Unmarshal(raw, &cfg) != nil {
		return DefaultRegion
	}
	for _, p := range cfg.Models.Providers {
		if DetectRegionFromHost(p.BaseURL) == RegionOversea {
			return RegionOversea
		}
	}
	return DefaultRegion
}

func truncID(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// LoadLocalDeviceIdentity 读取本机 AutoClaw 真实设备身份（identity/device.json），
// 校验 deviceId 与公钥指纹自洽后返回；用于"复用本机真实设备"登录（绕过换设备风控）。
func LoadLocalDeviceIdentity() (*DeviceIdentity, error) {
	paths, err := DetectLocalAutoClaw()
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(filepath.Join(paths.AppDataDir, "identity", "device.json"))
	if err != nil {
		return nil, fmt.Errorf("读取 identity/device.json 失败: %w", err)
	}
	var dev struct {
		DeviceID      string `json:"deviceId"`
		PublicKeyPem  string `json:"publicKeyPem"`
		PrivateKeyPem string `json:"privateKeyPem"`
	}
	if err := json.Unmarshal(raw, &dev); err != nil {
		return nil, fmt.Errorf("解析 device.json 失败: %w", err)
	}
	if dev.DeviceID == "" || dev.PublicKeyPem == "" {
		return nil, errors.New("device.json 缺少 deviceId/publicKeyPem")
	}
	if fp, ferr := FingerprintFromPublicPem(dev.PublicKeyPem); ferr != nil || fp != dev.DeviceID {
		return nil, errors.New("device.json 公钥指纹与 deviceId 不自洽")
	}
	return &DeviceIdentity{DeviceID: dev.DeviceID, PublicKeyPem: dev.PublicKeyPem, PrivateKeyPem: dev.PrivateKeyPem}, nil
}

// ReadLiveTokenFromClient 运行期兜底: 直接读官方客户端的 request-headers.json 明文 JWT
// （官方客户端运行且自行刷新时，这是最安全的取票方式——不触发 rt 竞争）
func ReadLiveTokenFromClient() string {
	home := os.Getenv("USERPROFILE")
	if home == "" {
		return ""
	}
	raw, err := os.ReadFile(filepath.Join(home, ".openclaw-autoclaw", "request-headers.json"))
	if err != nil {
		return ""
	}
	var f struct {
		Headers map[string]string `json:"headers"`
	}
	if json.Unmarshal(raw, &f) != nil {
		return ""
	}
	v := strings.TrimSpace(f.Headers["X-Authorization"])
	return StripBearer(v)
}
