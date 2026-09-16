// autoclaw-client - AutoClaw 账号远程导入客户端（配合 autoclaw-proxy「客户端远程导入」）。
//
// 场景：autoclaw-proxy 部署在无 AutoClaw 的服务器上时，在用户自己的 Windows 电脑运行本客户端：
//  1. 输入 服务器地址 + Web 管理页「客户端配对码」（10 分钟有效）
//  2. 模式 import：直接读取本机已登录 AutoClaw 的 auth.json（enc:v10 DPAPI 解密）+ 设备身份，回传服务器入池
//  3. 模式 reset：先重置本机设备身份并清除登录态 → 用户手动打开官方 AutoClaw 登录 → 客户端轮询到
//     新 auth.json 后解密回传（用于设备级风控拉黑后换设备）
//  4. -loop：连续多账号（reset 模式下每导入一个回到等待登录状态）
//
// 构建：CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o autoclaw-client-windows-amd64.exe ./cmd/autoclaw-client
package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// embeddedServerSlot 服务器在 /client/download 时写入二进制的地址槽；
// 未补丁的原始构建返回空串（回退 -server 参数/交互输入）。
var embeddedServerSlot = "<<AUTOCLAW_SERVER_URL>>" + strings.Repeat(string(rune(0)), 96)

func embeddedServerURL() string {
	s := strings.TrimRight(embeddedServerSlot, string(rune(0)))
	if s == "" || strings.Contains(s, "<<AUTOCLAW_SERVER_URL") {
		return ""
	}
	return s
}

// embeddedVersionSlot 服务器在 /client/download 时写入的"版本槽"（值=服务端 Version）
var embeddedVersionSlot = "<<AUTOCLAW_CLIENT_VERSION>>" + strings.Repeat(string(rune(0)), 32)

// clientVersion 兜底版本（未经 /client/download 打补丁的原始构建用）
const clientVersion = "1.0.1"

func embeddedVersion() string {
	s := strings.TrimRight(embeddedVersionSlot, string(rune(0)))
	if s == "" || strings.Contains(s, "<<AUTOCLAW_CLIENT_VERSION") {
		return ""
	}
	return s
}

// reportVersion 优先用下载时服务器盖的版本戳，否则用编译期兜底版本
func reportVersion() string {
	if v := embeddedVersion(); v != "" {
		return v
	}
	return clientVersion
}

var (
	flagServer = flag.String("server", "", "autoclaw-proxy 服务器地址，如 http://your-server:8317")
	flagCode   = flag.String("code", "", "Web 管理页「客户端配对码」")
	flagMode   = flag.String("mode", "import", "import=读本机已登录态 | reset=重置后等手动登录")
	flagLoop   = flag.Bool("loop", false, "连续多账号模式")
	flagGroup  = flag.String("group", "", "账号分组（可选）")
)

const (
	pollInterval = 5 * time.Second
	waitTimeout  = 10 * time.Minute
)

func main() {
	flag.Parse()
	fmt.Printf("autoclaw-client v%s\n", reportVersion())
	reader := bufio.NewReader(os.Stdin)
	server := strings.TrimRight(*flagServer, "/")
	code := strings.ToUpper(strings.TrimSpace(*flagCode))
	if server == "" {
		server = embeddedServerURL()
		if server != "" {
			fmt.Println("服务器地址(已内置):", server)
		}
	}
	if server == "" {
		fmt.Print("服务器地址 (如 http://1.2.3.4:8317): ")
		line, _ := reader.ReadString('\n')
		server = strings.TrimRight(strings.TrimSpace(line), "/")
	}
	if code == "" {
		fmt.Print("配对码 (Web 管理页获取): ")
		line, _ := reader.ReadString('\n')
		code = strings.ToUpper(strings.TrimSpace(line))
	}
	if server == "" || code == "" {
		fmt.Println("服务器地址与配对码不能为空")
		os.Exit(1)
	}
	if !strings.HasPrefix(server, "http://") && !strings.HasPrefix(server, "https://") {
		server = "http://" + server
	}

	// 1) 配对
	if err := hello(server, code); err != nil {
		fmt.Printf("配对失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✓ 配对成功")

	for {
		fmt.Println("")
		fmt.Println("== 请选择操作 ==")
		fmt.Println("  [1] 导入本机已登录账号（真实设备）")
		fmt.Println("  [2] 导入本机已登录账号（更换新设备身份）")
		fmt.Println("  [3] 重置本机设备+清除登录态，等手动登录后导入")
		fmt.Println("  [4] 海外账号 OAuth 登录（Z.ai/Google，浏览器操作 + 本地 18432 回调）")
		fmt.Println("  [5] 退出")
		fmt.Print("选择 [1-5]: ")
		choice := strings.TrimSpace(readLine(reader))
		if choice == "5" {
			return
		}
		if choice == "4" {
			fmt.Print("登录方式 [zai / google] (默认 zai): ")
			vendor := strings.ToLower(strings.TrimSpace(readLine(reader)))
			if vendor == "" {
				vendor = "zai"
			}
			group := askGroup(reader)
			if err := doOverseaOAuth(server, code, group, vendor); err != nil {
				fmt.Println(fmt.Sprintf("海外 OAuth 登录失败: %v", err))
			} else {
				fmt.Println("✓ 海外 OAuth 登录并导入成功")
			}
		} else {
			region := askRegion(reader)
			group := askGroup(reader)
			switch choice {
			case "1":
				if err := doImport(server, code, group, region, false); err != nil {
					fmt.Println(fmt.Sprintf("导入失败: %v", err))
				} else {
					fmt.Println("✓ 导入成功（真实设备）")
				}
			case "2":
				if err := doImport(server, code, group, region, true); err != nil {
					fmt.Println(fmt.Sprintf("导入失败: %v", err))
				} else {
					fmt.Println("✓ 导入成功（新设备身份）")
				}
			case "3":
				if err := doResetThenImport(server, code, group, region); err != nil {
					fmt.Println(fmt.Sprintf("重置导入失败: %v", err))
				} else {
					fmt.Println("✓ 重置导入成功")
				}
			default:
				fmt.Println("无效选择")
				continue
			}
		}
		fmt.Println("")
		fmt.Print("继续导入下一个账号? [y/N]: ")
		if !strings.EqualFold(strings.TrimSpace(readLine(reader)), "y") {
			return
		}
	}
}

// ---- 配对 ----

func hello(server, code string) error {
	body, _ := json.Marshal(map[string]string{"code": code, "version": reportVersion()})
	resp, err := http.Post(server+"/client/hello", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, b)
	}
	var out struct {
		ServerVersion string `json:"server_version"`
		Outdated      bool   `json:"outdated"`
		Msg           string `json:"msg"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out.Outdated && out.Msg != "" {
		fmt.Printf("⚠ %s\n", out.Msg)
	} else if out.ServerVersion != "" {
		fmt.Printf("✓ 版本一致（服务端 v%s）\n", out.ServerVersion)
	}
	return nil
}

// ---- 本地读取 AutoClaw 登录态 ----

type localAccount struct {
	UserID        string `json:"user_id"`
	Phone         string `json:"phone"`
	AccessToken   string `json:"access_token"`
	RefreshToken  string `json:"refresh_token"`
	DeviceID      string `json:"device_id"`
	PublicKeyPem  string `json:"public_key_pem"`
	PrivateKeyPem string `json:"private_key_pem"`
	DeviceSpoofed int    `json:"device_spoofed"`
}

// appDataDirFor 按区域返回官方客户端 userData 目录（国内 AutoClaw / 国际 autoclaw 等候选）
func appDataDirFor(region string) string {
	appdata := os.Getenv("APPDATA")
	var names []string
	if strings.EqualFold(region, "oversea") {
		names = []string{"autoclaw", "AutoClaw-Oversea", "AutoClaw-Global", "AutoClaw"}
	} else {
		names = []string{"AutoClaw", "autoclaw"}
	}
	for _, n := range names {
		p := filepath.Join(appdata, n)
		if _, err := os.Stat(filepath.Join(p, "auth.json")); err == nil {
			return p
		}
	}
	return filepath.Join(appdata, names[0])
}

func openclawHomeFor(region string) string {
	home := os.Getenv("USERPROFILE")
	var names []string
	if strings.EqualFold(region, "oversea") {
		names = []string{".eclaw", ".openclaw-autoclaw-oversea", ".openclaw-autoclaw"}
	} else {
		names = []string{".openclaw-autoclaw", ".eclaw"}
	}
	for _, n := range names {
		p := filepath.Join(home, n)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return filepath.Join(home, names[0])
}

// readLocalAccount 读取并解密本机 AutoClaw 登录态；spoof=true 时更换为新设备身份
func readLocalAccount(spoof bool, region string) (*localAccount, error) {
	dir := appDataDirFor(region)
	authRaw, err := os.ReadFile(filepath.Join(dir, "auth.json"))
	if err != nil {
		return nil, fmt.Errorf("读取 auth.json 失败（本机未安装/未登录 AutoClaw?）: %w", err)
	}
	var auth struct {
		Token        string `json:"token"`
		RefreshToken string `json:"refreshToken"`
		DeviceID     string `json:"deviceId"`
		UserInfo     struct {
			ID    json.RawMessage `json:"id"` // 数字(国内短信)或字符串(海外 Google/OAuth)
			Phone string          `json:"phone"`
		} `json:"userInfo"`
	}
	if err := json.Unmarshal(authRaw, &auth); err != nil {
		return nil, fmt.Errorf("解析 auth.json 失败: %w", err)
	}
	if auth.Token == "" || auth.RefreshToken == "" {
		return nil, fmt.Errorf("auth.json 无 token（官方客户端未登录）")
	}
	key, err := loadV10Key(dir)
	if err != nil {
		return nil, fmt.Errorf("加载 v10 密钥失败: %w", err)
	}
	at, err := v10Decrypt(key, auth.Token)
	if err != nil {
		return nil, fmt.Errorf("解密 token 失败: %w", err)
	}
	rt, err := v10Decrypt(key, auth.RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("解密 refreshToken 失败: %w", err)
	}
	acct := &localAccount{
		UserID:        oaUserIDString(auth.UserInfo.ID),
		Phone:         auth.UserInfo.Phone,
		AccessToken:   at,
		RefreshToken:  rt,
		DeviceID:      auth.DeviceID,
		DeviceSpoofed: 0,
	}
	// 设备身份：spoof 时生成新设备（更换设备信息），否则读本机真实设备
	if spoof {
		dev, gerr := generateDeviceIdentity()
		if gerr != nil {
			return nil, fmt.Errorf("生成新设备身份失败: %w", gerr)
		}
		acct.DeviceID = dev.id
		acct.PublicKeyPem = dev.pubPem
		acct.PrivateKeyPem = dev.privPem
		acct.DeviceSpoofed = 1
		return acct, nil
	}
	if raw, err := os.ReadFile(filepath.Join(dir, "identity", "device.json")); err == nil {
		var dev struct {
			DeviceID      string `json:"deviceId"`
			PublicKeyPem  string `json:"publicKeyPem"`
			PrivateKeyPem string `json:"privateKeyPem"`
		}
		if json.Unmarshal(raw, &dev) == nil {
			acct.PublicKeyPem = dev.PublicKeyPem
			acct.PrivateKeyPem = dev.PrivateKeyPem
			if acct.DeviceID == "" {
				acct.DeviceID = dev.DeviceID
			}
		}
	}
	return acct, nil
}

// ---- 回传服务器 ----

func pushAccount(server, code, group, region string, acct *localAccount, source string) error {
	payload := map[string]interface{}{
		"code": code,
		"account": map[string]interface{}{
			"user_id":         acct.UserID,
			"phone":           acct.Phone,
			"access_token":    acct.AccessToken,
			"refresh_token":   acct.RefreshToken,
			"device_id":       acct.DeviceID,
			"public_key_pem":  acct.PublicKeyPem,
			"private_key_pem": acct.PrivateKeyPem,
			"device_spoofed":  acct.DeviceSpoofed,
			"group":           group,
			"region":          region,
			"source":          source,
		},
	}
	body, _ := json.Marshal(payload)
	resp, err := http.Post(server+"/client/push", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 400))
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, b)
	}
	var out struct {
		AccountID int `json:"account_id"`
		Promotion *struct {
			TotalPoints  int `json:"total_points"`
			ActiveModals int `json:"active_modals"`
		} `json:"promotion"`
	}
	json.Unmarshal(b, &out)
	fmt.Printf("✓ 账号已回传服务器入池 (account_id=%d)\n", out.AccountID)
	if out.Promotion != nil {
		fmt.Printf("✓ 活动积分自动补领：本次 +%d 分（扫描 %d 个进行中活动；已领过则为 0）\n",
			out.Promotion.TotalPoints, out.Promotion.ActiveModals)
	}
	return nil
}

func doImport(server, code, group, region string, spoof bool) error {
	acct, err := readLocalAccount(spoof, region)
	if err != nil {
		return err
	}
	fmt.Printf("读到本机账号 user=%s phone=%s device=%s…\n", acct.UserID, acct.Phone, short(acct.DeviceID))
	return pushAccount(server, code, group, region, acct, "client_import")
}

func doResetThenImport(server, code, group, region string) error {
	if autoClawRunning() {
		return fmt.Errorf("官方 AutoClaw 正在运行，请先完全退出再执行 reset 模式")
	}
	if err := resetLocalDevice(region); err != nil {
		return err
	}
	fmt.Println("✓ 已重置本机设备身份并清除登录态。现在请打开官方 AutoClaw 手动登录…")
	deadline := time.Now().Add(waitTimeout)
	for time.Now().Before(deadline) {
		time.Sleep(pollInterval)
		if autoClawRunning() {
			// 官方运行中读 auth.json 可能被占用/回写；等其退出或短暂停留后读
		}
		acct, err := readLocalAccount(false, region)
		if err != nil {
			continue
		}
		fmt.Printf("检测到新登录 user=%s phone=%s\n", acct.UserID, acct.Phone)
		return pushAccount(server, code, group, region, acct, "client_reset_import")
	}
	return fmt.Errorf("等待手动登录超时（%s）", waitTimeout)
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func autoClawRunning() bool {
	out, err := exec.Command("tasklist", "/FI", "IMAGENAME eq AutoClaw.exe").Output()
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(out)), "autoclaw.exe")
}

// ---- 设备重置（与网关 device_reset 等价，客户端自包含） ----

func resetLocalDevice(region string) error {
	dir := appDataDirFor(region)
	identityPath := filepath.Join(dir, "identity", "device.json")
	// 备份
	ts := time.Now().Format("20060102-150405")
	backup := filepath.Join(os.TempDir(), "autoclaw-client-backup-"+ts)
	os.MkdirAll(backup, 0o755)
	for _, rel := range []string{"identity/device.json", "auth.json", "auth.json.backup", "Network", "Local Storage", "Session Storage", "WebStorage"} {
		src := filepath.Join(dir, filepath.FromSlash(rel))
		if _, err := os.Stat(src); err != nil {
			continue
		}
		dst := filepath.Join(backup, filepath.FromSlash(rel))
		if fi, err := os.Stat(src); err == nil && fi.IsDir() {
			copyDir(src, dst)
		} else {
			os.MkdirAll(filepath.Dir(dst), 0o755)
			copyFile(src, dst)
		}
		os.RemoveAll(src)
	}
	// 新设备身份
	dev, err := generateDeviceIdentity()
	if err != nil {
		return err
	}
	stored := map[string]interface{}{
		"version": 1, "deviceId": dev.id,
		"publicKeyPem": dev.pubPem, "privateKeyPem": dev.privPem,
		"createdAtMs": time.Now().UnixMilli(),
	}
	blob, _ := json.MarshalIndent(stored, "", "  ")
	os.MkdirAll(filepath.Dir(identityPath), 0o755)
	if err := os.WriteFile(identityPath, blob, 0o600); err != nil {
		return err
	}
	fmt.Printf("✓ 新设备身份 %s…（备份: %s）\n", short(dev.id), backup)
	return nil
}

func copyDir(src, dst string) error {
	return filepath.Walk(src, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		t := filepath.Join(dst, rel)
		if fi.IsDir() {
			return os.MkdirAll(t, 0o755)
		}
		return copyFile(p, t)
	})
}

func copyFile(src, dst string) error {
	in, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, in, 0o600)
}

// ---- enc:v10 解密（DPAPI → AES-256-GCM） ----

func loadV10Key(dir string) ([]byte, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "Local State"))
	if err != nil {
		return nil, err
	}
	var ls struct {
		OsCrypt struct {
			EncryptedKey string `json:"encrypted_key"`
		} `json:"os_crypt"`
	}
	if err := json.Unmarshal(raw, &ls); err != nil {
		return nil, err
	}
	blob, err := base64.StdEncoding.DecodeString(ls.OsCrypt.EncryptedKey)
	if err != nil {
		return nil, err
	}
	if len(blob) <= 5 || string(blob[:5]) != "DPAPI" {
		return nil, fmt.Errorf("encrypted_key 缺 DPAPI 魔数")
	}
	return dpapiUnprotect(blob[5:])
}

func v10Decrypt(key []byte, enc string) (string, error) {
	if !strings.HasPrefix(enc, "enc:") {
		return enc, nil
	}
	raw, err := base64.StdEncoding.DecodeString(enc[4:])
	if err != nil {
		return "", err
	}
	if len(raw) < 3+12+16 || string(raw[:3]) != "v10" {
		return "", fmt.Errorf("非 v10 格式")
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	g, err := cipher.NewGCMWithNonceSize(blk, 12)
	if err != nil {
		return "", err
	}
	pt, err := g.Open(nil, raw[3:15], raw[15:], nil)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// ---- DPAPI ----

type dataBlob struct {
	cbData uint32
	pbData *byte
}

func dpapiUnprotect(in []byte) ([]byte, error) {
	dll := syscall.NewLazyDLL("crypt32.dll")
	proc := dll.NewProc("CryptUnprotectData")
	inBlob := &dataBlob{cbData: uint32(len(in)), pbData: &in[0]}
	var out dataBlob
	r, _, err := proc.Call(
		uintptr(unsafe.Pointer(inBlob)), 0, 0, 0, 0, 1,
		uintptr(unsafe.Pointer(&out)),
	)
	if r == 0 || out.pbData == nil {
		return nil, fmt.Errorf("CryptUnprotectData: %v", err)
	}
	defer syscall.NewLazyDLL("kernel32.dll").NewProc("LocalFree").Call(uintptr(unsafe.Pointer(out.pbData)))
	res := unsafe.Slice(out.pbData, out.cbData)
	cp := make([]byte, len(res))
	copy(cp, res)
	return cp, nil
}

// ---- 设备身份生成（与官方算法一致） ----

type deviceIdentity struct {
	id      string
	pubPem  string
	privPem string
}

func generateDeviceIdentity() (*deviceIdentity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	pk8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	raw := der[len(spkiPrefix):]
	sum := sha256.Sum256(raw)
	return &deviceIdentity{
		id:      hex.EncodeToString(sum[:]),
		pubPem:  string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
		privPem: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk8})),
	}, nil
}

var spkiPrefix = []byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00}

func readLine(r *bufio.Reader) string {
	line, _ := r.ReadString(byte(10))
	return strings.TrimSpace(line)
}

func askRegion(r *bufio.Reader) string {
	fmt.Print("区域 [cn=国内 / oversea=海外] (默认 cn): ")
	v := strings.ToLower(strings.TrimSpace(readLine(r)))
	if v == "" {
		return "cn"
	}
	return v
}

func askGroup(r *bufio.Reader) string {
	fmt.Print("分组（可选，回车跳过）: ")
	return strings.TrimSpace(readLine(r))
}
