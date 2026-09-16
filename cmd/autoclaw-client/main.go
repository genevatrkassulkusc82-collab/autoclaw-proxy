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
	reader := bufio.NewReader(os.Stdin)
	server := strings.TrimRight(*flagServer, "/")
	code := strings.ToUpper(strings.TrimSpace(*flagCode))
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
		switch *flagMode {
		case "import":
			if err := doImport(server, code, *flagGroup); err != nil {
				fmt.Printf("导入失败: %v\n", err)
				os.Exit(1)
			}
			return
		case "reset":
			if err := doResetThenImport(server, code, *flagGroup); err != nil {
				fmt.Printf("重置导入失败: %v\n", err)
				os.Exit(1)
			}
		default:
			fmt.Println("未知 mode:", *flagMode)
			os.Exit(1)
		}
		if !*flagLoop {
			return
		}
		fmt.Println("\n[loop] 已导入一个账号；请在官方 AutoClaw 登录下一个账号，客户端将继续轮询…")
	}
}

// ---- 配对 ----

func hello(server, code string) error {
	body, _ := json.Marshal(map[string]string{"code": code})
	resp, err := http.Post(server+"/client/hello", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, b)
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

func appDataDir() string {
	return filepath.Join(os.Getenv("APPDATA"), "AutoClaw")
}

// readLocalAccount 读取并解密本机 AutoClaw 登录态；无 token 返回 error
func readLocalAccount() (*localAccount, error) {
	dir := appDataDir()
	authRaw, err := os.ReadFile(filepath.Join(dir, "auth.json"))
	if err != nil {
		return nil, fmt.Errorf("读取 auth.json 失败（本机未安装/未登录 AutoClaw?）: %w", err)
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
		UserID:        auth.UserInfo.ID.String(),
		Phone:         auth.UserInfo.Phone,
		AccessToken:   at,
		RefreshToken:  rt,
		DeviceID:      auth.DeviceID,
		DeviceSpoofed: 0,
	}
	// 设备身份（可缺省）
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

func pushAccount(server, code, group string, acct *localAccount, source string) error {
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
	}
	json.Unmarshal(b, &out)
	fmt.Printf("✓ 账号已回传服务器入池 (account_id=%d)\n", out.AccountID)
	return nil
}

func doImport(server, code, group string) error {
	acct, err := readLocalAccount()
	if err != nil {
		return err
	}
	fmt.Printf("读到本机账号 user=%s phone=%s device=%s…\n", acct.UserID, acct.Phone, short(acct.DeviceID))
	return pushAccount(server, code, group, acct, "client_import")
}

func doResetThenImport(server, code, group string) error {
	if autoClawRunning() {
		return fmt.Errorf("官方 AutoClaw 正在运行，请先完全退出再执行 reset 模式")
	}
	if err := resetLocalDevice(); err != nil {
		return err
	}
	fmt.Println("✓ 已重置本机设备身份并清除登录态。现在请打开官方 AutoClaw 手动登录…")
	deadline := time.Now().Add(waitTimeout)
	for time.Now().Before(deadline) {
		time.Sleep(pollInterval)
		if autoClawRunning() {
			// 官方运行中读 auth.json 可能被占用/回写；等其退出或短暂停留后读
		}
		acct, err := readLocalAccount()
		if err != nil {
			continue
		}
		fmt.Printf("检测到新登录 user=%s phone=%s\n", acct.UserID, acct.Phone)
		return pushAccount(server, code, group, acct, "client_reset_import")
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

func resetLocalDevice() error {
	dir := appDataDir()
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
