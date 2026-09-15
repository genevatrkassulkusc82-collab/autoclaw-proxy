package main

// ---- 凭证与设备密码学 ----
// 1) 设备身份伪造: Ed25519 密钥对 + deviceId = SHA-256(公钥原始32字节) hex
//    （与 AutoClaw generateIdentity/fingerprintPublicKey 逐位一致，实测吻合）
// 2) enc:v10 解密: Chrome 风格 AES-256-GCM
//    密钥链: %APPDATA%\AutoClaw\Local State → os_crypt.encrypted_key(base64)
//            → 剥 "DPAPI" 5 字节魔数 → CryptUnprotectData(CurrentUser) → 32B AES key
//    载荷:   "enc:" + base64( "v10"(3B) + nonce(12B) + ciphertext + tag(16B) )
//    明文自带 "Bearer " 前缀
// 3) JWT 无验签解码（取 exp/device_id/user_id 等 claims）

import (
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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// ---------------- 设备身份 ----------------

// DeviceIdentity AutoClaw 设备身份（identity/device.json 等价物）
type DeviceIdentity struct {
	DeviceID     string `json:"deviceId"`
	PublicKeyPem string `json:"publicKeyPem"`
	PrivateKeyPem string `json:"privateKeyPem"`
}

// ed25519 SPKI DER 固定前缀（12 字节），其后为 32 字节原始公钥
var spkiPrefix = []byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00}

// GenerateDeviceIdentity 纯本地生成新设备身份（伪造设备），无服务端注册
func GenerateDeviceIdentity() (*DeviceIdentity, error) {
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
	pubPem := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	privPem := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk8}))
	return &DeviceIdentity{
		DeviceID:      FingerprintPublicKeyRaw(der),
		PublicKeyPem:  pubPem,
		PrivateKeyPem: privPem,
	}, nil
}

// FingerprintPublicKeyRaw deviceId = SHA-256(SPKI DER 去前缀后的原始 32 字节公钥)
func FingerprintPublicKeyRaw(der []byte) string {
	raw := der
	if len(der) > len(spkiPrefix) && string(der[:len(spkiPrefix)]) == string(spkiPrefix) {
		raw = der[len(spkiPrefix):]
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// FingerprintFromPublicPem 从 PEM 重新推导 deviceId（用于导入校验自洽）
func FingerprintFromPublicPem(pemStr string) (string, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return "", errors.New("invalid pem")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", err
	}
	return FingerprintPublicKeyRaw(der), nil
}

// ---------------- DPAPI (Windows) ----------------

type dataBlob struct {
	cbData uint32
	pbData *byte
}

func newBlob(b []byte) *dataBlob {
	if len(b) == 0 {
		return &dataBlob{}
	}
	return &dataBlob{cbData: uint32(len(b)), pbData: &b[0]}
}

func (b *dataBlob) bytes() []byte {
	if b == nil || b.cbData == 0 {
		return nil
	}
	return unsafe.Slice(b.pbData, b.cbData)
}

// cryptUnprotectData DPAPI CryptUnprotectData(CurrentUser)
func cryptUnprotectData(data []byte) ([]byte, error) {
	dll := syscall.MustLoadDLL("crypt32.dll")
	defer dll.Release()
	proc := dll.MustFindProc("CryptUnprotectData")
	in := newBlob(data)
	// pDataOut 是 DATA_BLOB 结构体出参（API 原地填充 cbData/pbData 16 字节），
	// 必须传结构体值的地址，而不是指针变量的地址
	var out dataBlob
	r1, _, err := proc.Call(
		uintptr(unsafe.Pointer(in)),
		0,   // szDataDescr
		0,   // pOptionalEntropy
		0,   // pvReserved
		0,   // pPromptStruct
		0x1, // CRYPTPROTECT_UI_FORBIDDEN
		uintptr(unsafe.Pointer(&out)),
	)
	if r1 == 0 || out.pbData == nil {
		return nil, fmt.Errorf("CryptUnprotectData failed: %w", err)
	}
	defer localFree(uintptr(unsafe.Pointer(out.pbData)))
	res := out.bytes()
	cp := make([]byte, len(res))
	copy(cp, res)
	return cp, nil
}

func localFree(p uintptr) {
	if p == 0 {
		return
	}
	k32 := syscall.NewLazyDLL("kernel32.dll")
	k32.NewProc("LocalFree").Call(p)
}

// ---------------- v10 (Electron safeStorage) ----------------

// V10Cipher AutoClaw enc:v10 凭证加解密器
type V10Cipher struct {
	key []byte // 32B AES key
}

// LoadV10CipherFromApp 从 AutoClaw 安装数据目录加载密钥（Local State）
// appDataDir 例: D:\Users\Admin\AppData\Roaming\AutoClaw
func LoadV10CipherFromApp(appDataDir string) (*V10Cipher, error) {
	raw, err := os.ReadFile(filepath.Join(appDataDir, "Local State"))
	if err != nil {
		return nil, fmt.Errorf("读取 Local State 失败: %w", err)
	}
	var ls struct {
		OsCrypt struct {
			EncryptedKey string `json:"encrypted_key"`
		} `json:"os_crypt"`
	}
	if err := json.Unmarshal(raw, &ls); err != nil {
		return nil, fmt.Errorf("解析 Local State 失败: %w", err)
	}
	blob, err := base64.StdEncoding.DecodeString(ls.OsCrypt.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("encrypted_key base64 失败: %w", err)
	}
	if len(blob) <= 5 || string(blob[:5]) != "DPAPI" {
		return nil, errors.New("encrypted_key 缺少 DPAPI 魔数")
	}
	key, err := cryptUnprotectData(blob[5:])
	if err != nil {
		return nil, fmt.Errorf("DPAPI 解密失败: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("AES key 长度异常: %d", len(key))
	}
	return &V10Cipher{key: key}, nil
}

// Decrypt 解密 "enc:v10..." 字段；非 enc: 前缀原样返回（明文旁路语义）
func (c *V10Cipher) Decrypt(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	if !strings.HasPrefix(value, "enc:") {
		return value, nil
	}
	raw, err := base64.StdEncoding.DecodeString(value[4:])
	if err != nil {
		return "", err
	}
	if len(raw) < 3+12+16 || string(raw[:3]) != "v10" {
		return "", errors.New("非 v10 格式")
	}
	nonce, ctTag := raw[3:15], raw[15:]
	tag := ctTag[len(ctTag)-16:]
	ct := ctTag[:len(ctTag)-16]
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, 12)
	if err != nil {
		return "", err
	}
	plain, err := gcm.Open(nil, nonce, append(ct, tag...), nil)
	if err != nil {
		return "", fmt.Errorf("AES-GCM 解密失败: %w", err)
	}
	return string(plain), nil
}

// Encrypt 加密为 "enc:v10..."（写回 auth.json/token-cache.json 时用，与官方格式互操作）
func (c *V10Cipher) Encrypt(plain string) (string, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, 12)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nil, nonce, []byte(plain), nil) // ct||tag
	out := append([]byte("v10"), nonce...)
	out = append(out, ct...)
	return "enc:" + base64.StdEncoding.EncodeToString(out), nil
}

// ---------------- JWT ----------------

// JWTClaims 无验签解码的 claims（只取网关关心的字段）
type JWTClaims struct {
	UserID   json.Number `json:"user_id"`
	DeviceID string      `json:"device_id"`
	SourceID string      `json:"source_id"`
	Iat      int64       `json:"iat"`
	Exp      int64       `json:"exp"`
	Jti      string      `json:"jti"`
	IsGuest  bool        `json:"is_guest"`
}

// ParseJWTClaims 解码 JWT payload（不校验签名）
func ParseJWTClaims(token string) (*JWTClaims, error) {
	token = strings.TrimPrefix(strings.TrimSpace(token), "Bearer ")
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("不是合法 JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims JWTClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	return &claims, nil
}

// TokenExpiresAt JWT exp（unix 秒）；解析失败返回 0
func TokenExpiresAt(token string) int64 {
	c, err := ParseJWTClaims(token)
	if err != nil {
		return 0
	}
	return c.Exp
}

// TokenRemaining token 剩余有效期（负数=已过期）
func TokenRemaining(token string) time.Duration {
	exp := TokenExpiresAt(token)
	if exp == 0 {
		return 0
	}
	return time.Until(time.Unix(exp, 0))
}

// StripBearer 去掉 "Bearer " 前缀（存储统一存裸 JWT）
func StripBearer(v string) string {
	return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(v), "Bearer "))
}
