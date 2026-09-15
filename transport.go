package main

// ---- TLS 指纹伪装（utls）+ 出口代理 + HTTP 客户端工厂 ----
// 架构参考 D:\zcode-proxy（tls_fingerprint.go / client.go / egress_proxy.go）：
//   - utls 模拟浏览器 ClientHello（预置 + 自定义 JA3）
//   - SOCKS5 / HTTP CONNECT 隧道拨号，与指纹握手解耦
//   - 客户端按 (代理, 指纹, 超时, 主机类型) 缓存复用连接池

import (
	"bufio"
	"context"
	stdtls "crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	tls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
	"golang.org/x/net/proxy"
)

// TLSFingerprint 当前生效的指纹配置
type TLSFingerprint struct {
	Mode string `json:"mode"` // off|chrome|firefox|...|custom
	JA3  string `json:"ja3"`  // mode=custom 时的 JA3 字符串
}

var tlsFingerprintPresets = []struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}{
	{"chrome", "Chrome 浏览器（自动最新）"},
	{"chrome_120", "Chrome 120"},
	{"chrome_100", "Chrome 100"},
	{"chrome_83", "Chrome 83（旧版 Electron 常见）"},
	{"firefox", "Firefox（自动最新）"},
	{"safari", "Safari（16.0）"},
	{"edge", "Edge（85）"},
	{"randomized", "随机化指纹"},
	{"golang", "Go 标准库"},
	{"off", "关闭（Go 默认 crypto/tls）"},
	{"custom", "自定义 JA3"},
}

// fingerprintHook 由 main 注入：返回当前指纹配置
var fingerprintHook = func() TLSFingerprint { return TLSFingerprint{Mode: "chrome"} }

func presetHelloID(mode string) (tls.ClientHelloID, bool) {
	switch mode {
	case "chrome":
		return tls.HelloChrome_Auto, true
	case "chrome_120":
		return tls.HelloChrome_120, true
	case "chrome_100":
		return tls.HelloChrome_100, true
	case "chrome_83":
		return tls.HelloChrome_83, true
	case "firefox":
		return tls.HelloFirefox_Auto, true
	case "safari":
		return tls.HelloSafari_Auto, true
	case "edge":
		return tls.HelloEdge_Auto, true
	case "randomized":
		return tls.HelloRandomized, true
	case "golang":
		return tls.HelloGolang, true
	}
	return tls.HelloChrome_Auto, false
}

// utlsHandshake 对已建立的原始连接按指纹配置做 TLS 握手
func utlsHandshake(ctx context.Context, rawConn net.Conn, serverName string, fp TLSFingerprint) (net.Conn, error) {
	if fp.Mode == "" || fp.Mode == "off" {
		c := stdtls.Client(rawConn, &stdtls.Config{ServerName: serverName, MinVersion: stdtls.VersionTLS12})
		if err := c.HandshakeContext(ctx); err != nil {
			rawConn.Close()
			return nil, err
		}
		return c, nil
	}
	helloID, _ := presetHelloID(fp.Mode)
	// 本 transport 禁用 h2（TLSNextProto 置空）。utls 预设的 ALPN 扩展会反向覆盖
	// config.NextProtos（ALPNExtension.writeToUConn），因此必须按官方文档模式：
	// BuildHandshakeState → 改 Extensions 中 ALPN → 再 BuildHandshakeState 重编组，
	// 否则服务端协商出 h2 导致 "malformed HTTP response"。
	uconn := tls.UClient(rawConn, &tls.Config{ServerName: serverName, NextProtos: []string{"http/1.1"}}, helloID)
	if fp.Mode == "custom" {
		ja3Str := strings.TrimSpace(fp.JA3)
		if ja3Str != "" {
			spec, err := ja3ToClientHelloSpec(ja3Str)
			if err != nil {
				rawConn.Close()
				return nil, err
			}
			uconn.ClientHelloID = tls.HelloCustom
			if err := uconn.ApplyPreset(spec); err != nil {
				rawConn.Close()
				return nil, fmt.Errorf("指纹无效: %w", err)
			}
		}
	}
	if err := uconn.BuildHandshakeState(); err != nil {
		rawConn.Close()
		return nil, err
	}
	for _, ext := range uconn.Extensions {
		if alpn, ok := ext.(*tls.ALPNExtension); ok {
			alpn.AlpnProtocols = []string{"http/1.1"}
		}
	}
	if err := uconn.BuildHandshakeState(); err != nil {
		rawConn.Close()
		return nil, err
	}
	if err := uconn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, err
	}
	return uconn, nil
}

// ---- JA3 → ClientHelloSpec ----

func ja3ToClientHelloSpec(ja3 string) (*tls.ClientHelloSpec, error) {
	ja3 = strings.TrimSpace(ja3)
	parts := strings.Split(ja3, ",")
	if len(parts) != 5 {
		return nil, fmt.Errorf("JA3 需为 5 段（版本,密码套件,扩展,曲线,点格式）")
	}
	ciphers := parseU16List(parts[1])
	extIDs := parseU16List(parts[2])
	curves := parseU16List(parts[3])
	pointFmts := parseU8List(parts[4])
	spec := &tls.ClientHelloSpec{
		CipherSuites:       ciphers,
		CompressionMethods: []byte{0x00},
		TLSVersMin:         tls.VersionTLS12,
		TLSVersMax:         tls.VersionTLS13,
	}
	hasExt := func(id uint16) bool {
		for _, x := range extIDs {
			if x == id {
				return true
			}
		}
		return false
	}
	var exts []tls.TLSExtension
	exts = append(exts, &tls.SNIExtension{})
	for _, id := range extIDs {
		switch id {
		case 0:
		case 5:
			exts = append(exts, &tls.StatusRequestExtension{})
		case 10:
			exts = append(exts, &tls.SupportedCurvesExtension{Curves: toCurveIDs(curves)})
		case 11:
			exts = append(exts, &tls.SupportedPointsExtension{SupportedPoints: pointFmts})
		case 13:
			exts = append(exts, &tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: defaultSigAlgs()})
		case 16:
			exts = append(exts, &tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}})
		case 18:
			exts = append(exts, &tls.SCTExtension{})
		case 23:
			exts = append(exts, &tls.ExtendedMasterSecretExtension{})
		case 27:
			exts = append(exts, &tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{tls.CertCompressionBrotli}})
		case 35:
			exts = append(exts, &tls.SessionTicketExtension{})
		case 43:
			exts = append(exts, &tls.SupportedVersionsExtension{Versions: []uint16{tls.VersionTLS13, tls.VersionTLS12}})
		case 45:
			exts = append(exts, &tls.PSKKeyExchangeModesExtension{Modes: []uint8{1}})
		case 51:
		case 65281:
			exts = append(exts, &tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient})
		}
	}
	if hasExt(51) {
		exts = append(exts, &tls.KeyShareExtension{KeyShares: []tls.KeyShare{{Group: tls.X25519}}})
	}
	spec.Extensions = exts
	return spec, nil
}

func toCurveIDs(v []uint16) []tls.CurveID {
	out := make([]tls.CurveID, len(v))
	for i, x := range v {
		out[i] = tls.CurveID(x)
	}
	return out
}

func defaultSigAlgs() []tls.SignatureScheme {
	return []tls.SignatureScheme{
		tls.ECDSAWithP256AndSHA256, tls.ECDSAWithP384AndSHA384, tls.ECDSAWithP521AndSHA512,
		tls.PSSWithSHA256, tls.PSSWithSHA384, tls.PSSWithSHA512,
		tls.PKCS1WithSHA256, tls.PKCS1WithSHA384, tls.PKCS1WithSHA512,
		tls.ECDSAWithSHA1, tls.PKCS1WithSHA1,
	}
}

func parseU16List(s string) []uint16 {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []uint16
	for _, p := range strings.Split(s, "-") {
		if n, err := strconv.ParseUint(strings.TrimSpace(p), 10, 16); err == nil {
			out = append(out, uint16(n))
		}
	}
	return out
}

func parseU8List(s string) []uint8 {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []uint8
	for _, p := range strings.Split(s, "-") {
		if n, err := strconv.ParseUint(strings.TrimSpace(p), 10, 8); err == nil {
			out = append(out, uint8(n))
		}
	}
	return out
}

// ---- 拨号（直连 / SOCKS5 / HTTP CONNECT 隧道）----

func socks5Dialer(u *url.URL) (proxy.Dialer, error) {
	var auth *proxy.Auth
	if u.User != nil {
		auth = &proxy.Auth{User: u.User.Username()}
		if p, ok := u.User.Password(); ok {
			auth.Password = p
		}
	}
	forward := &net.Dialer{Timeout: 15 * time.Second}
	return proxy.SOCKS5("tcp", u.Host, auth, forward)
}

func dialRaw(ctx context.Context, dialer *net.Dialer, proxyURL, network, addr string) (net.Conn, error) {
	if proxyURL == "" {
		return dialer.DialContext(ctx, network, addr)
	}
	u, err := url.Parse(proxyURL)
	if err != nil {
		return dialer.DialContext(ctx, network, addr)
	}
	switch u.Scheme {
	case "socks5", "socks5h":
		sd, err := socks5Dialer(u)
		if err != nil {
			return nil, err
		}
		if cd, ok := sd.(interface {
			DialContext(ctx context.Context, network, addr string) (net.Conn, error)
		}); ok {
			return cd.DialContext(ctx, network, addr)
		}
		return sd.Dial(network, addr)
	default: // http/https 代理: CONNECT 隧道
		conn, err := dialer.DialContext(ctx, "tcp", u.Host)
		if err != nil {
			return nil, err
		}
		if err := httpConnectTunnel(ctx, conn, addr, u); err != nil {
			conn.Close()
			return nil, err
		}
		return conn, nil
	}
}

func httpConnectTunnel(ctx context.Context, conn net.Conn, addr string, proxyURL *url.URL) error {
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: make(http.Header),
	}
	if proxyURL.User != nil {
		pass, _ := proxyURL.User.Password()
		req.Header.Set("Proxy-Authorization",
			"Basic "+base64.StdEncoding.EncodeToString([]byte(proxyURL.User.Username()+":"+pass)))
	}
	if err := req.Write(conn); err != nil {
		return err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("代理 CONNECT 失败: HTTP %d", resp.StatusCode)
	}
	if br.Buffered() > 0 {
		return fmt.Errorf("CONNECT 响应带多余数据")
	}
	return nil
}

// ---- HTTP 客户端工厂 ----

var clientCache sync.Map

// sharedCookieJar 模拟官方 Electron 客户端的共享 cookie 会话：
// send-code 时服务端可能 Set-Cookie（风控/会话），login 需携带同一 cookie。
// 无 jar 的裸客户端会丢弃该 cookie，导致 login 返回 400001"请求数据有问题"。
var sharedCookieJar http.CookieJar

func init() {
	jar, err := cookiejar.New(nil)
	if err == nil {
		sharedCookieJar = jar
	}
}

// NewFingerprintHTTPClient utls 指纹客户端（HTTP/1.1）
func NewFingerprintHTTPClient(proxyURL string, timeout time.Duration) *http.Client {
	fp := fingerprintHook()
	dialer := &net.Dialer{Timeout: 30 * time.Second}
	dialTLS := func(ctx context.Context, network, addr string) (net.Conn, error) {
		host := addr
		if h, _, err := net.SplitHostPort(addr); err == nil {
			host = h
		}
		raw, err := dialRaw(ctx, dialer, proxyURL, network, addr)
		if err != nil {
			return nil, err
		}
		return utlsHandshake(ctx, raw, host, fp)
	}
	transport := &http.Transport{
		DialContext:     dialer.DialContext,
		DialTLSContext:  dialTLS,
		TLSNextProto:    map[string]func(string, *stdtls.Conn) http.RoundTripper{}, // 指纹通道禁 h2
		MaxIdleConns:    32,
		IdleConnTimeout: 90 * time.Second,
	}
	return &http.Client{Transport: transport, Timeout: timeout, Jar: sharedCookieJar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
}

// NewPlainHTTPClient 标准库客户端（h2），指纹关闭或对照测试时使用
func NewPlainHTTPClient(proxyURL string, timeout time.Duration) *http.Client {
	transport := &http.Transport{
		TLSClientConfig:   &stdtls.Config{MinVersion: stdtls.VersionTLS12},
		ForceAttemptHTTP2: true,
		MaxIdleConns:      32,
		IdleConnTimeout:   90 * time.Second,
	}
	if proxyURL != "" {
		if u, err := url.Parse(proxyURL); err == nil {
			switch u.Scheme {
			case "socks5", "socks5h":
				if dialer, derr := socks5Dialer(u); derr == nil {
					if cd, ok := dialer.(interface {
						DialContext(ctx context.Context, network, addr string) (net.Conn, error)
					}); ok {
						transport.DialContext = cd.DialContext
					}
				}
			default:
				transport.Proxy = http.ProxyURL(u)
			}
		}
	}
	return &http.Client{Transport: transport, Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
}

// ClientForProxy 按 (代理, 指纹, 超时) 缓存客户端
func ClientForProxy(proxyURL string, timeout time.Duration) *http.Client {
	fp := fingerprintHook()
	key := fmt.Sprintf("%s|%s|%s|%v", proxyURL, fp.Mode, fp.JA3, timeout)
	if v, ok := clientCache.Load(key); ok {
		return v.(*http.Client)
	}
	var c *http.Client
	if fp.Mode == "" || fp.Mode == "off" {
		c = NewPlainHTTPClient(proxyURL, timeout)
	} else {
		c = NewFingerprintHTTPClient(proxyURL, timeout)
	}
	actual, _ := clientCache.LoadOrStore(key, c)
	return actual.(*http.Client)
}

// ---- utls over HTTP/2（真实浏览器指纹模拟）----
// 真实 Chrome/Electron 的指纹 = Chrome ClientHello(JA3) + HTTP/2。此前指纹客户端强制
// ALPN=http/1.1 只说 h1，"Chrome JA3 + h1" 本身就是 bot 特征，被 WAF/业务风控识别。
// 这里用 utls 做 Chrome ClientHello（保留预设 h2 ALPN），再在 utls 连接上跑 x/net/http2，
// 使 TLS 指纹与 HTTP/2 指纹同时对齐真实浏览器。

// utlsH2Conn 包装 utls 连接，向 x/net/http2 暴露标准库 tls.ConnectionState
type utlsH2Conn struct {
	net.Conn
	st stdtls.ConnectionState
}

func (c *utlsH2Conn) ConnectionState() stdtls.ConnectionState { return c.st }

func newUTLSH2Conn(ctx context.Context, raw net.Conn, serverName string, fp TLSFingerprint) (net.Conn, error) {
	helloID, _ := presetHelloID(fp.Mode)
	// 不修改 ALPN：保留预设的 h2+http/1.1，让服务端协商 h2（与真实浏览器一致）
	u := tls.UClient(raw, &tls.Config{ServerName: serverName}, helloID)
	if fp.Mode == "custom" && strings.TrimSpace(fp.JA3) != "" {
		spec, err := ja3ToClientHelloSpec(strings.TrimSpace(fp.JA3))
		if err != nil {
			raw.Close()
			return nil, err
		}
		u.ClientHelloID = tls.HelloCustom
		if err := u.ApplyPreset(spec); err != nil {
			raw.Close()
			return nil, err
		}
	}
	if err := u.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	us := u.ConnectionState()
	st := stdtls.ConnectionState{
		Version:                     us.Version,
		HandshakeComplete:           us.HandshakeComplete,
		DidResume:                   us.DidResume,
		CipherSuite:                 us.CipherSuite,
		NegotiatedProtocol:          us.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  true,
		ServerName:                  us.ServerName,
		PeerCertificates:            us.PeerCertificates,
		VerifiedChains:              us.VerifiedChains,
	}
	return &utlsH2Conn{Conn: u, st: st}, nil
}

// NewFingerprintH2Client utls(Chrome) + HTTP/2 客户端，用于需要真实浏览器指纹的端点（login 等）
func NewFingerprintH2Client(proxyURL string, timeout time.Duration) *http.Client {
	fp := fingerprintHook()
	dialer := &net.Dialer{Timeout: 30 * time.Second}
	t2 := &http2.Transport{
		AllowHTTP: false,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *stdtls.Config) (net.Conn, error) {
			host := addr
			if h, _, err := net.SplitHostPort(addr); err == nil {
				host = h
			}
			raw, err := dialRaw(ctx, dialer, proxyURL, network, addr)
			if err != nil {
				return nil, err
			}
			return newUTLSH2Conn(ctx, raw, host, fp)
		},
	}
	return &http.Client{Transport: t2, Timeout: timeout, Jar: sharedCookieJar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
}

var fpH2ClientCache sync.Map

// FingerprintH2ClientForProxy 缓存的 utls+h2 客户端
func FingerprintH2ClientForProxy(proxyURL string, timeout time.Duration) *http.Client {
	key := fmt.Sprintf("fph2|%s|%s|%v", proxyURL, fingerprintHook().Mode, timeout)
	if v, ok := fpH2ClientCache.Load(key); ok {
		return v.(*http.Client)
	}
	c := NewFingerprintH2Client(proxyURL, timeout)
	actual, _ := fpH2ClientCache.LoadOrStore(key, c)
	return actual.(*http.Client)
}
// 实测：阿里云 WAF 对 utls 指纹 ClientHello 返回 307 且不下发 acw_tc 会话 cookie，
// 导致高风险 login 端点 400001；标准 Go TLS 则正常 200 + acw_tc。
// 故 userapi（login/send-code/refresh/models）用标准传输，LLM 通道才用 utls。
var plainClientCache sync.Map

func PlainClientForProxy(proxyURL string, timeout time.Duration) *http.Client {
	key := fmt.Sprintf("plain|%s|%v", proxyURL, timeout)
	if v, ok := plainClientCache.Load(key); ok {
		return v.(*http.Client)
	}
	c := NewPlainHTTPClient(proxyURL, timeout)
	actual, _ := plainClientCache.LoadOrStore(key, c)
	return actual.(*http.Client)
}

// CloseIdleClients 设置变更后清空客户端缓存
func CloseIdleClients() {
	clientCache.Range(func(k, v interface{}) bool {
		v.(*http.Client).CloseIdleConnections()
		clientCache.Delete(k)
		return true
	})
	plainClientCache.Range(func(k, v interface{}) bool {
		v.(*http.Client).CloseIdleConnections()
		plainClientCache.Delete(k)
		return true
	})
}

// ---- 出口代理工具 ----

func ProxyURLForNode(n *ProxyNode) string {
	if n == nil || n.Host == "" {
		return ""
	}
	scheme := n.Type
	if scheme == "" {
		scheme = "socks5"
	}
	auth := ""
	if n.Username != "" {
		auth = url.UserPassword(n.Username, n.Password).String() + "@"
	}
	return fmt.Sprintf("%s://%s%s:%d", scheme, auth, n.Host, n.Port)
}

func MaskProxyURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return raw
	}
	username := u.User.Username()
	masked := "***"
	if len(username) >= 2 {
		masked = username[:2] + "***"
	}
	u.User = url.User(masked)
	return u.String()
}

// TestProxyExitIP 测试代理连通性并返回出口 IP
func TestProxyExitIP(proxyURL string) (string, time.Duration, error) {
	client := ClientForProxy(proxyURL, 15*time.Second)
	start := time.Now()
	var lastErr error
	for _, api := range []string{"https://api.ipify.org/?format=json", "https://ipinfo.io/json"} {
		resp, err := client.Get(api)
		if err != nil {
			lastErr = err
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		var v map[string]interface{}
		if json.Unmarshal(body, &v) == nil {
			if s, ok := v["ip"].(string); ok && s != "" {
				return s, time.Since(start), nil
			}
		}
		lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("无法获取出口 IP")
	}
	return "", time.Since(start), lastErr
}

// DetectSystemProxy 读取系统代理设置
func DetectSystemProxy() (bool, string) {
	if runtime.GOOS != "windows" {
		for _, env := range []string{"http_proxy", "HTTP_PROXY", "all_proxy", "ALL_PROXY"} {
			if v := strings.TrimSpace(os.Getenv(env)); v != "" {
				return true, v
			}
		}
		return false, ""
	}
	out, err := exec.Command("reg", "query",
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`, "/v", "ProxyEnable").Output()
	if err != nil || !strings.Contains(string(out), "0x1") {
		return false, ""
	}
	out2, err := exec.Command("reg", "query",
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`, "/v", "ProxyServer").Output()
	if err != nil {
		return false, ""
	}
	server := ""
	for _, line := range strings.Split(string(out2), "\n") {
		if strings.Contains(line, "ProxyServer") {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				server = fields[len(fields)-1]
			}
		}
	}
	if server == "" {
		return false, ""
	}
	if strings.Contains(server, "=") {
		parts := map[string]string{}
		for _, p := range strings.Split(server, ";") {
			if kv := strings.SplitN(p, "=", 2); len(kv) == 2 {
				parts[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
			}
		}
		server = parts["https"]
		if server == "" {
			server = parts["http"]
		}
		if server == "" {
			for _, v := range parts {
				server = v
				break
			}
		}
	}
	if server != "" && !strings.Contains(server, "://") {
		server = "http://" + server
	}
	return true, server
}

// ProbeLocalProxyPorts 并发探测本机常见代理内核端口
func ProbeLocalProxyPorts() []map[string]interface{} {
	ports := []int{7897, 7890, 7891, 7899, 1080, 10808, 2080, 8889, 8118}
	labels := map[int]string{
		7897: "Clash Verge 混合端口", 7890: "Clash 混合端口", 7891: "Clash HTTP 端口",
		7899: "Clash Verge 备用", 1080: "SOCKS5 通用", 10808: "v2rayN SOCKS",
		2080: "sing-box 混合端口", 8889: "HTTP 代理通用", 8118: "Privoxy",
	}
	type result struct {
		port int
		open bool
	}
	results := make(chan result, len(ports))
	for _, p := range ports {
		go func(port int) {
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 500*time.Millisecond)
			if err == nil {
				conn.Close()
			}
			results <- result{port, err == nil}
		}(p)
	}
	byPort := map[int]bool{}
	for i := 0; i < len(ports); i++ {
		r := <-results
		byPort[r.port] = r.open
	}
	var out []map[string]interface{}
	for _, p := range ports {
		if byPort[p] {
			label := labels[p]
			if label == "" {
				label = "本机代理端口"
			}
			out = append(out, map[string]interface{}{
				"url": fmt.Sprintf("http://127.0.0.1:%d", p), "port": p, "label": label,
			})
		}
	}
	return out
}
