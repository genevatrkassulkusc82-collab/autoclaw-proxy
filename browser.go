package main

// ---- 浏览器指纹伪装 + 在线验证码求解 ----
// 参考 D:\zcode-proxy captcha.go（go-rod 移植版），适配 AutoClaw:
//   - CN 短信登录通道实测无验证码参数；本模块作为风控兜底：
//     当 send-code/login 返回风控错误码时，可用真实浏览器过阿里云无痕验证
//   - 浏览器指纹伪装: 本机真实 Chrome/Edge + stealth 注入（webdriver/plugins/
//     languages/WebGL/chrome runtime/权限查询），持久化 profile 保留风控 cookie
//   - 有头手动兜底: 无头连续失败自动升级有头窗口人工过

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	neturl "net/url"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
	"github.com/ysmood/gson"
)

const (
	captchaSolveTimeout  = 40 * time.Second
	captchaManualTimeout = 180 * time.Second // 有头人工滑动：留足操作时间
	captchaSolveRetries  = 3
	// 与本机 Chrome 稳定版一致的 UA（stealth 注入保持同值）
	browserUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)

// BrowserService 浏览器指纹伪装 + 验证码求解 + HTTP 桥
type BrowserService struct {
	dataDir string

	mu       sync.Mutex
	solveSem chan struct{}
	manual   bool
	lastUsed time.Time

	// HTTP 桥复用
	browser  *rod.Browser
	launcher *launcher.Launcher
	page     *rod.Page

	// ProxyFunc 返回登录桥出口代理（换干净 IP，规避 IP 级风控黑名单）
	ProxyFunc func() string
}

// NewBrowserService 创建
func NewBrowserService(dataDir string) *BrowserService {
	return &BrowserService{dataDir: dataDir, solveSem: make(chan struct{}, 1)}
}

// stealthJS 浏览器指纹伪装注入脚本（在任何页面脚本前执行）
const stealthJS = `
(() => {
  // webdriver 标志
  Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
  delete Object.getPrototypeOf(navigator).webdriver;
  // chrome runtime
  if (!window.chrome) { window.chrome = { runtime: {} }; }
  if (!window.chrome.runtime) { window.chrome.runtime = {}; }
  // plugins/mimeTypes 非空
  Object.defineProperty(navigator, 'plugins', {
    get: () => [1, 2, 3, 4, 5].map(i => ({ name: 'Plugin ' + i })),
  });
  Object.defineProperty(navigator, 'languages', { get: () => ['zh-CN', 'zh', 'en'] });
  // WebGL 厂商/渲染器伪装（Intel 核显常见值）
  const getParameter = WebGLRenderingContext.prototype.getParameter;
  WebGLRenderingContext.prototype.getParameter = function (p) {
    if (p === 37445) return 'Intel Inc.';
    if (p === 37446) return 'Intel Iris OpenGL Engine';
    return getParameter.apply(this, [p]);
  };
  // 硬件并发/内存
  Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 16 });
  Object.defineProperty(navigator, 'deviceMemory', { get: () => 8 });
  // permissions query 补丁（notification 权限态一致性）
  const originalQuery = window.navigator.permissions.query;
  window.navigator.permissions.query = (parameters) => (
    parameters.name === 'notifications'
      ? Promise.resolve({ state: Notification.permission })
      : originalQuery(parameters)
  );
  // 去除自动化特征
  Object.defineProperty(screen, 'availWidth', { get: () => screen.width });
  Object.defineProperty(screen, 'availHeight', { get: () => screen.height - 40 });
})();
`

// findRealBrowser 定位本机真实 Chrome/Edge（捆绑 Chromium 会被风控识别）
func findRealBrowser() string {
	if runtime.GOOS != "windows" {
		for _, p := range []string{
			"/usr/bin/google-chrome", "/usr/bin/chromium-browser",
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		} {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
		return ""
	}
	localAppData := os.Getenv("LOCALAPPDATA")
	programFiles := os.Getenv("ProgramFiles")
	programFilesX86 := os.Getenv("ProgramFiles(x86)")
	candidates := []string{
		filepath.Join(programFiles, `Google\Chrome\Application\chrome.exe`),
		filepath.Join(programFilesX86, `Google\Chrome\Application\chrome.exe`),
		filepath.Join(localAppData, `Google\Chrome\Application\chrome.exe`),
		filepath.Join(programFilesX86, `Microsoft\Edge\Application\msedge.exe`),
		filepath.Join(programFiles, `Microsoft\Edge\Application\msedge.exe`),
	}
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

// launch 启动带指纹伪装的浏览器；调用方负责 Close
func (s *BrowserService) launch(headless bool, proxyURL string) (*rod.Browser, *launcher.Launcher, error) {
	bin := findRealBrowser()
	l := launcher.New().
		Headless(headless).
		Set("no-sandbox").
		Set("disable-blink-features", "AutomationControlled"). // 关键: 去自动化标志
		Set("lang", "zh-CN").
		Set("user-agent", browserUA).
		Set("window-size", "1280,800")
	if bin != "" {
		l = l.Bin(bin)
	} else {
		log.Printf("[browser] 未找到真实 Chrome/Edge，使用 rod 托管浏览器（易被风控识别）")
	}
	// 持久化 profile: 保留风控 cookie，避免每次求解都被视为新设备
	profile := filepath.Join(s.dataDir, "browser-profile")
	os.MkdirAll(profile, 0o755)
	l = l.UserDataDir(profile)
	if proxyURL != "" {
		l = l.Proxy(proxyURL)
	}
	controlURL, err := l.Launch()
	if err != nil {
		return nil, nil, fmt.Errorf("启动浏览器失败: %w", err)
	}
	browser := rod.New().ControlURL(controlURL)
	if err := browser.Connect(); err != nil {
		l.Kill()
		return nil, nil, fmt.Errorf("连接浏览器失败: %w", err)
	}
	return browser, l, nil
}

// CaptchaConfig 阿里云无痕验证配置（settings 表: captcha_prefix/region/scene_id）
type CaptchaConfig struct {
	Enabled bool   `json:"enabled"`
	Prefix  string `json:"prefix"`
	Region  string `json:"region"`
	SceneID string `json:"scene_id"`
	PageURL string `json:"page_url"` // 求解所用同源页面
}

// captchaHTML 阿里云无痕验证注入页（zcode-proxy 同款）
func captchaHTML(sceneID, region, prefix string) string {
	js := func(v string) string {
		b, _ := json.Marshal(v)
		return string(b)
	}
	return `<!DOCTYPE html><html><head><meta charset="utf-8">
<script src="https://o.alicdn.com/captcha-frontend/aliyunCaptcha/AliyunCaptcha.js"></script>
</head><body><div id="cap"></div><button id="btn"></button>
<script>
window.initAliyunCaptcha({
  SceneId: ` + js(sceneID) + `, mode: 'popup', region: ` + js(region) + `, prefix: ` + js(prefix) + `,
  element: '#cap', button: '#btn', captchaLogoImg: '', showErrorTip: false,
  getInstance: function (inst) {
    var fn = inst.startTracelessVerification || inst.show;
    try { fn.call(inst); } catch (e) {
      window.__onCaptcha(JSON.stringify({event: 'starterr', message: String(e && e.message || e)}));
    }
  },
  success: function (param) { window.__onCaptcha(JSON.stringify({event: 'success', param: param})); },
  fail: function (m) { window.__onCaptcha(JSON.stringify({event: 'fail', reason: m})); },
  onError: function (m) { window.__onCaptcha(JSON.stringify({event: 'error', reason: m})); }
});
</script></body></html>`
}

// SolveCaptcha 求解阿里云无痕验证，返回 verifyParam（X-Aliyun-Captcha-Verify-Param）
func (s *BrowserService) SolveCaptcha(cc *CaptchaConfig, proxyURL string) (string, error) {
	if cc == nil || !cc.Enabled || cc.SceneID == "" {
		return "", errors.New("验证码配置未启用（settings: captcha_enabled/prefix/region/scene_id）")
	}
	s.solveSem <- struct{}{}
	defer func() { <-s.solveSem }()

	s.mu.Lock()
	headless := !s.manual
	s.mu.Unlock()

	var lastErr error
	for attempt := 1; attempt <= captchaSolveRetries; attempt++ {
		param, err := s.solveOnce(cc, headless, proxyURL, captchaSolveTimeout)
		if err == nil && param != "" {
			s.mu.Lock()
			s.manual = false
			s.lastUsed = time.Now()
			s.mu.Unlock()
			log.Printf("[browser] 验证码求解成功 (headless=%v, attempt=%d)", headless, attempt)
			return param, nil
		}
		lastErr = err
		log.Printf("[browser] 求解失败 attempt=%d headless=%v: %v", attempt, headless, err)
		if headless && attempt >= 2 {
			headless = true
			s.mu.Lock()
			s.manual = true // 升级有头手动
			s.mu.Unlock()
			log.Printf("[browser] 切换有头手动模式（弹窗人工完成验证）")
		}
	}
	return "", fmt.Errorf("验证码求解失败（%d 次）: %v", captchaSolveRetries, lastErr)
}

// SolveCaptchaHeaded 强制有头模式：弹出可见浏览器窗口加载验证码，由用户手动滑动完成。
// 用于海外 OAuth 等必须人工过验证码的场景（无痕验证不一定能自动过；有头窗口让用户直接操作）。
func (s *BrowserService) SolveCaptchaHeaded(cc *CaptchaConfig, proxyURL string) (string, error) {
	if cc == nil || !cc.Enabled || cc.SceneID == "" {
		return "", errors.New("验证码配置未启用（scene_id/prefix/region 缺失）")
	}
	s.solveSem <- struct{}{}
	defer func() { <-s.solveSem }()

	var lastErr error
	for attempt := 1; attempt <= captchaSolveRetries; attempt++ {
		log.Printf("[browser] 弹出有头浏览器，请人工滑动完成验证 (attempt=%d, 超时 %v)", attempt, captchaManualTimeout)
		param, err := s.solveOnce(cc, false, proxyURL, captchaManualTimeout)
		if err == nil && param != "" {
			s.mu.Lock()
			s.lastUsed = time.Now()
			s.mu.Unlock()
			log.Printf("[browser] 人工验证成功 (attempt=%d)", attempt)
			return param, nil
		}
		lastErr = err
		log.Printf("[browser] 人工验证失败 attempt=%d: %v", attempt, err)
	}
	return "", fmt.Errorf("有头人工验证失败（%d 次）: %v", captchaSolveRetries, lastErr)
}

func (s *BrowserService) solveOnce(cc *CaptchaConfig, headless bool, proxyURL string, timeout time.Duration) (string, error) {
	browser, l, err := s.launch(headless, proxyURL)
	if err != nil {
		return "", err
	}
	killed := false
	defer func() {
		if !killed {
			l.Kill()
		}
	}()
	defer func() {
		killed = true
		browser.Close()
	}()

	pageURL := cc.PageURL
	if pageURL == "" {
		pageURL = "https://autoglm.aminer.cn/"
	}
	page, err := browser.Page(proto.TargetCreateTarget{URL: pageURL})
	if err != nil {
		return "", fmt.Errorf("打开页面失败: %w", err)
	}
	defer page.Close()
	_ = page.WaitLoad()
	// 页面加载后再补一次 stealth（EachEvent 可能晚于首个页面）
	_, _ = page.Eval(stealthJS)

	events := make(chan map[string]interface{}, 8)
	if _, err = page.Expose("__onCaptcha", func(j gson.JSON) (interface{}, error) {
		var m map[string]interface{}
		if json.Unmarshal([]byte(j.Str()), &m) == nil {
			select {
			case events <- m:
			default:
			}
		}
		return nil, nil
	}); err != nil {
		return "", fmt.Errorf("暴露回调失败: %w", err)
	}
	if err = page.SetDocumentContent(captchaHTML(cc.SceneID, cc.Region, cc.Prefix)); err != nil {
		return "", fmt.Errorf("注入验证页失败: %w", err)
	}
	deadline := time.After(timeout)
	for {
		select {
		case ev := <-events:
			switch ev["event"] {
			case "success":
				if p, ok := ev["param"].(string); ok && p != "" {
					return p, nil
				}
				return "", errors.New("success 事件缺少 param")
			case "fail":
				return "", fmt.Errorf("验证失败: %v", ev["reason"])
			case "error":
				return "", fmt.Errorf("SDK 错误: %v", ev["reason"])
			case "starterr":
				return "", fmt.Errorf("启动异常: %v", ev["message"])
			}
		case <-deadline:
			return "", fmt.Errorf("求解超时（%v）", timeout)
		}
	}
}

// FingerprintCheck 打开指纹检测页并截图/取 UA（UI 展示伪装效果）
func (s *BrowserService) FingerprintCheck(proxyURL string) (map[string]interface{}, error) {
	browser, l, err := s.launch(true, proxyURL)
	if err != nil {
		return nil, err
	}
	defer func() { browser.Close(); l.Kill() }()
	page, err := browser.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		return nil, err
	}
	defer page.Close()
	_, _ = page.Eval(stealthJS)
	res, err := page.Eval(`() => ({
		webdriver: navigator.webdriver,
		ua: navigator.userAgent,
		languages: navigator.languages,
		platform: navigator.platform,
		hardwareConcurrency: navigator.hardwareConcurrency,
		deviceMemory: navigator.deviceMemory,
		hasChrome: Boolean(window.chrome),
		plugins: navigator.plugins.length,
	})`)
	if err != nil {
		return nil, err
	}
	var out map[string]interface{}
	json.Unmarshal([]byte(res.Value.String()), &out)
	out["real_browser"] = findRealBrowser()
	return out, nil
}

// HTTPJSON 浏览器 HTTP 桥：在真实 Chrome 页面内执行 fetch，借用其真实
// TLS/HTTP2/TCP/cookie 指纹调用上游接口（绕过仅认官方客户端指纹的风控）。
// 首次调用会启动浏览器并导航到目标 origin 以建立同源与 cookie（acw_tc）。
func (s *BrowserService) HTTPJSON(method, url string, headers map[string]string, body string) (int, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.browser == nil {
		proxy := ""
		if s.ProxyFunc != nil {
			proxy = s.ProxyFunc()
		}
		browser, l, err := s.launch(true, proxy) // headless；经干净出口 IP
		if err != nil {
			return 0, "", err
		}
		s.browser = browser
		s.launcher = l
	}
	// 确保有一个同源页面（建立 cookie / acw_tc）
	if s.page == nil {
		origin := url
		if u, err := neturl.Parse(url); err == nil {
			origin = u.Scheme + "://" + u.Host + "/"
		}
		page, err := s.browser.Page(proto.TargetCreateTarget{URL: origin})
		if err != nil {
			return 0, "", fmt.Errorf("打开同源页失败: %w", err)
		}
		_ = page.WaitLoad()
		s.page = page
	}

	hjson, _ := json.Marshal(headers)
	js := `async (arg) => {
		const r = await fetch(arg.url, {
			method: arg.method,
			headers: arg.headers,
			body: arg.body || undefined,
			credentials: 'include',
			redirect: 'follow',
		});
		const text = await r.text();
		return JSON.stringify({ status: r.status, text: text });
	}`
	res, err := s.page.Evaluate(&rod.EvalOptions{
		JS:           js,
		JSArgs:       []interface{}{map[string]interface{}{"url": url, "method": method, "headers": json.RawMessage(hjson), "body": body}},
		ByValue:      true,
		AwaitPromise: true,
	})
	if err != nil {
		return 0, "", fmt.Errorf("浏览器 fetch 失败: %w", err)
	}
	var out struct {
		Status int    `json:"status"`
		Text   string `json:"text"`
	}
	rawVal := res.Value.String()
	if err := json.Unmarshal([]byte(rawVal), &out); err != nil {
		return 0, "", fmt.Errorf("解析 fetch 结果失败: %w (raw=%s)", err, truncate(rawVal, 200))
	}
	return out.Status, out.Text, nil
}

// CloseBrowser 关闭浏览器桥
func (s *BrowserService) CloseBrowser() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.page != nil {
		_ = s.page.Close()
		s.page = nil
	}
	if s.browser != nil {
		_ = s.browser.Close()
		if s.launcher != nil {
			s.launcher.Kill()
		}
		s.browser = nil
	}
}

// Status 服务状态（UI 展示）
func (s *BrowserService) Status() map[string]interface{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	return map[string]interface{}{
		"manual_mode":   s.manual,
		"real_browser":  findRealBrowser(),
		"profile_dir":   filepath.Join(s.dataDir, "browser-profile"),
		"solve_timeout": captchaSolveTimeout.String(),
	}
}
