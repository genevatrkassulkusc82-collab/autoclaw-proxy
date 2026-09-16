// 海外账号 OAuth 登录（Z.ai / Google）—— 集成在客户端，本地浏览器操作界面 + loopback 监听。
//
// 流程（与官方海外 AutoClaw 一致，只是把"应用窗口"换成客户端起的本地网页）：
//  1. 客户端在 127.0.0.1:18432（占用则顺延 19654/19723/53699）起本地服务，并用系统浏览器打开操作页
//  2. 操作页加载阿里云验证码（popup 模式，scene=18vhnjxl/region=ga/prefix=sq51tr）；用户点「登录」弹出点击验证码并完成
//  3. captchaVerifyCallback 拿到 captchaVerifyParam → POST 本地 /x/oauth-url → 客户端调
//     autoglm-api.autoglm.ai /userapi/overseasv1/{vendor}-oauth-url（MD5 签名 + device_id + navigate_uri）→ 返回授权链接
//  4. 操作页【展示授权链接供复制】（不自动跳转）——用户可粘贴到自己的浏览器/指纹浏览器打开登录
//  5. 登录后重定向回 http://localhost:18432/auth/callback-{vendor}?code=..&state=.. → 客户端 loopback 捕获
//  6. 客户端调 {vendor}-oauth-login 换 token → 通过配对码 push 到 autoclaw-proxy 服务器入池（region=oversea）
//
// 协议来源：海外版 AutoClaw 1.18.5 bundle 逆向（renderer chatStore + main index）+ 生产端点实测。

package main

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	overseaAPIHost = "https://autoglm-api.autoglm.ai"
	oaAppID        = "100003"
	oaAppKey       = "38d2391985e2369a5fb8227d8e6cd5e5"
	oaAppVersion   = "1.18.5"
	oaUA           = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) AutoClaw/1.18.5 Chrome/120.0.6099.291 Electron/28.3.1 Safari/537.36"
	oaCallbackTTL  = 10 * time.Minute
)

// oaAllPorts 官方 loopback 端口候选（首选 18432）
var oaAllPorts = []int{18432, 19654, 19723, 53699}

// oaEnvelope autoglm-api 统一响应信封
type oaEnvelope struct {
	Code int             `json:"code"`
	Msg  string          `json:"msg"`
	Data json.RawMessage `json:"data"`
}

func oaTraceID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// oaPost 向海外 userapi 发 MD5 签名 POST，返回信封
func oaPost(path string, body map[string]interface{}) (*oaEnvelope, error) {
	payload, _ := json.Marshal(body)
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	sum := md5.Sum([]byte(oaAppID + "&" + ts + "&" + oaAppKey))
	req, err := http.NewRequest("POST", overseaAPIHost+path, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	h := req.Header
	h.Set("Content-Type", "application/json")
	h.Set("Accept", "*/*")
	h.Set("User-Agent", oaUA)
	h.Set("X-Version", oaAppVersion)
	h.Set("X-Tm", "win")
	h.Set("X-Product", "autoclaw")
	h.Set("X-Auth-Appid", oaAppID)
	h.Set("X-Auth-TimeStamp", ts)
	h.Set("X-Auth-Sign", hex.EncodeToString(sum[:]))
	h.Set("X-Trace-Id", oaTraceID())
	h.Set("X-Lang", "en")
	h.Set("X-Channel", "official")
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	var env oaEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("响应非 JSON (HTTP %d): %s", resp.StatusCode, truncateStr(string(raw), 200))
	}
	return &env, nil
}

func oaWebInfo(deviceID string, params map[string]interface{}) map[string]interface{} {
	body := map[string]interface{}{"source_id": "autoclaw", "device_id": deviceID}
	for k, v := range params {
		body[k] = v
	}
	return body
}

// oaCaptchaConfig 取阿里云验证码配置（enabled/region/prefix/scene_id）
func oaCaptchaConfig() (map[string]interface{}, error) {
	env, err := oaPost("/userapi/overseasv1/oauth-captcha-config", map[string]interface{}{})
	if err != nil {
		return nil, err
	}
	if env.Code != 0 {
		return nil, fmt.Errorf("oauth-captcha-config code=%d msg=%s", env.Code, env.Msg)
	}
	var m map[string]interface{}
	if len(env.Data) > 0 {
		_ = json.Unmarshal(env.Data, &m)
	}
	return m, nil
}

// oaAuthURL 换取授权链接（带验证码 verifyParam）
func oaAuthURL(vendor, deviceID, navigateURI, captchaParam string) (string, error) {
	params := map[string]interface{}{"navigate_uri": navigateURI}
	if captchaParam != "" {
		params["ali_captcha_verify_param"] = captchaParam
	}
	env, err := oaPost("/userapi/overseasv1/"+vendor+"-oauth-url", oaWebInfo(deviceID, params))
	if err != nil {
		return "", err
	}
	if env.Code != 0 {
		return "", fmt.Errorf("%s-oauth-url code=%d msg=%s", vendor, env.Code, env.Msg)
	}
	u := oaExtractURL(env.Data)
	if u == "" {
		return "", fmt.Errorf("%s-oauth-url 未返回授权链接 (data=%s)", vendor, truncateStr(string(env.Data), 200))
	}
	return u, nil
}

// oaLogin 用 code+state 换 token
func oaLogin(vendor, deviceID, code, state, navigateURI string) (at, rt, userID string, err error) {
	env, err := oaPost("/userapi/overseasv1/"+vendor+"-oauth-login", oaWebInfo(deviceID, map[string]interface{}{
		"code": code, "state": state, "navigate_uri": navigateURI,
	}))
	if err != nil {
		return "", "", "", err
	}
	if env.Code != 0 || len(env.Data) == 0 {
		return "", "", "", fmt.Errorf("%s-oauth-login code=%d msg=%s", vendor, env.Code, env.Msg)
	}
	var d struct {
		AccessToken  string      `json:"access_token"`
		RefreshToken string      `json:"refresh_token"`
		UserID       json.Number `json:"user_id"`
	}
	if err := json.Unmarshal(env.Data, &d); err != nil {
		return "", "", "", fmt.Errorf("解析登录响应失败: %w", err)
	}
	if d.AccessToken == "" || d.RefreshToken == "" {
		return "", "", "", fmt.Errorf("登录响应缺少 token (code=%d)", env.Code)
	}
	return d.AccessToken, d.RefreshToken, d.UserID.String(), nil
}

// oaExtractURL 容错提取授权链接（data 可能是字符串或含 url 字段的对象）
func oaExtractURL(data json.RawMessage) string {
	if len(data) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(data, &s) == nil && strings.HasPrefix(s, "http") {
		return s
	}
	keys := []string{"url", "authorize_url", "oauth_url", "navigate_url", "auth_url", "redirect_url", "link"}
	var walk func(m map[string]interface{}) string
	walk = func(m map[string]interface{}) string {
		for _, k := range keys {
			if v, ok := m[k].(string); ok && strings.HasPrefix(v, "http") {
				return v
			}
		}
		for _, v := range m {
			if sub, ok := v.(map[string]interface{}); ok {
				if u := walk(sub); u != "" {
					return u
				}
			}
		}
		return ""
	}
	var m map[string]interface{}
	if json.Unmarshal(data, &m) == nil {
		return walk(m)
	}
	return ""
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// oaResult loopback 回调捕获结果
type oaResult struct {
	code  string
	state string
	err   error
}

// doOverseaOAuth 海外 OAuth 登录主流程（vendor: zai|google）
func doOverseaOAuth(server, pairCode, group, vendor string) error {
	vendor = strings.ToLower(strings.TrimSpace(vendor))
	if vendor != "zai" && vendor != "google" {
		return fmt.Errorf("vendor 必须是 zai 或 google")
	}
	dev, err := generateDeviceIdentity()
	if err != nil {
		return fmt.Errorf("生成设备身份失败: %w", err)
	}

	// 绑定 loopback 端口（首选 18432）
	ln, port := oaBindLoopback()
	if ln == nil {
		if autoClawRunning() {
			return fmt.Errorf("无法绑定回调端口 %v：官方 AutoClaw 正在运行并占用了这些端口，请先完全退出 AutoClaw 再试", oaAllPorts)
		}
		return fmt.Errorf("无法绑定本地回调端口 %v（被占用？）", oaAllPorts)
	}
	navigateURI := fmt.Sprintf("http://localhost:%d/auth/callback-%s", port, vendor)
	fmt.Printf("✓ 本地回调监听 127.0.0.1:%d（navigate_uri=%s）\n", port, navigateURI)
	fmt.Printf("✓ 设备身份 %s…\n", short(dev.id))

	resultCh := make(chan oaResult, 1)
	var stMu sync.Mutex
	stText := "① 请点「登录」完成阿里云点击验证"
	setSt := func(s string) { stMu.Lock(); stText = s; stMu.Unlock() }
	getSt := func() string { stMu.Lock(); defer stMu.Unlock(); return stText }

	mux := http.NewServeMux()

	// 操作页（含阿里云点击验证码 + 授权链接展示/复制）
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, oaUIPage(vendor))
	})
	// 验证码配置（代理到海外，避免页面跨域）
	mux.HandleFunc("/x/captcha-config", func(w http.ResponseWriter, r *http.Request) {
		cfg, err := oaCaptchaConfig()
		w.Header().Set("Content-Type", "application/json")
		if err != nil || cfg == nil {
			cfg = map[string]interface{}{"enabled": true, "region": "ga", "prefix": "sq51tr", "scene_id": "18vhnjxl", "captcha_supplier": "aliyun"}
		}
		json.NewEncoder(w).Encode(cfg)
	})
	// 用验证码 param 换授权链接（返回给页面展示，不自动跳转）
	mux.HandleFunc("/x/oauth-url", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			CaptchaParam string `json:"captcha_param"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		url, err := oaAuthURL(vendor, dev.id, navigateURI, req.CaptchaParam)
		if err != nil {
			setSt("❌ 获取授权链接失败：" + err.Error())
			json.NewEncoder(w).Encode(map[string]interface{}{"error": err.Error()})
			return
		}
		setSt("② 授权链接已生成：复制到你自己的浏览器（如指纹浏览器）打开并登录")
		json.NewEncoder(w).Encode(map[string]interface{}{"authorize_url": url})
	})
	// 流程状态（操作页轮询展示）
	mux.HandleFunc("/x/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"status": getSt()})
	})
	// OAuth 回调（用户浏览器登录后重定向到此）
	mux.HandleFunc("/auth/callback-"+vendor, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		code := strings.TrimSpace(q.Get("code"))
		state := strings.TrimSpace(q.Get("state"))
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if code == "" {
			setSt("❌ 登录被拒：" + q.Get("error"))
			fmt.Fprintf(w, "<!doctype html><meta charset='utf-8'><body style='font-family:system-ui;text-align:center;padding:60px'><h2>❌ 登录失败</h2><pre>%s</pre></body>", q.Get("error"))
			resultCh <- oaResult{err: fmt.Errorf("回调无 code: %s", q.Get("error"))}
			return
		}
		setSt("③ 已捕获登录回调，正在换取 token 并导入…")
		fmt.Fprint(w, "<!doctype html><meta charset='utf-8'><body style='font-family:system-ui;text-align:center;padding:60px'><h2>✅ 登录成功</h2><p>正在把账号导入服务器，请稍候…完成后即可关闭本页。</p></body>")
		resultCh <- oaResult{code: code, state: state}
	})

	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	defer srv.Shutdown(context.Background())

	uiURL := fmt.Sprintf("http://localhost:%d/", port)
	fmt.Printf("→ 已打开操作页：%s（若未自动打开请手动访问）\n", uiURL)
	_ = openBrowser(uiURL)

	fmt.Println("→ 操作页里：① 点「登录」过阿里云点击验证 → ② 复制生成的授权链接到你自己的浏览器（如指纹浏览器）打开登录")
	fmt.Println("  客户端持续监听回调（10 分钟超时）…")

	select {
	case res := <-resultCh:
		if res.err != nil {
			return res.err
		}
		fmt.Println("✓ 收到回调 code，正在换取 token…")
		at, rt, userID, err := oaLogin(vendor, dev.id, res.code, res.state, navigateURI)
		if err != nil {
			setSt("❌ 换取 token 失败：" + err.Error())
			return fmt.Errorf("换取 token 失败: %w", err)
		}
		acct := &localAccount{
			UserID:        userID,
			AccessToken:   at,
			RefreshToken:  rt,
			DeviceID:      dev.id,
			PublicKeyPem:  dev.pubPem,
			PrivateKeyPem: dev.privPem,
			DeviceSpoofed: 1,
		}
		fmt.Printf("✓ 海外登录成功 user=%s device=%s…\n", userID, short(dev.id))
		setSt("④ 正在导入到服务器…")
		if perr := pushAccount(server, pairCode, group, "oversea", acct, "oauth_"+vendor); perr != nil {
			setSt("❌ 导入服务器失败：" + perr.Error())
			return perr
		}
		setSt("✅ 账号已导入服务器（区域=海外），可关闭本页")
		return nil
	case <-time.After(oaCallbackTTL):
		setSt("❌ 等待登录回调超时")
		return fmt.Errorf("等待登录回调超时（%s）", oaCallbackTTL)
	}
}

// oaBindLoopback 依次尝试候选端口，返回已监听的 listener 与端口
func oaBindLoopback() (net.Listener, int) {
	for _, p := range oaAllPorts {
		ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(p))
		if err == nil {
			return ln, p
		}
	}
	return nil, 0
}

func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start()
}

// oaUIPage 客户端本地操作页：阿里云点击验证码（popup，与官方 renderer 一致）+ 授权链接展示/复制（不自动跳转）
func oaUIPage(vendor string) string {
	return `<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AutoClaw 海外登录</title>
<script src="https://o.alicdn.com/captcha-frontend/aliyunCaptcha/AliyunCaptcha.js"></script>
<style>
 body{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;background:#0b0d12;color:#e6e8ee;margin:0;padding:40px 20px}
 .card{max-width:520px;margin:0 auto;background:#151922;border:1px solid #232a36;border-radius:14px;padding:28px}
 h1{font-size:20px;margin:0 0 6px} .sub{color:#8b93a7;font-size:13px;margin:0 0 22px}
 button{padding:11px 16px;font-size:14px;font-weight:600;color:#fff;background:#3b6ef5;border:0;border-radius:9px;cursor:pointer}
 button.ghost{background:#222a38;border:1px solid #2c3547}
 #login-btn{width:100%;padding:13px;font-size:15px}
 #cap{min-height:8px;margin:14px 0}
 #status{margin-top:16px;font-size:13px;color:#9aa3b6;min-height:20px;word-break:break-all}
 .vendor{display:inline-block;background:#1d2431;border:1px solid #2c3547;color:#cdd4e4;padding:3px 10px;border-radius:999px;font-size:12px}
 .err{color:#ff7a7a} .ok{color:#5ad47a}
 #link-panel{display:none;margin-top:18px;border-top:1px solid #232a36;padding-top:16px}
 label{display:block;font-size:12px;color:#8b93a7;margin-bottom:6px}
 textarea{width:100%;box-sizing:border-box;background:#0d1119;border:1px solid #2c3547;color:#cdd4e4;border-radius:8px;padding:10px;font-family:ui-monospace,monospace;font-size:12px;resize:vertical}
 .row{display:flex;gap:10px;margin-top:10px;align-items:center}
 .tip{font-size:12px;color:#6f7789;margin-top:10px;line-height:1.6}
</style></head><body>
<div class="card">
 <h1>AutoClaw 海外账号登录</h1>
 <p class="sub">登录方式 <span class="vendor">` + vendor + `</span> · 先过验证码生成授权链接，再复制到你自己的浏览器登录</p>
 <div id="cap"></div>
 <button id="login-btn">登录（先过验证码）</button>
 <div id="link-panel">
   <label>授权链接（复制后在你自己的浏览器 / 指纹浏览器中打开登录）</label>
   <textarea id="auth-url" rows="3" readonly></textarea>
   <div class="row">
     <button onclick="copyLink()">📋 复制链接</button>
     <button class="ghost" onclick="openHere()">在本浏览器打开</button>
   </div>
   <div class="tip">登录成功后浏览器会跳到 <b>localhost:18432</b>（页面打不开属正常），客户端会自动捕获回调并导入账号；本页状态会自动刷新。链接约 10 分钟内有效。</div>
 </div>
 <div id="status">正在初始化验证码…</div>
</div>
<script>
const VENDOR = ` + strconv.Quote(vendor) + `;
let cfg = {region:'ga', prefix:'sq51tr', sceneId:'18vhnjxl'};
let pollT = null;
function setStatus(t, kind){ const el=document.getElementById('status'); el.textContent=t; el.className = kind==='err'?'err':(kind==='ok'?'ok':''); }
function copyLink(){
  const el=document.getElementById('auth-url'); el.focus(); el.select();
  if(navigator.clipboard && navigator.clipboard.writeText){ navigator.clipboard.writeText(el.value).then(()=>setStatus('📋 已复制授权链接，去你的浏览器粘贴打开')).catch(()=>fallbackCopy(el)); }
  else fallbackCopy(el);
}
function fallbackCopy(el){ try{ document.execCommand('copy'); setStatus('📋 已复制授权链接'); }catch(e){ setStatus('请手动选中链接复制','err'); } }
function openHere(){ const u=document.getElementById('auth-url').value; if(u) window.open(u,'_blank'); }
function startPoll(){
  if(pollT) return;
  pollT = setInterval(async ()=>{
    try{ const r=await fetch('/x/status'); const j=await r.json();
      if(j.status){ const kind = /❌/.test(j.status)?'err':(/✅/.test(j.status)?'ok':''); setStatus(j.status, kind);
        if(/✅|❌/.test(j.status)){ clearInterval(pollT); pollT=null; } }
    }catch(e){}
  }, 2000);
}
async function boot(){
  try{ const r=await fetch('/x/captcha-config'); const j=await r.json();
    if(j && j.scene_id) cfg={region:j.region||'ga', prefix:j.prefix||'sq51tr', sceneId:j.scene_id};
  }catch(e){}
  try{
    initAliyunCaptcha({
      SceneId: cfg.sceneId, prefix: cfg.prefix, region: cfg.region,
      mode: 'popup', element: '#cap', button: '#login-btn', language: 'en',
      captchaVerifyCallback: async (param) => {
        setStatus('验证通过，正在获取授权链接…');
        try{
          const r = await fetch('/x/oauth-url', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({captcha_param: param})});
          const j = await r.json();
          if(j.authorize_url){
            document.getElementById('link-panel').style.display='block';
            document.getElementById('auth-url').value=j.authorize_url;
            setStatus('② 授权链接已生成：复制到你自己的浏览器（如指纹浏览器）打开登录');
            startPoll();
            return {captchaResult:true, bizResult:true};
          }
          setStatus('❌ '+(j.error||'获取授权链接失败'), 'err');
          return {captchaResult:false, bizResult:false};
        }catch(e){ setStatus('❌ 请求本地服务失败: '+e, 'err'); return {captchaResult:false, bizResult:false}; }
      },
      onBizResultCallback: function(){},
      getInstance: function(inst){ window.__cap = inst; }
    });
    setStatus('就绪：点「登录」弹出阿里云点击验证码');
  }catch(e){ setStatus('❌ 验证码初始化失败: '+e, 'err'); }
}
boot();
</script></body></html>`
}
