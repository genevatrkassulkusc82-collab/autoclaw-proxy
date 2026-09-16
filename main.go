package main

// autoclaw-proxy — AutoClaw 多账号 OpenAI 兼容网关
//
// 功能: 多账号池(短信验证码在线登录/本地导入) + 自持 rt 刷新 at + 伪造设备身份
//       + utls TLS 指纹伪装 + go-rod 浏览器指纹伪装 + 上游出口代理(SOCKS5/HTTP)
//       + OpenAI 兼容 /v1/chat/completions、/v1/models(上游同步)
//
// 协议依据: docs/01-llm-api.md、docs/03-token-refresh-and-device-identity.md（均实测验证）

import (
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

//go:embed web
var webFS embed.FS

func main() {
	listen := flag.String("listen", "", "监听地址（默认 settings.listen_addr 或 127.0.0.1:8317）")
	dataDir := flag.String("data", "", "数据目录（默认 ./data）")
	showKey := flag.Bool("show-key", false, "打印网关 API Key 后退出")
	importLocal := flag.Bool("import-local", false, "启动时自动导入本机 AutoClaw 登录态")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	if *dataDir == "" {
		if exe, err := os.Executable(); err == nil {
			*dataDir = filepath.Join(filepath.Dir(exe), "data")
		} else {
			*dataDir = "data"
		}
	}

	db, err := OpenDB(*dataDir)
	if err != nil {
		log.Fatalf("数据库初始化失败: %v", err)
	}

	pool := NewAccountPool(db)
	llm := NewLLMCaller(db, pool)
	browser := NewBrowserService(*dataDir)
	browser.ProxyFunc = func() string {
		v, _ := db.GetSetting("login_proxy")
		return strings.TrimSpace(v)
	}
	login := NewLoginManager(db, pool, browser)
	auth := NewAuthManager(db)

	// 指纹配置 hook（settings: tls_mode / tls_ja3）
	fingerprintHook = func() TLSFingerprint {
		mode, _ := db.GetSetting("tls_mode")
		if mode == "" {
			mode = "chrome"
		}
		ja3, _ := db.GetSetting("tls_ja3")
		return TLSFingerprint{Mode: mode, JA3: ja3}
	}

	// API Key 迁移/初始化（旧 settings.api_key → api_keys 表）
	newKey := auth.SeedDefaultAPIKey()
	if *showKey {
		if newKey != "" {
			fmt.Println(newKey)
		} else {
			fmt.Println(auth.FirstAPIKey())
		}
		return
	}

	if *importLocal {
		if a, err := ImportLocalAccount(db, ""); err != nil {
			log.Printf("[main] 本地导入失败: %v", err)
		} else {
			log.Printf("[main] 本地导入成功: account=%d user=%s", a.ID, a.UserID)
		}
	}

	// 启动时尝试同步一次模型目录（失败静默，用内置兜底）
	go func() {
		time.Sleep(2 * time.Second)
		if _, err := llm.SyncCatalog(); err != nil {
			log.Printf("[main] 模型目录同步失败（用内置兜底）: %v", err)
		}
	}()

	mux := http.NewServeMux()
	openai := NewOpenAIHandler(db, llm, pool, auth)
	openai.Register(mux)
	admin := NewAdminHandler(db, pool, llm, login, browser, auth, *dataDir)
	admin.Register(mux)

	// 嵌入式 Web UI（index.html + /web/static/*）
	webSub, err := fs.Sub(webFS, "web")
	if err != nil {
		log.Fatalf("web 资源嵌入失败: %v", err)
	}
	// embed 文件无修改时间，浏览器拿不到 Last-Modified/ETag 会启发式强缓存，
	// 导致升级后用户仍看到旧前端（页签失效那种）。统一 no-cache 强制每次协商。
	noCache := func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-cache")
			h.ServeHTTP(w, r)
		})
	}
	fileServer := http.FileServer(http.FS(webSub))
	mux.Handle("GET /{$}", noCache(fileServer))
	mux.Handle("GET /index.html", noCache(fileServer))
	mux.Handle("GET /web/", http.StripPrefix("/web/", noCache(fileServer)))

	addr := *listen
	if addr == "" {
		addr, _ = db.GetSetting("listen_addr")
	}
	if addr == "" {
		addr = "127.0.0.1:8317"
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           logRequest(mux),
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	log.Printf("autoclaw-proxy 启动: http://%s", addr)
	log.Printf("  OpenAI 端点:  POST http://%s/v1/chat/completions  GET /v1/models（仅 LLM API Key）", addr)
	log.Printf("  管理面板:     http://%s/（账号密码登录，默认 admin/admin123，请尽快在设置中修改）", addr)
	if newKey != "" {
		log.Printf("  LLM API Key:  %s", newKey)
	} else {
		log.Printf("  LLM API Key:  %s", auth.FirstAPIKey())
	}
	log.Printf("  TLS 指纹:     %s（settings.tls_mode 可调）", fingerprintHook().Mode)
	log.Printf("  数据目录:     %s", *dataDir)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("服务退出: %v", err)
	}
}
