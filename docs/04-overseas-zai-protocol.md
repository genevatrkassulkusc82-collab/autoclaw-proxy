# AutoClaw 海外版（autoglm.ai / z.ai）协议差异分析

> 对比对象：国内版 = 本仓库 `autoclaw-proxy` 现状（`*.zhipuai.cn`，AutoClaw 1.18.4 实现）；
> 海外版 = `autoclaw.z.ai` 发行的 AutoClaw 1.18.5（`isOversea=true` 构建）。
> 编写时间：2026-09-16。**结论基于对两个官方安装包的解包逆向（非推断）**：
> 国内 `autoclaw_1.18.5_amd64.deb`（`isOversea=false`）+ 海外 `autoclaw-1.18.5-mac.zip`（`isOversea=true`），
> 解出 `app.asar → out/main/index.js`（9.6MB）与 `model-provider-config.json`，并实时抓取了 `autoclaw.z.ai` 落地页。

## 0. 结论速览（含对早期推断的重要修正）

1. **海外版与国内版是同一份代码的两个构建**，由编译期常量 `isOversea` 区分（国内 `false`、海外 `true`）。
2. **内置 LLM 通道协议两边完全相同**：同样的 `/autoclaw-proxy/proxy/autoclaw/chat/completions` 路径、同样的账号 **JWT**（`X-Authorization: Bearer`）、同样的 `X-Request-Model` 路由、同样的 `X-Harness-Type: zcode`、同样的 MD5 `X-Auth-Sign`（`APP_ID=100003`/`APP_KEY` 两构建逐字相同）、同样的 `/userapi/v1/refresh`（含 `400002→agent-refresh` 降级）。
3. **真正的差异只有三处**：① **主机域名**（`*.zhipuai.cn` → `*.autoglm.ai`）；② **登录方式**（+86 短信 → Google / Z.ai OAuth）；③ **`X-Lang`**（`zh-CN` → `en`）。
4. **修正早期误解**：之前推断"海外 = Coding Plan apiKey + Ed25519 签名"是**错的**。Ed25519+PoW 客户端签名是 **BYOK（用户自带 `bigmodel.cn`/`z.ai` apiKey）的可选通道**，国内外构建都有，**与内置加速通道无关**（详见 §5）。
5. **对 `autoclaw-proxy` 的含义**：支持海外版 ≈ **换个 host**（仓库已有 `upstream_host` 设置）+ 改 `X-Lang`，其余 JWT/刷新/签名/头部全一致——**不需要实现 Ed25519 签名通道**。

## 1. 取证来源（✅ 全部实测，可复现）

| 物料 | 来源 | 大小 | 关键产物 |
|---|---|---|---|
| 国内构建 | `autoglm.oss-cn-beijing.aliyuncs.com/autoclaw/updates/autoclaw_1.18.5_amd64.deb` | 299MB | `isOversea=false`，`app.asar`(308MB) |
| 海外构建 | `autoglm-public-oss.z.ai/autoclaw/updates/autoclaw-1.18.5-mac.zip` | 628MB | `isOversea=true`，`app.asar`(310MB) |
| 落地页 | `autoclaw.z.ai`（内置浏览器实时抓取） | — | 版本/更新源/支付 API/模型清单 |

解包链：`.deb`→`ar`→`data.tar.xz`→`opt/AutoClaw/resources/app.asar`；`.zip`→`AutoClaw.app/Contents/Resources/app.asar`。
`app.asar` 用 Python 解析 Pickle 头（无 `7z`/`asar` 工具）→ 提取 `out/main/index.js`、`package.json`、`model-provider-config.json`。

## 2. 主机映射（✅ 两构建 `index.js` 实证）

| 用途 | 国内（`isOversea=false`） | 海外（`isOversea=true`） |
|---|---|---|
| **LLM 代理**(prod) | `autoglm-acceleration-api.zhipuai.cn/autoclaw-proxy/proxy/autoclaw` | **`autoglm-api.autoglm.ai/autoclaw-proxy/proxy/autoclaw`** |
| LLM 代理(pre) | `autoglm-pre-api.zhipuai.cn/...` | `autoglm-pre-api.autoglm.ai/...` |
| userapi(prod) | `autoglm-api.zhipuai.cn` | `autoglm-api.autoglm.ai` |
| userapi(accel/test) | `autoglm-acceleration-api.zhipuai.cn` / `autoglm-inner-3.zhipuai.cn` | `autoglm-api.autoglm.ai` / `autoglm-test-api.autoglm.ai` |
| cloud/relay | `autoglm-acceleration-api.zhipuai.cn` | `autoglm-api.autoglm.ai` |
| agent-common(文件/OCR) | `autoglm-acceleration-api.zhipuai.cn/agent-common` | `autoglm-api.autoglm.ai/agent-common` |
| 登录回调 | 无（短信） | `autoglm-api.autoglm.ai/userapi/oauth/google/callback` |
| 更新源 | `autoglm.aminer.cn` / `oss-cn-beijing` | `autoglm-public-oss.z.ai` |
| 支付 API | userapi（`*.zhipuai.cn`） | `autoglm-api.autoglm.ai`（落地页 `pay-sign.js`） |

海外构建里 `getZaiProxyBaseUrl$1()` / `getUserApiHost()` / `getApiRequestHost()` / `getCloudServiceHost()` **全部硬编码返回 `*.autoglm.ai`**（zhipuai.cn 分支被编译期消除）。证据：
```js
// 海外 index.js
function getZaiProxyBaseUrl$1(){ const suffix="/autoclaw-proxy/proxy/autoclaw";
  { if(isPre) return `https://autoglm-pre-api.autoglm.ai${suffix}`;
    return `https://autoglm-api.autoglm.ai${suffix}`; } }
function getUserApiHost(env=getEnv()){ switch(env){
  case "development": case "test": return "https://autoglm-test-api.autoglm.ai";
  case "pre": return "https://autoglm-pre-api.autoglm.ai";
  default: return "https://autoglm-api.autoglm.ai"; } }
const isOversea = true;            // 国内构建此处为 false
let currentLang = "en";            // 国内构建为 "zh-CN"
const APP_ID="100003", APP_KEY="38d2391985e2369a5fb8227d8e6cd5e5";  // 两构建相同
```

## 3. 内置 LLM 通道逐项对比（✅ 实证）

| 维度 | 国内 | 海外 | 是否相同 |
|---|---|---|---|
| 端点路径 | `/autoclaw-proxy/proxy/autoclaw/chat/completions` | 同 | ✅相同 |
| 鉴权 | `X-Authorization: Bearer <账号JWT>`（HS256,24h） | 同 | ✅相同 |
| 路由 | `X-Request-Model`（优先于 body model），前缀 `zai_/zaicoding_/openrouter_`，`toModelProxyBodyModelId=replace(/^[a-z]+_/,"")` | 同 | ✅相同 |
| 准入头 | `X-Harness-Type: zcode`（必带） | 同 | ✅相同 |
| 静态头 | `X-Product:autoclaw`/`X-Client-Type:pc`/`X-Tm:getPlatformTm()`/`X-Version:app.getVersion()`/`X-Channel`/`x_trace_id:autoclaw-desktop` | 同 | ✅相同 |
| 语言头 | `X-Lang: zh-CN` | `X-Lang: en`（`getLang()`） | ❌不同 |
| userapi 签名 | `X-Auth-Sign=md5("100003&<ts>&38d2…5e5")` | 同（常量逐字相同） | ✅相同 |
| 刷新 | `POST /userapi/v1/refresh`，`400002`→`/userapi/v1/agent-refresh` | 同 | ✅相同 |
| 凭证存储 | `enc:v10`（Electron safeStorage：DPAPI→AES-256-GCM） | 同框架 | ✅相同（⚠️海外账号未实测） |
| 模型清单 | 远端 `{proxy}/autoclaw-model-config` 下发 | 同机制 | ✅相同（海外具体 ID 未拉取） |
| 线格式 | 标准 OpenAI Chat Completions + `reasoning_content` | 同 | ✅相同 |

> 即：**海外内置通道 = 国内通道，把 `autoglm-acceleration-api.zhipuai.cn` 换成 `autoglm-api.autoglm.ai`、`X-Lang` 换 `en`**。

## 4. 登录差异（最大的工程差异，✅ 实证）

| | 国内 | 海外 |
|---|---|---|
| 主流程 | +86 短信：`/userapi/v1/agent-send-code` → `/userapi/v1/agent-login/` | **Google OAuth** + **Z.ai OAuth** |
| 相关常量 | `phoneCodeLogin`/`sendCode` | `GOOGLE_WEB_OAUTH_CALLBACK_PROD_URL`、`AUTH_OVERSEA_GOOGLE_OAUTH_URL`、`AUTH_OVERSEA_ZAI_OAUTH_URL`、`AUTH_OVERSEA_CAPTCHA_CONFIG` |
| 验证码 | 阿里云 WAF（`acw_tc`/307） | 海外 captcha（`auth:oversea-captcha-config`） |

注：短信登录函数（`agent-send-code`/`agent-login/`）在海外 bundle 中**仍存在**（共享代码），但海外主流程走 OAuth。
**对代理的含义**：OAuth 自动化比短信难；但**账号导入不受影响**——海外版登录后 JWT 同样落 `~/.openclaw-autoclaw/openclaw.json`、`request-headers.json`，格式一致，`import_local.go` 可直接复用，只需把该账号的 host 指向 `autoglm-api.autoglm.ai`。

## 5. BYOK 第三方 provider 与 Ed25519 客户端签名（澄清：与国内/海外差异**无关**）

`model-provider-config.json`（两构建同款）列出**用户可自带的第三方 provider**：
```
zhipu-direct      openai=https://open.bigmodel.cn/api/paas/v4         anthropic=…/api/anthropic
zhipu-codingPlan  openai=https://open.bigmodel.cn/api/coding/paas/v4  (accessType=codingPlan)
deepseek-direct   https://api.deepseek.com
kimi-direct/codingPlan, minimax-direct …
```
海外对应 host 为 `api.z.ai/api/paas/v4`、`api.z.ai/api/coding/paas/v4`。

当用户用 `{id}.{secret}` 形态 apiKey 连接 host ∈ `{bigmodel.cn, z.ai}` 的 provider 时，启用 **Ed25519 + PoW 客户端签名**（算法见 `docs/02 §5`：握手 `/api/paas/c1f3a7e2/v2/client`、`X-Client-Sig/Id/Ts/Version/Nonce/Pow`）。bundle 注释原文：
> "后缀匹配。国内 `open.bigmodel.cn`/`dev.bigmodel.cn`，海外 `api.z.ai` —— 两地的握手路径相同，握手地址按业务请求同源推导，因此只需放行域名即可两地通用。"
> `AUTOCLAW_CLIENT_SIGN_DEFAULT_HOSTS = ["bigmodel.cn","z.ai"]`

**关键**：`getAutoClawClientSignTarget()` 对内置 `zai`/autoclaw 加速通道返回 null（不签名）。所以 Ed25519 签名是 **BYOK 直连第三方/Coding Plan 的可选特性，国内外构建都有**，不是"海外 vs 国内"的差异，也不是内置 LLM 通道所需。落地页 "Use your GLM Coding Plan in AutoClaw" 指的就是这条 BYOK 增益路径。

## 6. 对 autoclaw-proxy 的改造点（修正后，大幅简化）

| # | 文件 | 改动 | 难度 |
|---|---|---|---|
| 1 | `account.go:185-190`(`hostSetting`)、`llm.go:167` | host 改为 **per-account/region**：海外账号 → `https://autoglm-api.autoglm.ai`（仓库已有全局 `upstream_host` 设置，扩成按账号即可） | 低 |
| 2 | `userapi.go:36`(`autoclawLang="zh-CN"`)、`llm.go:54` | `X-Lang` 改为 per-region：海外 `en` | 低 |
| 3 | `userapi.go:34`(`autoclawAppVersion="1.18.4"`) | 可选升到 `1.18.5`（`X-Version`，疑似不严格校验） | 低 |
| 4 | `import_local.go` | 海外安装的同路径 `~/.openclaw-autoclaw/` JWT 直接可导入；导入时标记 `region=overseas` | 低 |
| 5 | `database.go` accounts 表 | 增 `region`/`provider_host` 字段 | 低 |
| 6 | `account.go`(`LoginManager`) | 海外 OAuth 登录自动化（**难，建议先不做**，靠导入海外版已登录账号） | 高/可选 |
| — | ~~`clientsign.go`~~ | **不需要**（除非另行支持 BYOK Coding Plan，那是独立 feature） | — |

> 一句话：**让 autoclaw-proxy 支持海外版，核心就是"按账号切 host + 切 X-Lang"，JWT/刷新/MD5 签名/请求头全部复用现有实现。**

## 7. 待核实 / 未覆盖（需海外账号实测）

1. 海外账号 JWT 的 claims 结构是否与国内完全一致（同 codebase，大概率一致，未用真实海外账号验证）。
2. 海外 `autoclaw-model-config` 实际下发的模型路由 ID 清单（落地页营销名为 GLM-5.3-Flash/5.3/5.2/5-Turbo/5V-Turbo，对应路由 ID 未拉取）。
3. 海外端点是否真的接受相同 `APP_ID/APP_KEY` 的 MD5 签名（bundle 常量相同，但未对 `autoglm-api.autoglm.ai` 发实测请求）。
4. 海外风控/TLS 指纹（`autoglm.ai` 是否在 Cloudflare 后、是否拒 utls），`transport.go` 指纹预设需实测调整。
5. 海外 OAuth 登录能否被代理自动化（或是否只能靠导入）。

**进一步取证方式**：(A) 注册/登录一个海外账号，用 `autoclaw-proxy -import-local` 导入其 JWT，把 `upstream_host` 设为 `https://autoglm-api.autoglm.ai` 直接实测；(B) 运行海外版抓包（mitmproxy）观测真实请求头与 host。

## 8. 附录：实测证据片段

**版本/发行**：两构建 `package.json` 均 `name=autoclaw, version=1.18.5`；海外更新清单 `latest.yml`/`latest-mac.yml` 标 `releaseDate 2026-09-11`；安装包命名国内带 `-cn` 后缀、海外不带（`BaseLayout.js` 反编译：`const r = isCN ? "-cn" : ""`）。

**落地页**（`autoclaw.z.ai`，Astro 静态站）：标题 "AutoClaw - Z.ai's Official AI Agent | GLM-5.3-Flash Now Live"；`sameAs` 含国内对应站 `autoclaw.zhipuai.cn`；营销 "Use your GLM Coding Plan in AutoClaw"、新用户送 1 亿 GLM-5.3-Flash tokens；分析埋点走 Volcengine `ap-southeast-1`（新加坡）。`pay-sign.js` → `https://autoglm-api.autoglm.ai`，带 `X-Auth-Appid/TimeStamp/Sign`（同 MD5 签名族）。

**webview 白名单**（海外构建）：`["zhipuai.cn","z.ai","autoglm.ai","aminer.cn","stripe.com", …]`；可信远程文件后缀含 `.autoglm.ai`/`.autoglm.com`/`.zhipuai.cn`。

> 早期 WebFetch/浏览器对 `autoclaw.z.ai` 超时系加载慢/瞬时；改用已打开标签 + 轮询 `readyState` 后稳定抓取。落地页不含 LLM 协议，真实主机/签名由 §1 的安装包逆向确认。
