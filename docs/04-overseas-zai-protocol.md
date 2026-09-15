# AutoClaw 海外版（z.ai）协议差异分析

> 对比对象：国内版 = 本仓库 `autoclaw-proxy` 现状（`*.zhipuai.cn`，账号 JWT 通道）；
> 海外版 = `autoclaw.z.ai` / `*.z.ai`（Z.ai 海外品牌）。
> 编写时间：2026-09-15。国内侧依据代码 + `docs/01~03` 实测；海外侧依据 `docs/02 §5`、`docs/03 §5`
> 从官方 AutoClaw 1.18.4 bundle 逆向出的 z.ai/bigmodel 客户端签名规范，叠加本次对 z.ai 生态的可达性探测。

## 0. 取证状态与可信度标注

本机为国内 IP、无海外出口代理，`autoclaw.z.ai` **不可达**（见 §7 实测）。因此海外侧结论按可信度分级标注：

| 标记 | 含义 |
|---|---|
| ✅已证实 | 仓库代码/`docs` 已从官方 bundle 逆向并实测，或本次对可达 z.ai 主机的直接观测 |
| ⚠️推断 | 依据上述文档 + z.ai 生态常识推出，**未经 `autoclaw.z.ai` 实时验证** |
| ❓待核实 | 关键未知项，必须拿到海外出口代理或海外版客户端 bundle 才能确认 |

> 一句话结论：**国内版与海外版不是"换域名"，而是两套鉴权体系。** 国内走「账号 JWT 私有头 + 无签名」，
> 海外 z.ai 主机走「Coding Plan apiKey `{id}.{secret}` + Ed25519 客户端签名 + SHA-256 PoW」。

## 1. 核心差异对比表

| 维度 | 国内版（autoclaw-proxy 现状 ✅） | 海外版（autoclaw.z.ai / z.ai） |
|---|---|---|
| 品牌主体 | 智谱 AutoClaw / `zhipuai.cn` | Z.ai 海外品牌 / `z.ai`（`chat.z.ai` 标题=GLM-5.3-Flash ✅） |
| LLM 主机 | `autoglm-acceleration-api.zhipuai.cn`（`userapi.go:40`） | `api.z.ai` ⚠️（`api.z.ai`→`z.ai/model-api` 301 ✅） |
| LLM 路径 | `/autoclaw-proxy/proxy/autoclaw/chat/completions`（`userapi.go:43`,`llm.go:167-168`） | `/api/paas/v4/chat/completions` ⚠️（`docs/01:19` 提及 `api.z.ai/api/paas/v4` 被补丁替换 ✅） |
| 鉴权凭证 | 账号 **JWT**，私有头 `X-Authorization: Bearer <JWT>`，HS256，24h（`llm.go:46`,`docs/02 §3`） | **Coding Plan apiKey `{id}.{secret}`**，走 `Authorization`/`x-api-key` ⚠️（`docs/02 §5`） |
| 请求签名 | **无**（`zai` provider 显式豁免，`docs/02 §5`/`docs/01 §2.4`） | **Ed25519 签名 + SHA-256 PoW(8 bit)** ✅文档（`docs/02 §5`） |
| 签名握手 | 无 | `POST {origin}/api/paas/c1f3a7e2/v2/client` ✅文档 |
| userapi 业务签名 | MD5：`X-Auth-Sign=md5("100003&<ts>&38d2…5e5")`（`userapi.go:69-72`） | ❓未知（海外可能不同/不需要） |
| 登录方式 | **+86 短信**（`agent-send-code`/`agent-login/`，`userapi.go:6-7`） | ❓推断 email / Google OAuth |
| 路由 | 私有头 `X-Request-Model: zai_auto`（覆盖 body model，`llm.go:48`,`docs/01 §3`） | ⚠️可能直接用 body `model`（PaaS v4 标准） |
| 语言/准入头 | `X-Lang: zh-CN`（`userapi.go:36`）、`X-Harness-Type: zcode`（必带，`llm.go:49`） | `X-Lang: en-US` ⚠️、准入头 ❓ |
| 凭证存储 | `enc:v10`（Electron safeStorage：DPAPI→AES-256-GCM，`crypto.go:160-243`） | ⚠️大概率相同（同一 Electron 框架） |
| 风控/WAF | 阿里云 WAF（`acw_tc` cookie、307、拒 utls 指纹，`transport.go:490-503`） | ❓推断 Cloudflare 类 |
| 模型 | `zai_auto`→`deepseek-v4-flash`、`glm-5.3`、`glm-5.3-flash`（`docs/01 §3`） | `GLM-5.3-Flash` 等（`chat.z.ai` 标题证实存在 ✅），完整清单 ❓ |

## 2. 国内版协议回顾（基线，全部 ✅）

作为对照锚点，国内版主链路（详见 `docs/01-llm-api.md`）：

- **端点**：`POST https://autoglm-acceleration-api.zhipuai.cn/autoclaw-proxy/proxy/autoclaw/chat/completions`
- **鉴权**：私有头 `X-Authorization: Bearer <账号 JWT>`（HS256，24h，claims 含 `user_id/device_id/source_id`）。
  注意**不是**标准 `Authorization`。
- **路由**：`X-Request-Model: zai_auto`（优先级高于 body `model`）；body model = 路由 ID 去前缀（`zai_auto`→`auto`，`llm.go:36-39`）。
- **准入**：`X-Harness-Type: zcode` 必带，缺失返回误导性 `500 {"message":"invalid request body"}`。
- **静态身份头**：`X-Product: autoclaw`、`X-Client-Type: pc`、`X-Tm: win`、`X-Version: 1.18.4`、`X-Channel: official`、`X-Lang: zh-CN`（`llm.go:42-57`）。
- **令牌刷新**：`POST /userapi/v1/refresh`，MD5 签名 `X-Auth-Sign`，rt 单次轮换；401→刷新重放一次（`llm.go:190-202`）。
- **登录**：+86 短信验证码（`agent-send-code` → `agent-login/`，尾斜杠触发阿里云 WAF 307 下发 `acw_tc`）。
- **签名**：LLM 通道**不做客户端签名**——网关 `getAutoClawClientSignTarget()` 对 `model.provider==="zai"` 直接返回 null。

## 3. 海外版（z.ai）协议

### 3.1 API 面（⚠️推断）
海外大概率是标准 **PaaS v4** OpenAI 兼容接口：`https://api.z.ai/api/paas/v4/chat/completions`，
而非国内 autoclaw 专属加速代理路径。依据：`docs/01:19` 记录官方补丁 `patchPiAiModelsBaseUrl`
会把所有 `api.z.ai/api/paas/v4`、`open.bigmodel.cn/api/paas/v4`（含 `/api/coding/paas/v4`）上游地址
替换为加速代理——说明 z.ai 原生 API 面就是 `/api/paas/v4`。线格式两边都应是标准 OpenAI Chat Completions
（国内 ✅实测；海外 ⚠️未验证）。`autoclaw.z.ai` 本身是门户/下载站还是 API 主机，❓待核实。

### 3.2 鉴权：Coding Plan apiKey（⚠️）
海外通道用 **Coding Plan apiKey**，形态 `{id}.{secret}`，经 `Authorization: Bearer {id}.{secret}` 或
`x-api-key` 携带（`docs/02 §5`）。这与国内的"账号 JWT"是**不同凭证类型**：apiKey 是长期密钥，
JWT 是 24h 短时令牌。账号模型需相应扩展（见 §4）。

### 3.3 Ed25519 客户端签名 + PoW（✅文档已证实算法）

这是海外侧与国内侧**最实质的差异**。以下常量与流程取自 `docs/02 §5` / `docs/03 §5`（官方 bundle 逆向）：

**常量**
```
KDF_SALT        = "WD_CLIENT_SIGN_KDF_SALT"     // HKDF-SHA256 salt
INFO_HANDSHAKE  = "getSignKey_hmac"             // 握手 HMAC key 的 HKDF info
INFO_PRIV       = "ed25519_priv"                // 私钥解封 KEK 的 HKDF info
APP_ID          = "autoclaw"
SIGN_VERSION    = "1.18.1"                      // X-Client-Version
POW_BITS        = 8                             // PoW 难度：SHA-256 前导 8 个零 bit
POW_MAX_ITER    = 5,000,000
KEY_TTL         = 6h                            // 签名私钥缓存时长
HANDSHAKE_PATH  = /api/paas/c1f3a7e2/v2/client  // 拼在模型 baseUrl 的 origin 后
```

**握手（取签名私钥）**
```
reqKek  = HKDF-SHA256(secret, salt=KDF_SALT, info=INFO_HANDSHAKE, 32B)
message = "get_sign_key\n" + id + "\n" + ts + "\n" + nonce      // nonce = 16 字节随机 hex
sig     = HMAC-SHA256(reqKek, message) → base64

POST {origin}/api/paas/c1f3a7e2/v2/client     (超时 10s)
  Authorization: Bearer {id}.{secret}
  body: {"apiKey":"{id}.{secret}", "ts":…, "nonce":…, "sig":…}
  → {"code":200, "data":{"privateCipher":"<base64>"}}

kek     = HKDF-SHA256(secret, salt=KDF_SALT, info=INFO_PRIV, 32B)
blob    = base64decode(privateCipher)         // [0:12]=IV, [12:-16]=密文, [-16:]=tag
privPK8 = AES-256-GCM-Decrypt(kek, IV, 密文, tag, AAD=id)
Ed25519PrivateKey = ParsePKCS8(privPK8)       // 缓存 6h，失败冷却 10min
```

**每请求签名 + PoW**
```
sessionId = 会话 ID（读自请求头/上下文）
message   = id + "\n" + ts + "\n" + SIGN_VERSION + "\n" + sessionId + "\n" + nonce
X-Client-Sig     = base64( Ed25519Sign(私钥, message) )
X-Client-Id      = id
X-Client-Ts      = ts
X-Client-Version = "1.18.1"
X-Client-Nonce   = nonce
X-Session-Id     = sessionId

challenge = SHA256(id + "\n" + APP_ID + "\n" + sessionId + "\n" + ts).hex[:32]
遍历 candidate=0…：SHA256(challenge + "\n" + candidate) 前导零 bit ≥ 8 → X-Client-Pow = candidate
（平均 256 次哈希，<1ms）
```

**验签失败自愈（401 + body 含 `VERIFY_*`）**

| 分类 | 错误码 | 动作 |
|---|---|---|
| rekey | `VERIFY_SIGNATURE_INVALID`、`VERIFY_APIKEY_EXPIRED` | 失效私钥缓存 → 重握手 → 重签，重试一次 |
| hard | `VERIFY_POW_REQUIRED/INVALID`、`VERIFY_TS_OUT_OF_WINDOW`、`VERIFY_MISSING_FIELD`、`VERIFY_INVALID_FORMAT`、`VERIFY_PROTOCOL_ERROR`、`VERIFY_APIKEY_DISABLED` | 立即停签 30min（请求继续但不带签名），到期自动恢复 |
| 未知码 | 其余 `VERIFY_*` | 仅计数，10min 窗口内连续 ≥2 次才停签 |

### 3.4 登录 / 账号获取（❓待核实）
国内是 +86 短信。海外通常 email / Google OAuth，且大概率无阿里云 WAF 的 `acw_tc` 307 那套。
**海外版究竟是「用户用 apiKey 直接接入」还是「也有账号登录态铸 JWT」，是最大未知项**，需 §6 取证确认。

### 3.5 风控 / TLS 指纹（❓）
国内上游有阿里云 WAF（拒 utls ClientHello，见 `transport.go:490-503`）。海外 z.ai 更可能在 Cloudflare 之后，
TLS/HTTP2 指纹与 PoW 准入策略不同。`transport.go` 的 utls 指纹与 SOCKS5/HTTP CONNECT 出口能力可复用，
但具体指纹预设需实测调整。

## 4. 对 autoclaw-proxy 的改造点（引用真实代码行）

底层密码学能力**大部分已具备**：`crypto.go` 已 import `crypto/ed25519`、`crypto/sha256`、`crypto/aes`、
`crypto/cipher`、`crypto/x509`，并有 `GenerateDeviceIdentity()`（`crypto.go:47`）、AES-GCM 加解密
（`crypto.go:193-243`）。需补齐 HKDF（`golang.org/x/crypto/hkdf`，go.mod 已含 `golang.org/x/crypto`）、
HMAC（`crypto/hmac` 标准库）、Ed25519 签名（`crypto/ed25519` 标准库）、PoW（SHA-256 计数）。

| # | 文件 | 改动 |
|---|---|---|
| 1 | `userapi.go:29-45` / `llm.go:167-168` | 把「主机 + 路径 + 鉴权方式」抽象为 provider；新增 z.ai provider：host=`api.z.ai`、path=`/api/paas/v4`、apiKey 鉴权（区别于现有 `hostSetting()`+`llmProxyPath`+JWT） |
| 2 | 新增 `clientsign.go` | 实现 §3.3：HKDF+HMAC 握手 → AES-256-GCM 解封 Ed25519 私钥（AAD=id）→ 每请求 Ed25519 签名 + SHA-256 PoW(8bit) + `VERIFY_*` 自愈；私钥 6h 缓存、失败 10min 冷却 |
| 3 | `llm.go:42-57`（`llmHeaders`） | 海外通道头：去掉 `X-Authorization`/`X-Harness-Type`/`X-Request-Model`（⚠️待核实），改注入 `Authorization: Bearer {id}.{secret}` + `X-Client-Sig/Id/Ts/Version/Nonce` + `X-Client-Pow` + `X-Session-Id`；`X-Lang: en-US` |
| 4 | `account.go` | 账号模型增加 "Coding Plan apiKey `{id}.{secret}`" 类型（区别于 JWT）；对应失效/重握手逻辑（apiKey 不过期但会 `VERIFY_APIKEY_EXPIRED/DISABLED`） |
| 5 | `transport.go` | 海外出口 utls 指纹预设 + 复用现有 SOCKS5/HTTP CONNECT（`ClientForProxy`，`llm.go:180` 已用） |
| 6 | `database.go` | accounts 表增加 provider/region 字段与 apiKey 存储（沿用 `enc:v10` 或独立加密） |

> 注意：`docs/02 §5` 明确客户端签名"仅当 host ∈ {bigmodel.cn, z.ai} 且带 `{id}.{secret}` apiKey 时启用"。
> 因此海外通道是否真的启用签名，取决于 §6 对 `autoclaw.z.ai` 的实测——**不要在未验证前直接照搬实现**。

## 5. 必须实时核实的清单（需海外出口代理 / 海外版 bundle）

1. `autoclaw.z.ai` 是门户/下载站还是 API 主机？真实 LLM 主机与路径（是否 `api.z.ai/api/paas/v4`）。
2. 海外登录流程：email/Google OAuth？是否仍签发 JWT，还是纯 apiKey 接入。
3. 海外是否真启用 Ed25519+PoW 客户端签名？握手路径是否仍是 `/api/paas/c1f3a7e2/v2/client`？常量是否一致？
4. 海外模型 ID 清单与路由方式（`X-Request-Model` 头 vs body `model`）。
5. 海外是否仍有 `X-Harness-Type: zcode` 类准入头；`X-Lang`/`X-Channel`/`X-Product` 取值。
6. 海外风控类型（Cloudflare？）与 TLS 指纹要求。

## 6. 取证方法（阶段 0）

- **方式 A（推荐）**：用户开启海外出口代理（系统级/TUN 全局，或提供 SOCKS5/HTTP 代理）。
  代理生效后，本工具的 WebFetch / 内置浏览器即可触达 `autoclaw.z.ai`，用浏览器抓 Network 面板：
  登录流程、LLM 请求主机/路径/头、是否出现 `/api/paas/c1f3a7e2/v2/client` 握手、模型清单。
- **方式 B**：用户提供海外版抓包文件 / HAR / 海外版 AutoClaw 客户端 bundle（`app.asar`），离线逆向。
- 取证后用一手证据替换本文所有 ⚠️/❓ 标注，再进入阶段 2 编码。

## 7. 附录：z.ai 生态可达性实测（2026-09-15，本机国内 IP，无出口代理）

| 主机 | WebFetch | 内置浏览器(IAB) | 结论 |
|---|---|---|---|
| `z.ai` | 307 → `chat.z.ai` ✅ | — |  apex 可达，跳转海外 chat |
| `chat.z.ai` | 200，标题 "Z.ai - Advanced AI Chatbot & Agent powered by GLM-5.3-Flash" ✅ | 32s 超时 ❌ | 海外消费级 chat，模型含 GLM-5.3-Flash |
| `api.z.ai` | 301 → `z.ai/model-api` ✅ | — | 海外 API 产品入口 |
| `z.ai/model-api` | 超时 ❌ | — | 重页面/防护，未取到内容 |
| `docs.z.ai` | 超时 ❌ | — | 未取到内容 |
| `autoclaw.z.ai` | 超时 ×3 ❌ | 32s 超时 ×2 ❌ | **本机不可达**，海外 AutoClaw 主机需出口代理 |

> 探测限制：plan 模式下 Bash（含只读 `curl`）被禁用，无法走命令行/代理直连；WebFetch 与内置浏览器
> 默认不走任意代理。故 `autoclaw.z.ai` 实时取证依赖 §6 方式 A/B。
