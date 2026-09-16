# AutoClaw 海外版（z.ai）协议差异分析

> 对比对象：国内版 = 本仓库 `autoclaw-proxy` 现状（`*.zhipuai.cn`，账号 JWT 通道，AutoClaw 1.18.4）；
> 海外版 = `autoclaw.z.ai`（Z.ai 海外品牌，AutoClaw 1.18.5）。
> 编写时间：2026-09-15。**本次已用内置浏览器实时抓取 `autoclaw.z.ai`（落地页 + `/models/` + `_astro` JS 包 + electron-updater 清单）**，
> 海外侧大量结论从"推断"升级为"实测"。LLM 通道签名细节仍引自 `docs/02 §5`、`docs/03 §5`（官方 1.18.4 bundle 逆向）。

## 0. 取证状态与可信度标注

| 标记 | 含义 |
|---|---|
| ✅实测 | 本次对 `autoclaw.z.ai` 的实时抓取，或仓库代码/`docs` 已实测 |
| ✅文档 | 仓库 `docs/02~03` 从官方 bundle 逆向并实测的协议（海外 LLM 签名通道） |
| ⚠️推断 | 依据上述证据推出、未直接验证 |
| ❓待核实 | 关键未知项，需海外版客户端 bundle 或抓包确认 |

> **一句话结论**：海外版与国内版是**同一款 AutoClaw 的两个发行版**（同源 Electron 应用），但走**两套不同的 LLM 鉴权体系**：
> 国内 = 账号 **JWT** 私有头 + **无签名**；海外 = **GLM Coding Plan apiKey `{id}.{secret}` + Ed25519 客户端签名 + SHA-256 PoW**（标准 PaaS v4 接口）。
> 业务/支付层两边都用同一套 **MD5 `X-Auth-Sign`** 签名（海外支付 API `autoglm-api.autoglm.ai` 已实测带 `X-Auth-Appid/TimeStamp/Sign`）。

## 1. 核心差异对比表

| 维度 | 国内版（autoclaw-proxy 现状） | 海外版（autoclaw.z.ai） | 可信度 |
|---|---|---|---|
| 落地页 | `autoclaw.zhipuai.cn` | `autoclaw.z.ai`（标题 "Z.ai's Official AI Agent \| GLM-5.3-Flash"） | ✅实测 |
| 应用版本 | 1.18.4（`userapi.go:34`） | **1.18.5**（2026-09-11 发布） | ✅实测 |
| 更新源(electron-updater) | `autoglm.aminer.cn/autoclaw/updates` | `autoglm-public-oss.z.ai/autoclaw/updates` | ✅实测 |
| 安装包命名 | `autoclaw-<ver>-cn.dmg` / `-cn` 后缀 | `autoclaw-1.18.5-setup.exe` / `autoclaw-1.18.5.dmg`（无 `-cn`） | ✅实测 |
| 支付/业务 API | userapi `*.zhipuai.cn`（MD5 `X-Auth-Sign`） | `autoglm-api.autoglm.ai`（MD5 `X-Auth-Sign`，同款签名） | ✅实测 |
| LLM 主机 | `autoglm-acceleration-api.zhipuai.cn`（`userapi.go:40`） | `api.z.ai`（候选）/ 或 `autoglm-api.autoglm.ai` | ✅文档 / ❓实测主机 |
| LLM 路径 | `/autoclaw-proxy/proxy/autoclaw/chat/completions`（`llm.go:167-168`） | `/api/paas/v4/chat/completions` | ✅文档 / ⚠️ |
| LLM 鉴权 | 账号 **JWT**，私有头 `X-Authorization: Bearer <JWT>`（`llm.go:46`） | **Coding Plan apiKey `{id}.{secret}`**（`Authorization`/`x-api-key`） | ✅文档 + 落地页佐证 |
| LLM 请求签名 | **无**（`zai` provider 豁免，`docs/02 §5`） | **Ed25519 签名 + SHA-256 PoW(8bit)**，握手 `/api/paas/c1f3a7e2/v2/client` | ✅文档 |
| 路由 | 私有头 `X-Request-Model: zai_auto`（`llm.go:48`） | ⚠️可能用 body `model`（PaaS v4 标准） | ⚠️ |
| 登录 | **+86 短信**（`agent-send-code`/`agent-login/`） | ❓email/Google OAuth + Coding Plan（落地页 "Join now"→飞书文档） | ❓ |
| 语言/准入头 | `X-Lang: zh-CN`、`X-Harness-Type: zcode`（必带，`llm.go:49`） | `X-Lang: en-US`⚠️、准入头❓ | ⚠️/❓ |
| 模型 | `zai_auto`→deepseek-v4-flash、glm-5.3、glm-5.3-flash | **GLM-5.3-Flash / 5.3 / 5.2 / 5-Turbo / 5V-Turbo** | ✅实测 |
| 部署区域 | 国内（阿里云 OSS北京、aminer.cn） | 海外（Volcengine `ap-southeast-1` 新加坡、z.ai/autoglm.ai） | ✅实测 |
| 风控/WAF | 阿里云 WAF（`acw_tc`、307、拒 utls，`transport.go:490-503`） | ❓推断 Cloudflare 类 | ❓ |
| 多端 | Windows 为主 | Win/Mac(intel+apple-silicon)/Linux(.deb)/Android(.apk) | ✅实测 |

## 2. 海外版分发与基础设施（✅本次实时抓取）

从 `autoclaw.z.ai` 落地页、`/_astro/*.js` 包与 electron-updater 清单提取：

**落地页性质**：Astro 静态营销站（`/_astro/` 资源），`<html lang="en">`，仅发分析类 XHR（Volcengine/GA/Bing/Clarity），**不含 LLM API 调用**。结构化数据 `sameAs` 同时列出 `https://z.ai`、`https://x.com/Zai_org`、**`https://autoclaw.zhipuai.cn/`**——证实国内/海外落地页成对存在。

**版本与更新源**（electron-updater，CORS 可读）：
```
海外: https://autoglm-public-oss.z.ai/autoclaw/updates/latest.yml      → version 1.18.5, autoclaw-1.18.5-setup.exe (sha512…, 2026-09-11)
海外: https://autoglm-public-oss.z.ai/autoclaw/updates/latest-mac.yml  → autoclaw-1.18.5-mac.zip(628MB) / autoclaw-1.18.5.dmg(636MB)
国内: https://autoglm.aminer.cn/autoclaw/updates/...
Linux: https://autoglm.oss-cn-beijing.aliyuncs.com/autoclaw/updates/autoclaw_1.18.5_{amd64,arm64}.deb
Android: https://autoglm.aminer.cn/autoclaw/update-apk/official/autoclaw_release.apk
```

**安装包命名规则**（`BaseLayout…js` 实测反编译）：
```js
// manifest: `${downloadRoot}/${mac?"latest-mac.yml":"latest.yml"}?t=<ts-rand>`
// 下载路径: const r = isCN ? "-cn" : "";
//   mac(apple-silicon): `${root}/autoclaw-${ver}${r}.dmg`
//   mac(intel):         `${root}/autoclaw-${ver}-x64${r}.dmg`
//   windows:            `${root}/autoclaw-${ver}-setup${r}.exe`
```
即**国内构建带 `-cn` 后缀，海外不带**——这是发行版区分的硬证据。

**支付/业务 API**（`pay-sign.DjyFK-JG.js` 实测）：
```
const et = "https://autoglm-api.autoglm.ai";   // 海外支付/订单 API
请求头含: X-Auth-Appid / X-Auth-TimeStamp / X-Auth-Sign   // 与国内 userapi 同款 MD5 签名族
```
说明海外**业务层签名沿用 MD5 `X-Auth-Sign`**（`docs/03 §1.2` 同款：`md5(APP_ID&ts&APP_KEY)`），与 LLM 层的 Ed25519 签名是两套独立体系。

**海外模型清单**（`/models/` 实测）：GLM-5.3-Flash（NEW 2026.08，多模态轻量）、GLM-5.3（2026.08 旗舰/agentic coding）、GLM-5.2（2026.06 长上下文）、GLM-5-Turbo（2026.03 agent 工作流）、GLM-5V-Turbo（2026.04 视觉）。营销主打 "**Use your GLM Coding Plan in AutoClaw**"、新用户注册送 1 亿 GLM-5.3-Flash tokens、Individual/Team 套餐——**直接佐证海外 LLM 鉴权 = GLM Coding Plan apiKey**。

## 3. 国内版协议回顾（基线，✅代码+实测）

详见 `docs/01-llm-api.md`。主链路：
- 端点 `POST https://autoglm-acceleration-api.zhipuai.cn/autoclaw-proxy/proxy/autoclaw/chat/completions`
- 鉴权 私有头 `X-Authorization: Bearer <账号JWT>`（HS256,24h,claims含user_id/device_id/source_id），**非标准 Authorization**
- 路由 `X-Request-Model: zai_auto`（优先于 body model）；body model = 路由ID去前缀（`llm.go:36-39`）
- 准入 `X-Harness-Type: zcode` 必带（缺失→误导性 `500 invalid request body`）
- 静态头 `X-Product:autoclaw`/`X-Client-Type:pc`/`X-Tm:win`/`X-Version:1.18.4`/`X-Channel:official`/`X-Lang:zh-CN`（`llm.go:42-57`）
- 刷新 `POST /userapi/v1/refresh`，MD5 `X-Auth-Sign`，rt 单次轮换；401→刷新重放一次（`llm.go:190-202`）
- 登录 +86 短信；**LLM 通道不做客户端签名**（`getAutoClawClientSignTarget()` 对 `provider==="zai"` 返回 null）

## 4. 海外版 LLM 协议（✅文档 bundle 逆向 + 落地页佐证）

### 4.1 API 面（⚠️/❓主机待实测）
海外 LLM 大概率是标准 **PaaS v4** OpenAI 兼容接口 `https://api.z.ai/api/paas/v4/chat/completions`
（依据 `docs/01:19`：官方补丁把 `api.z.ai/api/paas/v4`、`open.bigmodel.cn/api/paas/v4` 上游替换为加速代理）。
落地页实测到的海外主机为 `autoglm-public-oss.z.ai`（更新）与 `autoglm-api.autoglm.ai`（支付）；
**LLM 真实主机未从落地页暴露**（在 app bundle 内），候选 `api.z.ai` 或 `autoglm-api.autoglm.ai`，❓待抓包确认。

### 4.2 鉴权：GLM Coding Plan apiKey（✅落地页佐证 + 文档）
凭证形态 `{id}.{secret}`，经 `Authorization: Bearer {id}.{secret}` 或 `x-api-key` 携带（`docs/02 §5`）。
落地页 "Use your GLM Coding Plan in AutoClaw" + Individual/Team 套餐 ✅佐证。这是与国内"账号 JWT"**不同的凭证类型**（apiKey 长期密钥 vs JWT 24h 短令牌）。

### 4.3 Ed25519 客户端签名 + PoW（✅文档已证实算法）

海外侧与国内侧**最实质的差异**。常量与流程取自 `docs/02 §5`/`docs/03 §5`：

**常量**
```
KDF_SALT="WD_CLIENT_SIGN_KDF_SALT"  INFO_HANDSHAKE="getSignKey_hmac"  INFO_PRIV="ed25519_priv"
APP_ID="autoclaw"  SIGN_VERSION="1.18.1"  POW_BITS=8  POW_MAX_ITER=5,000,000  KEY_TTL=6h
HANDSHAKE_PATH=/api/paas/c1f3a7e2/v2/client
```
**握手取私钥**
```
reqKek=HKDF-SHA256(secret,SALT,INFO_HANDSHAKE,32B)
sig=base64(HMAC-SHA256(reqKek,"get_sign_key\n"+id+"\n"+ts+"\n"+nonce))
POST {origin}/api/paas/c1f3a7e2/v2/client  Authorization:Bearer {id}.{secret}
  body{apiKey,ts,nonce,sig} → {code:200,data:{privateCipher}}
kek=HKDF-SHA256(secret,SALT,INFO_PRIV,32B)
privPK8=AES-256-GCM-Decrypt(kek,IV=base64decode(privateCipher)[0:12],ct=[12:-16],tag=[-16:],AAD=id)
Ed25519PrivateKey=ParsePKCS8(privPK8)   // 缓存6h，失败冷却10min
```
**每请求签名 + PoW**
```
message=id+"\n"+ts+"\n"+SIGN_VERSION+"\n"+sessionId+"\n"+nonce
X-Client-Sig=base64(Ed25519Sign(priv,message)); X-Client-Id=id; X-Client-Ts=ts
X-Client-Version="1.18.1"; X-Client-Nonce=nonce; X-Session-Id=sessionId
challenge=SHA256(id+"\n"+APP_ID+"\n"+sessionId+"\n"+ts).hex[:32]
找 candidate 使 SHA256(challenge+"\n"+candidate) 前导零bit≥8 → X-Client-Pow=candidate (平均256次,<1ms)
```
**401 + `VERIFY_*` 自愈**：rekey 类（`SIGNATURE_INVALID`/`APIKEY_EXPIRED`）→重握手重签一次；hard 类（`POW_*`/`TS_OUT_OF_WINDOW`/`MISSING_FIELD`/`INVALID_FORMAT`/`PROTOCOL_ERROR`/`APIKEY_DISABLED`）→停签30min；未知码→10min内≥2次才停签。

### 4.4 登录 / 账号获取（❓）
国内 +86 短信。海外落地页 "Join now"→飞书文档（Coding Plan 购买），"Download"→安装包；**未暴露登录流程**。
推断 email/Google OAuth + Coding Plan 绑定，❓待 app 抓包确认。

### 4.5 风控 / TLS（❓）
国内阿里云 WAF（拒 utls，`transport.go:490-503`）。海外更可能 Cloudflare 类；utls 指纹与 SOCKS5/HTTP CONNECT 出口能力可复用，预设需实测调整。

## 5. 对 autoclaw-proxy 的改造点（引用真实代码行）

底层密码学**大部分已具备**：`crypto.go` 已 import `crypto/ed25519`、`crypto/sha256`、`crypto/aes`、`crypto/cipher`、`crypto/x509`，有 `GenerateDeviceIdentity()`(`crypto.go:47`)、AES-GCM(`crypto.go:193-243`)。需补 HKDF（`golang.org/x/crypto/hkdf`，go.mod 已含 x/crypto）、HMAC（`crypto/hmac`）、Ed25519 签名（标准库）、PoW（SHA-256 计数）。

| # | 文件 | 改动 |
|---|---|---|
| 1 | `userapi.go:29-45`/`llm.go:167-168` | 把「主机+路径+鉴权」抽象为 provider；新增 z.ai provider：host=`api.z.ai`(❓待确认)、path=`/api/paas/v4`、apiKey 鉴权 |
| 2 | 新增 `clientsign.go` | 实现 §4.3：HKDF+HMAC 握手→AES-256-GCM 解封 Ed25519 私钥(AAD=id)→每请求签名+PoW(8bit)+`VERIFY_*` 自愈；私钥6h缓存、失败10min冷却 |
| 3 | `llm.go:42-57`(`llmHeaders`) | 海外头：去 `X-Authorization`/`X-Harness-Type`/`X-Request-Model`(⚠️待核实)，注入 `Authorization:Bearer {id}.{secret}` + `X-Client-Sig/Id/Ts/Version/Nonce` + `X-Client-Pow` + `X-Session-Id`；`X-Lang:en-US` |
| 4 | `account.go` | 账号模型增 "Coding Plan apiKey `{id}.{secret}`" 类型（区别 JWT）；失效/重握手逻辑 |
| 5 | `transport.go` | 海外出口 utls 指纹预设 + 复用 SOCKS5/HTTP CONNECT（`ClientForProxy`，`llm.go:180` 已用） |
| 6 | `database.go` | accounts 表增 provider/region 字段与 apiKey 存储 |

> 注：`docs/02 §5` 明确签名"仅当 host∈{bigmodel.cn,z.ai} 且带 `{id}.{secret}` apiKey 时启用"。海外是否真启用、握手路径/常量是否一致，**编码前务必先抓包验证**（§6）。

## 6. 待核实清单（需海外版 bundle 或抓包）

1. 海外 **LLM 真实主机与路径**：`api.z.ai/api/paas/v4` 还是 `autoglm-api.autoglm.ai`？是否仍有 autoclaw 专属加速代理路径？
2. 海外是否真启用 **Ed25519+PoW** 客户端签名？握手是否仍 `/api/paas/c1f3a7e2/v2/client`？常量是否随 1.18.5 变化（`SIGN_VERSION` 是否升到 1.18.5）？
3. 海外**登录流程**（email/OAuth？是否铸 JWT 还是纯 apiKey）。
4. 海外**模型路由**方式（`X-Request-Model` 头 vs body `model`）与模型 ID 映射（GLM-5.3-Flash 等对应的路由 ID）。
5. 海外是否仍有 `X-Harness-Type: zcode` 类准入头；`X-Lang`/`X-Channel`/`X-Product` 取值。
6. 海外风控类型与 TLS 指纹要求。

**取证方式**：(A) 下载海外安装包 `autoclaw-1.18.5-setup.exe`/`.dmg`（约 600MB，`autoglm-public-oss.z.ai/autoclaw/updates`），解包 `app.asar` 逆向 `getZaiProxyBaseUrl`/`getAutoClawClientSignTarget`/握手常量；(B) 运行海外版抓包（Fiddler/mitmproxy）观测真实 LLM 请求头与握手。

## 7. 附录：实时抓取记录（2026-09-15，内置浏览器 IAB）

| 目标 | 结果 |
|---|---|
| `autoclaw.z.ai/` | ✅加载，标题 "AutoClaw - Z.ai's Official AI Agent \| GLM-5.3-Flash Now Live"，Astro 静态站 |
| `_astro/BaseLayout…js` | ✅提取更新源/安装包命名规则/版本 1.18.5/`-cn` 后缀逻辑 |
| `_astro/pay-sign…js` | ✅提取支付 API `autoglm-api.autoglm.ai` + `X-Auth-Appid/TimeStamp/Sign` |
| `autoglm-public-oss.z.ai/.../latest.yml` `latest-mac.yml` | ✅CORS 可读，version 1.18.5，exe/dmg/zip + sha512 + 2026-09-11 |
| `autoclaw.z.ai/models/` | ✅模型清单 GLM-5.3-Flash/5.3/5.2/5-Turbo/5V-Turbo |
| 落地页 XHR | 仅分析埋点（`gator.uba.ap-southeast-1.volces.com`、GA、Bing、Clarity），无 LLM API |

> 早期 WebFetch/浏览器对 `autoclaw.z.ai` 超时系瞬时/加载慢；改用已打开标签页 + 轮询 `readyState` 后稳定抓取。
> `autoclaw.z.ai` 落地页**不含 LLM 协议**，真实 LLM 主机/签名仍需 §6 (A)/(B) 取证。
