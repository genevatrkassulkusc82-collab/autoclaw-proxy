# autoclaw-proxy

复用 [AutoClaw](https://autoglm.aminer.cn/)（智谱桌面 Agent 应用）登录态的 **多账号 OpenAI 兼容 LLM 网关**。Go 单二进制，无 CGO、无外部运行时依赖。

> **状态：已实现并实测通过。** 协议逆向 + 真机验证见 [`docs/`](docs/)；全链路（本地导入 → 模型同步 → 流式/非流式对话 → 用量落库）已在生产端点跑通。
>
> **合规声明**：本项目仅用于**个人学习研究**与**管理本人自有账号**，请遵守上游服务条款与相关法律法规；不得用于批量注册、配额滥用或任何欺诈行为。逆向结论仅供 interoperability 研究。

---

## 特性

| 模块 | 说明 | 状态 |
|---|---|---|
| OpenAI 兼容网关 | `POST /v1/chat/completions`（SSE 流式透传 + 非流式）、`GET /v1/models`；标准 `tool_calls` / `usage` / `reasoning_content` | ✅ 实测 |
| 双认证体系 | 后台 = 账号密码 + session cookie（bcrypt、DB 持久化、失败限流）；LLM = 独立 `sk-` Key（sha256 存储、启停/配额/过期/用量）。**Key 仅 LLM，不通管理面** | ✅ 实测 |
| 多账号池 | round_robin / random / least_used；429/5xx 冷却退避自动换号；401 → 自持 rt 刷新重试；账号级互斥 | ✅ |
| 自持 rt 刷新 at | `/userapi/v1/refresh`（MD5 签名）+ 400002 降级 `agent-refresh`；rt 轮换即持久化 | ✅ 协议已验证 |
| 模型同步 | 上游 `autoclaw-model-config` 同步（`?sync=1` 强制）；路由 ID + 短名双暴露；内置兜底目录 | ✅ 实测 |
| 本地账号导入 | 解密 `%APPDATA%\AutoClaw\auth.json` 的 `enc:v10`（DPAPI → AES-256-GCM）+ 真实设备身份，一键入库 | ✅ 实测（推荐） |
| 本机设备身份重置 | 重新生成官方 AutoClaw 的 `identity/device.json`（Ed25519+deviceId），并**清除全部登录态**（`auth.json*` + Chromium `Network`/`Local Storage`/`Session Storage`/`WebStorage`），自动备份/可恢复；使官方客户端以**新设备+未登录**弹登录页供手动登录；用于设备级风控拉黑后换设备 | ✅ |
| 验证码登录 | 管理 UI 填手机号 → 真实 Chrome 浏览器桥发码/登录 → 入库 | ⚠️ 见[登录限制](#账号获取与登录限制) |
| 设备身份 | Ed25519 密钥对；`deviceId = SHA-256(公钥原始32字节)hex`，与官方算法逐位一致 | ✅ 实测 |
| TLS 指纹 | utls：Chrome/Firefox/Safari/Edge/随机化等预置 + 自定义 JA3；utls-over-HTTP/2 | ✅ |
| 浏览器桥 | go-rod 驱动本机真实 Chrome/Edge（headless），页面内 `fetch` 借用真实 TLS/HTTP2/TCP/cookie 指纹；stealth 注入；阿里云无痕验证码求解框架 | ✅ |
| 出口代理 | SOCKS5 / HTTP CONNECT；按账号分组绑定；登录桥独立 `login_proxy`；出口 IP 测试 / 本机代理探测 | ✅ |
| 管理面板 | 嵌入式 Web UI（浅色卡片 + pill 导航）：仪表盘/账号/登录/测试/密钥/模型/代理/设置/日志 | ✅ 实测 |
| 用量观测 | 每次调用落库：账号/路由/状态/入出 tokens/TTFT/耗时/错误 | ✅ 实测 |

## 架构

```
                 ┌─────────────────────────── autoclaw-proxy (Go) ───────────────────────────┐
 OpenAI 客户端   │  /v1/chat/completions ─► 账号池(轮换/冷却/401刷新) ─► 上游转发(utls/代理)      │
  (sk- Key) ───►│  /v1/models           ─► 模型目录(上游同步)                              │
                │                                                                            │
 管理浏览器     │  /admin/* (session) ─► 账号/密钥/代理/设置  ─► SQLite(data/, gitignored)    │
  (账号密码) ──►│                   └─► 登录桥(go-rod 真实 Chrome fetch) ─                  │
                │  本地导入 ─► 解密 %APPDATA%\AutoClaw\auth.json (enc:v10) │                  │
                └───────────────────────────────────────────────────────┼──────────────────┘
                                                                        ▼
                                          https://autoglm-acceleration-api.zhipuai.cn
                                              /autoclaw-proxy/proxy/autoclaw   (OpenAI Chat Completions)
                                              /userapi/v1/{agent-send-code,agent-login,refresh}
```

## 快速开始

```bash
# 构建（Windows / Linux / macOS，Go ≥1.25）
go build -o autoclaw-proxy.exe .

# 启动（-import-local 自动导入本机 AutoClaw 登录态）
./autoclaw-proxy.exe -listen 127.0.0.1:8317 -data ./data -import-local
./autoclaw-proxy.exe -show-key        # 打印初始 LLM API Key
```

- 管理面板：`http://127.0.0.1:8317/`，默认 `admin / admin123`（**首次登录请立即改密**）。
- LLM 接入：面板「API 密钥」新建 `sk-` Key（仅可调用 `/v1/*`）。

```bash
curl http://127.0.0.1:8317/v1/chat/completions \
  -H "Authorization: Bearer sk-…" -H "Content-Type: application/json" \
  -d '{"model":"auto","messages":[{"role":"user","content":"你好"}],"stream":true}'
```

```python
from openai import OpenAI
client = OpenAI(base_url="http://127.0.0.1:8317/v1", api_key="sk-…")
print(client.chat.completions.create(
    model="glm-5.3-flash",
    messages=[{"role": "user", "content": "你好"}]).choices[0].message.content)
```

## 配置参考（设置页 / SQLite settings）

| 键 | 说明 |
|---|---|
| `upstream_host` | 上游主机（默认生产加速域名） |
| `upstream_proxy` | 全局出口代理（socks5/http，兜底） |
| `login_proxy` | **登录桥**专用出口代理（换干净 IP 规避 IP 级风控黑名单） |
| `pool_strategy` | 账号池策略：round_robin / random / least_used |
| `tls_mode` / `tls_ja3` | utls 指纹预置 / 自定义 JA3 |
| `captcha_*` | 阿里云无痕验证码兜底配置（CN 短信通道当前无需） |
| `listen_addr` | 监听地址（重启生效） |

## 账号获取与登录限制

| 路径 | 说明 | 可靠性 |
|---|---|---|
| **导入本机登录态（推荐）** | 官方 AutoClaw 登录目标账号 → 面板「导入本机登录态」解密入库；切换账号重复导入即多账号 | ✅ 已验证 |
| 验证码登录（补充） | 面板填手机号 → 真实 Chrome 桥发码/登录 | ❌ 发码稳定；**login 被上游风控拒绝（400001）** |

> **登录 400001 定性**（逐项对照实验）：与验证码时效、设备注册、cookie(`acw_tc`)、UA、请求体、Go 原生 TLS、utls Chrome+HTTP/2 均无关；真实 Chrome 桥干净单发仍拒。
> 结合"官方客户端早期可登录、本机连打十余次失败后全拒、同 IP 新号也拒"，最可能为**反复失败+高频发码触发的 IP/设备级风控黑名单**。
> 应对（不 spoof 风险 SDK）：设置 `login_proxy` 换干净出口 IP → 停止高频触发、冷却后**单次**干净尝试；或直接用官方登录+导入（最稳）。
>
> **设备级拉黑自救**：面板「🔄 重置本机设备身份」（自动备份、要求官方客户端已退出）→ 打开官方 AutoClaw 手动登录（以新设备绑定，官方风控正常执行）→ 回本网关「导入本机登录态」。可用「♻️ 恢复设备备份」撤销。

## 客户端远程导入（autoclaw-client）

参考 dumate-proxy 的 login-client 配对码机制。当网关部署在**无 AutoClaw 的服务器**上时，由用户在自有 Windows 电脑运行客户端回传账号：

```bash
# 构建客户端（单二进制，无 CGO）
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o clients/autoclaw-client-windows-amd64.exe ./cmd/autoclaw-client

# 模式一：本地导入（本机 AutoClaw 已登录）——解密 auth.json(enc:v10) + 设备身份回传
autoclaw-client-windows-amd64.exe -server http://<服务器>:8317 -code <配对码> -mode import

# 模式二：重置设备 + 等手动登录（设备级拉黑自救）——重置本机设备身份/清登录态，
#          轮询到官方 AutoClaw 新登录态后解密回传；-loop 连续多账号
autoclaw-client-windows-amd64.exe -server http://<服务器>:8317 -code <配对码> -mode reset -loop
```

- 配对码：管理面「🖥 客户端配对码」生成，10 分钟有效；`POST /client/hello` 握手、`POST /client/push` 回传（均以配对码鉴权）。
- 客户端自包含 enc:v10 解密（DPAPI→AES-256-GCM）与设备身份生成，不依赖网关代码。
- "某些情况下用客户端本地导入"：本机已有登录态时直接 `import`；被设备拉黑时 `reset` 后手动登录再回传。

## API 参考

| 端点 | 鉴权 | 说明 |
|---|---|---|
| `POST /v1/chat/completions` | LLM Key | OpenAI Chat Completions（流式/非流式） |
| `GET /v1/models` | LLM Key | 模型目录（`?sync=1` 强制上游同步） |
| `POST /admin/login` / `logout` / `me` / `password` | 公开/会话 | 后台会话与改密 |
| `GET/POST /admin/accounts…`、`keys`、`proxies`、`models`、`usage`、`settings`、`test/chat` | 会话 | 管理面 |

## 项目结构

```
autoclaw-proxy/
├── main.go              启动/路由/静态资源/no-cache
├── auth.go              双认证（session + API Key，bcrypt/sha256/限流）
├── account.go           账号池/状态机/验证码登录流程/设备身份开关
├── import_local.go      本地 auth.json(enc:v10) 解密导入 + 真实设备身份加载
├── crypto.go            Ed25519 设备身份 / enc:v10(DPAPI+AES-GCM) / JWT 解析
├── userapi.go           上游 userapi 客户端（MD5 签名/登录/刷新/模型/浏览器桥接入）
├── transport.go         utls 指纹 / utls-over-HTTP2 / 标准客户端 / 代理隧道 / cookie jar
├── browser.go           go-rod 浏览器桥(fetch) + stealth + 验证码求解框架
├── llm.go               上游 LLM 转发（路由/401刷新/429冷却/用量）
├── handlers_openai.go   /v1/* OpenAI 兼容层
├── handlers_admin.go    /admin/* 管理面 + 密钥/代理/设置
├── database.go          SQLite schema（accounts/api_keys/sessions/proxy_nodes/usage_logs）
├── web/                 嵌入式管理 UI（index.html + static/app.js + static/style.css）
├── scripts/verify-v10.js  enc:v10 凭证方案验证脚本
└── docs/                协议/凭证/刷新 逆向文档与实测记录
```

## 实测结论速览

| # | 测试 | 结果 |
|---|------|------|
| 1 | `zai_auto` 非流式 / 流式 | 200；流式 SSE 透传含 `reasoning_content`，TTFT ~1.1–1.9s |
| 2 | `zai_glm-5.3-flash` / `zaicoding_glm-5.3` | 200，分别返回 `glm-5.3-flash` / `glm-5.3` |
| 3 | tools / function calling | 200，标准 `tool_calls` |
| 4 | `/v1/messages`（Anthropic 路径） | 200 但返回 **OpenAI 格式**（上游不实现 Anthropic） |
| 5 | 双认证隔离 | Key 访问管理面 401；会话访问 `/v1` 401；改密/启停/删除/用量闭环正确 |

关键发现：

- **`X-Harness-Type: zcode` 必带**，缺失返回误导性 `500 invalid request body`。
- **路由由 `X-Request-Model` 头决定**，优先于 body `model`；body `model` 需去前缀（`zai_auto`→`auto`）。
- 登录态 JWT 明文存于 `~/.openclaw-autoclaw/openclaw.json` 与 `request-headers.json`（24h，主进程自动回写）；长效凭证在 `%APPDATA%\AutoClaw\auth.json` 为 `enc:v10`（DPAPI→AES-256-GCM）。

## 上游错误屏蔽（参考 dumate-proxy）

上游 4xx/5xx/网络异常的**原文与内部细节只进服务端日志**，客户端只收到规范化通用错误（OpenAI 错误体）：

| 上游情况 | 客户端收到 | 服务端日志 |
|---|---|---|
| 传输层错误（拨号/超时/DNS） | `503 upstream temporarily unreachable` | 完整拨号/地址/错误原文 |
| 401/403 | `503 upstream authentication failed` | 上游状态+错误体+reqID |
| 429 | `429 upstream rate limited or quota exhausted` | 同上 |
| 5xx | `502 upstream server error (N)` | 同上 |
| 其它 4xx | `502 upstream request failed (N)` | 同上 |
| 流式中途 error 事件 | 不转发该 chunk（截断流） | error 原文 |
| 无可用账号 | `503 no available account` | 池状态 |

- 上游错误体中的 `requestId/logId/trace` 提取为 reqID，仅用于日志关联与客户端提示后缀，不泄漏上游地址/错误体。
- 已实测：坏 host → 客户端 `upstream temporarily unreachable`，服务端日志保留 `dial tcp …` 全文。

## 安全与共存须知

1. **rt 竞争**：导入账号与官方客户端共享同一 rt（轮换单次有效）。官方运行期间网关只读消费；主动刷新建议在官方关闭时执行。彻底隔离用独立设备身份账号。
2. **凭据隔离**：后台密码 bcrypt 落库；LLM Key 只存 sha256+前缀，明文仅创建时显示一次；Key 无管理面权限。
3. **本地敏感数据**：`data/`（SQLite 含 token）、`.secrets-backup/` 均已 gitignore，不会入库/上传；日志与 API 响应脱敏。

## 文档目录

| 文档 | 内容 |
|------|------|
| [docs/01-llm-api.md](docs/01-llm-api.md) | LLM 接口协议：端点/请求头/请求体/响应/流式/模型路由/错误语义/最小复现 |
| [docs/02-credentials-and-encryption.md](docs/02-credentials-and-encryption.md) | 凭证与加密：文件清单、enc:v10 解密配方、JWT 结构、Ed25519+PoW 签名、刷新链路 |
| [docs/03-token-refresh-and-device-identity.md](docs/03-token-refresh-and-device-identity.md) | 自持 rt 刷新 at、4 文件写回规范、设备身份生成、完整时序 |

## 证据来源

- `AutoClaw/resources/gateway/openclaw/`（OpenClaw 2026.6.8，MIT；补丁后 `dist/openai-completions-*.js`、`.runtime-patch.json`）
- `AutoClaw/resources/app.asar` → `/out/main/index.js`（Model Broker、`buildModelProxyUpstreamHeaders`、`patchPiAiModelsBaseUrl`、客户端签名）
- `~/.openclaw-autoclaw/`、`%APPDATA%\AutoClaw\`（运行时状态与凭证文件）

## License

仅供个人学习研究。逆向与互操作结论见 docs/；请尊重上游版权与服务条款。
