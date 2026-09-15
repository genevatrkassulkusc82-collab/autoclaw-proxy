# AutoClaw LLM 接口协议总结

> 基于 AutoClaw 1.18.4（OpenClaw 2026.6.8 网关 + patchSetVersion 104 运行时补丁）静态逆向 + 真机实测。
> 实测时间：2026-09-15；实测环境：Windows，官方渠道（`official.json: {"channel":"official"}`），账号已登录。

## 1. 端点

| 项 | 值 |
|---|---|
| Base URL（生产） | `https://autoglm-acceleration-api.zhipuai.cn/autoclaw-proxy/proxy/autoclaw` |
| Base URL（预发） | `https://autoglm-pre-api.zhipuai.cn/autoclaw-proxy/proxy/autoclaw` |
| Base URL（开发） | `https://autoglm-inner-3.zhipuai.cn/autoclaw-proxy/proxy/autoclaw` |
| 对话补全 | `POST {base}/chat/completions` —— **标准 OpenAI Chat Completions** |
| Anthropic 路径 | `POST {base}/v1/messages` 可通（HTTP 200），但**返回的仍是 OpenAI chat.completion 格式**，代理不实现 Anthropic Messages 协议，仅做透传路由 |
| 模型列表 | `GET {base}/models` → 404，无此端点 |
| 用量遥测（客户端上报，非必需） | `POST https://autoglm-…/autoclaw-proxy/proxy/client-report/model` |

Base URL 由主进程 `getZaiProxyBaseUrl()` 决定，并被 `patchPiAiModelsBaseUrl` 补丁强制写入网关：
所有 `api.z.ai/api/paas/v4`、`open.bigmodel.cn/api/paas/v4`（含 `/api/coding/paas/v4`）上游地址
一律字符串替换为上述代理地址；启动时校验模型注册表，若仍指向上游 host 直接抛错拒绝启动。

## 2. 请求头

### 2.1 必带（缺一即 4xx/5xx）

| Header | 示例值 | 来源/说明 |
|---|---|---|
| `Content-Type` | `application/json` | — |
| `X-Authorization` | `Bearer eyJhbGciOiJIUzI1NiIs…` | **AutoClaw 账号 JWT**（注意：不是标准 `Authorization`）。明文存于 `~/.openclaw-autoclaw/openclaw.json` → `models.providers.zai.models[].headers` 及 `request-headers.json`；24h 有效，主进程自动刷新回写。结构见文档 02 §3 |
| `X-Harness-Type` | `zcode` | **必带**。缺失时代理返回误导性的 `500 {"message":"invalid request body"}`（实测 body 合法）。语义：豁免 api-proxy 的 system-prompt 白名单检查（主进程注释原文："Exempts zcode requests from api-proxy's system-prompt allowlist check"） |
| `X-Request-Model` | `zai_auto` | **路由键**，决定后端模型；优先级高于 body 的 `model`（实测）。取值为完整路由 ID（带前缀） |
| `X-Request-Id` | UUID v4 | 每请求生成（网关 `buildAutoClawRequestHeaders`：`headers["X-Request-Id"] ||= randomUUID()`） |

### 2.2 静态身份头（来自 openclaw.json 的 model.headers，实测全部照抄即可）

| Header | 实测值 | 说明 |
|---|---|---|
| `X-Product` | `autoclaw` | 产品标识（补丁 `autoclaw-third-party-product-header` 强制覆写） |
| `X-Client-Type` | `pc` | 客户端类型 |
| `X-Tm` | `win` | 平台标记（`getPlatformTm()`：win/darwin/…） |
| `X-Version` | `1.18.4` | 应用版本 |
| `X-Channel` | `official` | 发布渠道（official.json） |
| `X-Lang` | `zh-CN` | 语言 |

### 2.3 会话上下文头（网关动态注入，可选；直连测试未带也成功）

`X-Session-Id`、`X-Session-Key`、`X-Agent-Id`（由 sessionKey 派生）、`X-Agent-Team`、
`X-Is-Goal-Mode`、`X-Financial-Expert`、`X-Account-Expert`、`X-Auto-Legal`、`X-Auto-Design` 等
—— 对应补丁 `patchOpenAICompletionsSessionHeader` / `AgentTeamHeader` / `GoalModeHeader` / `FinancialDbHeader`。
代理用它们做业务侧统计/路由微调，非鉴权必需。

### 2.4 客户端签名头（本通道**不需要**）

`X-Client-Sig / X-Client-Ts / X-Client-Nonce / X-Client-Pow / X-Client-Id / X-Client-Version`。
网关 `getAutoClawClientSignTarget()` 明确排除 zai provider（`model.provider === "zai" → return null`），
即 JWT 账号通道不签名；签名仅用于 Coding Plan apiKey（`{id}.{secret}`）通道。算法详见文档 02 §5。

## 3. 模型路由

路由 ID（`X-Request-Model`）→ body `model`（去前缀规则 `replace(/^[a-z]+_/, "")`，即
`normalizeAutoClawRequestBodyModel` / `toModelProxyBodyModelId`）→ 实际后端（实测响应 `model` 字段）：

| 路由 ID | body model | 实测后端 | 备注 |
|---|---|---|---|
| `zai_auto` | `auto` | `deepseek-v4-flash-202605` | 默认主模型（`agents.defaults.model.primary = zai/zai_auto`），自动路由，带思考链（`reasoning_tokens`） |
| `zai_auto-fast` | `auto-fast` | （未测） | 快速档自动路由 |
| `zaicoding_glm-5.3` | `glm-5.3` | `glm-5.3` | Coding 档 |
| `zai_glm-5.3-flash` | `glm-5.3-flash` | `glm-5.3-flash` | 轻量档 |

模型清单由远端配置下发（`{proxy}/autoclaw-model-config`、`autoclaw-provider-config`），非硬编码；
上表为 2026-09-15 该账号的实际下发结果，随时间变化。

## 4. 请求体（标准 OpenAI Chat Completions）

网关 `buildParams()` 构造，实测代理接受的字段：

```jsonc
{
  "model": "auto",                  // 去前缀后的路由名；实际以 X-Request-Model 头为准
  "messages": [ {"role":"user","content":"…"} ],
  "stream": true,                   // 网关恒为 true；实测 false 也可（返回非流式 JSON）
  "stream_options": {"include_usage": true},
  "store": false,
  "max_tokens": 131072,             // 或 max_completion_tokens（按 compat.maxTokensField）
  "temperature": 0.7,               // 可选
  "stop": ["…"],                    // 可选
  "tools": [ {"type":"function","function":{"name":"…","description":"…","parameters":{…JSON Schema…}}} ],
  "prompt_cache_key": "…",          // 可选（仅 api.openai.com 或 compat 支持时）
  "thinking": {"type":"enabled"},   // 智谱扩展：仅 open.bigmodel.cn 的 glm-5.2 注入（applyBigModelGlm52…），代理通道可不带
  "tool_stream": true               // 智谱扩展：zai compat 且有 tools 时注入
}
```

工具调用实测正常：返回标准 `choices[0].message.tool_calls[]`（`id` 形如 `call_00_…`，`function.arguments` 为 JSON 字符串）。

## 5. 响应

### 5.1 非流式（`stream:false`）

标准 `chat.completion` 对象，**扩展了 `reasoning_content` 字段**（思考链，DeepSeek 风格）：

```jsonc
{
  "id": "a15fa0ba-…",               // UUID，非 OpenAI 的 chatcmpl- 前缀
  "object": "chat.completion",
  "model": "deepseek-v4-flash-202605",
  "created": 1789442321,
  "choices": [{
    "index": 0,
    "message": {"role":"assistant","content":"…","reasoning_content":"…"},
    "finish_reason": "stop"
  }],
  "usage": {"prompt_tokens":40,"completion_tokens":3188,"total_tokens":3228,
            "prompt_tokens_details":{"cached_tokens":0},
            "completion_tokens_details":{"reasoning_tokens":3156}}
}
```

### 5.2 流式（`stream:true`）

标准 SSE：`data: {chunk}\n\n` … `data: [DONE]\n\n`。chunk 为 `chat.completion.chunk`，
`delta.content` / `delta.reasoning_content` 增量；`stream_options.include_usage` 时末段带 `usage`。
实测：3189 chunks，TTFT 1.89s。

## 6. 错误语义（实测 + 补丁代码）

| 现象 | 含义 |
|---|---|
| `500 {"message":"invalid request body"}`（<0.5s 即拒） | **大概率是缺 `X-Harness-Type` 头**，而非 body 问题（实测教训） |
| `401` + body 含 `VERIFY_*` 枚举（如 `VERIFY_SIGNATURE_INVALID`、`VERIFY_APIKEY_EXPIRED`） | 客户端签名验签失败（仅签名通道）。网关自愈策略：rekey 类→重握手重签重试一次；hard 类（PoW 难度/时间窗/协议错）→停签降级；未知码→计数超阈值才停签 |
| `401`（zai 通道） | JWT 过期。网关行为（`patchOpenAICompletionsZai401Retry`）：等待主进程刷新 `request-headers.json` 中的 `X-Authorization`，拿到新值后重放请求一次 |

## 7. 最小复现（Python，实测通过）

```python
import json, uuid, urllib.request

cfg = json.load(open(r"C:/Users/<用户>/.openclaw-autoclaw/openclaw.json", encoding="utf-8"))
zai = cfg["models"]["providers"]["zai"]
route = next(m for m in zai["models"] if m["id"] == "zai_auto")

headers = dict(route["headers"])          # X-Authorization / X-Request-Model / X-Tm / X-Version / X-Product / X-Channel / X-Lang / X-Client-Type
headers.update({
    "Content-Type": "application/json",
    "X-Request-Id": str(uuid.uuid4()),
    "X-Harness-Type": "zcode",            # 必带！
})
body = {"model": "auto", "messages": [{"role": "user", "content": "你好"}], "stream": False}

req = urllib.request.Request(
    zai["baseUrl"].rstrip("/") + "/chat/completions",
    data=json.dumps(body).encode(), headers=headers, method="POST")
print(json.loads(urllib.request.urlopen(req, timeout=120).read())["choices"][0]["message"]["content"])
```

curl 等价形式：

```bash
curl -sS https://autoglm-acceleration-api.zhipuai.cn/autoclaw-proxy/proxy/autoclaw/chat/completions \
  -H "Content-Type: application/json" \
  -H "X-Authorization: Bearer $JWT" \
  -H "X-Harness-Type: zcode" \
  -H "X-Request-Model: zai_auto" \
  -H "X-Request-Id: $(uuidgen)" \
  -H "X-Product: autoclaw" -H "X-Client-Type: pc" -H "X-Tm: win" \
  -H "X-Version: 1.18.4" -H "X-Channel: official" -H "X-Lang: zh-CN" \
  -d '{"model":"auto","messages":[{"role":"user","content":"你好"}],"stream":false}'
```

## 8. 实测记录（2026-09-15）

| # | 用例 | 结果 |
|---|---|---|
| A | `model=auto`，无 `X-Harness-Type` | 500 `invalid request body`（0.1s） |
| B | `model=zai_auto`，无 `X-Harness-Type` | 500（同上，证明与 body model 无关） |
| C | `model=auto` + `X-Harness-Type: zcode` | **200**，1.2s，`deepseek-v4-flash-202605` |
| 1 | zai_auto 中文问答（非流式） | 200，3.3s，414 tok，内容正常 |
| 2 | zai_auto 流式 SSE | 200，3189 chunks，TTFT 1.89s，`reasoning_tokens=3156` |
| 3 | zai_glm-5.3-flash | 200，4.5s，`glm-5.3-flash`，自称 Z.ai GLM |
| 4 | zaicoding_glm-5.3 | 200，9.2s，`glm-5.3` |
| 5 | tools 函数调用（get_weather） | 200，1.3s，标准 `tool_calls`，参数 `{"city":"北京"}` |
| 6 | `POST /v1/messages`（anthropic-version 头） | 200 但返回 OpenAI `chat.completion` 格式；且 body model 被 `X-Request-Model: zai_auto` 头覆盖 → **头优先路由** |
| 7 | `GET /models` | 404 |

## 9. 协议定性

- **线格式：标准 OpenAI Chat Completions**（openai SDK `client.chat.completions.create()` 直连可用），
  SSE 事件、usage、tools/tool_calls 均符合 OpenAI 规范。
- **非标准部分**：鉴权用私有 `X-Authorization`（非 `Authorization`）；路由靠私有 `X-Request-Model` 头；
  `X-Harness-Type` 准入头；响应扩展 `reasoning_content`；`thinking`/`tool_stream` 为智谱 body 扩展（本通道可选）。
- 结论：**"标准 OpenAI wire format + 智谱私有头体系"**。任何 OpenAI 兼容客户端只要支持自定义
  default headers（openai SDK、LiteLLM、one-api 等均可）就能接入。
