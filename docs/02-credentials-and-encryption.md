# AutoClaw 凭证与加密机制

> 基于 AutoClaw 1.18.4 静态逆向 + 本机实测（2026-09-15，Windows，账号已登录）。
> 本文只描述机制与验证过的事实，不包含任何真实密钥/令牌明文。

## 1. 凭证文件总览

| 文件 | 内容 | 保护方式 |
|---|---|---|
| `%APPDATA%\AutoClaw\auth.json`（本机实际在 `D:\Users\Admin\AppData\Roaming\AutoClaw\`） | `token` / `refreshToken`（长效登录态，明文含 `Bearer ` 前缀）、`deviceId`、`userInfo`（user_id、手机号等） | token 为 **`enc:v10` AES-256-GCM 加密**（Electron safeStorage，密钥在 `Local State`，受 DPAPI 保护，见 §2）；deviceId、userInfo 明文；另有 `auth.json.backup`（每次读取自动生成） |
| `%APPDATA%\AutoClaw\token-cache.json` | token/refreshToken 缓存副本（`setTokenCache`，同样 `enc:v10`）；**应用有内存缓存，运行中外部写回不生效** | 同 auth.json |
| `%APPDATA%\AutoClaw\identity\device.json` | 设备身份：`deviceId`（64 hex）+ **Ed25519 设备密钥对**（PEM 明文） | 无加密 |
| `~/.openclaw-autoclaw/openclaw.json` | 网关配置。`models.providers.zai.models[].headers` 内含 **明文 `X-Authorization: Bearer <JWT>`**（每个模型条目一份，同值） | **无加密（明文 JWT）** |
| `~/.openclaw-autoclaw/request-headers.json` | 动态请求头：`{"headers":{"X-Authorization":"Bearer <JWT>","X-Client-Type":"pc"}}` | **无加密（明文 JWT）**；主进程刷新 token 后回写此文件 |
| `~/.openclaw-autoclaw/.gateway-token` | 本地网关 RPC 令牌（64 hex） | 无加密，仅限本机进程间通信 |
| `~/.openclaw-autoclaw/client-sign.json` | `{"enabled": true}` —— 客户端签名总开关 | — |
| `~/.zcode/v2/credentials.json`（ZCode CLI，非 AutoClaw 本体） | `zcodejwttoken`、`oauth:*:access_token` 等 | `enc:v1:` AES-256-GCM，密钥派生 `SHA-256("zcode-credential-fallback:{platform}:{home}:{user}")` —— 与 AutoClaw 的 DPAPI 方案**不同** |

要点：**日常 LLM 调用真正用到的 JWT 是明文落盘的**（openclaw.json + request-headers.json），
DPAPI 只保护 auth.json 里的长效 token/refreshToken。任何以同一 Windows 用户身份运行的进程
都可以直接读取 JWT 调用 LLM 接口（本项目实测已验证）。

## 2. `enc:v10` —— Electron safeStorage（Chrome 风格 AES-256-GCM，**非裸 DPAPI**）

> ⚠️ 实测修正（2026-09-15）：v10 载荷对裸 `CryptUnprotectData` 报"数据无效"。
> 真实方案与 Chrome Cookies 相同：**AES-256-GCM**，AES 密钥存放于
> `%APPDATA%\AutoClaw\Local State` → `os_crypt.encrypted_key`（base64，前 5 字节魔数
> `DPAPI`，剥掉后才是 DPAPI(CurrentUser) 保护的 32 字节密钥）。

字段格式：`enc:` + Base64( `"v10"`(3B) + nonce(12B) + ciphertext + tag(16B，末尾) )，
明文值自带 `Bearer ` 前缀。解密两步：

```powershell
# ① 取 AES key（这一步才是 DPAPI）
$ls = Get-Content "$env:APPDATA\AutoClaw\Local State" -Raw | ConvertFrom-Json
$ek = [Convert]::FromBase64String($ls.os_crypt.encrypted_key)
Add-Type -AssemblyName System.Security
$key = [System.Security.Cryptography.ProtectedData]::Unprotect(
    [byte[]]$ek[5..($ek.Length-1)], $null, 'CurrentUser')   # 32 字节
```

```js
// ② AES-256-GCM 解字段（Node，实测通过，见 scripts/verify-v10.js）
function decrypt(enc, key) {
  const raw = Buffer.from(enc.slice(4), 'base64');           // 去 "enc:"
  const d = crypto.createDecipheriv('aes-256-gcm', key, raw.subarray(3, 15)); // 去 "v10"，nonce 12B
  d.setAuthTag(raw.subarray(raw.length - 16));               // 末 16B = tag
  return Buffer.concat([d.update(raw.subarray(15, raw.length - 16)), d.final()]).toString('utf8');
}
```

- 绑定 Windows 用户账户（DPAPI 层）：同机同用户可解，异机/异用户不可解。
- 明文旁路：环境变量 `AUTOCLAW_DEV_PLAINTEXT_AUTH=1`（或 `AUTOCLAW_E2E=1`）时官方代码直接存/读明文。
- `auth.json.backup` 由 `readJson$3` 在每次**读取**时自动生成（copyFileSync），非写入备份。
- 重加密写回（自持刷新的"恢复 json"）与完整文件同步清单见
  [03-token-refresh-and-device-identity.md](03-token-refresh-and-device-identity.md) §2–§3。

## 3. 账号 JWT 结构（实测解码，敏感值已脱敏）

```
header : {"alg":"HS256","typ":"JWT"}
payload: {
  "user_id"  : 1000001,              // 与 auth.json userInfo.id 一致
  "device_id": "f655…(64 hex)",     // 与 identity/device.json deviceId 一致
  "source_id": "agen…(17)",         // 渠道标识
  "guid"     : "",
  "is_guest" : false,
  "power"    : 0,
  "iat"      : 1789441312,           // 签发 = 登录时刻
  "exp"      : 1789527712,           // 有效期 24h
  "jti"      : "1736…"
}
```

- **有效期 24 小时**；到期前由主进程用 refreshToken 刷新，并回写
  `request-headers.json` 与 `openclaw.json` 的全部 `X-Authorization`。
- 网关侧配套补丁 `patchOpenAICompletionsZai401Retry`：收到 401 时轮询等待
  `request-headers.json` 出现新的 `X-Authorization`（与旧值不同），替换后重放一次请求。
  —— 自建代理应复刻此语义：**401 → 重读 request-headers.json → 重试**，而非自行刷新。

## 4. 设备身份

- `deviceId`：64 hex，登录时注册，写入 JWT `device_id` claim（服务端可做设备绑定风控）。
- `identity/device.json` 的 Ed25519 密钥对：应用级设备密钥（PEM 明文），用于设备认证/网关
  device-auth（`importGatewayAuthFromOpenclaw` 会读取 `identity/device-auth.json`、`device.json`）。
- JWT 请求时设备指纹通过 header 透传（`X-Tm: win` 等静态头 + deviceId 在 token 内）。

## 5. Ed25519 客户端签名体系（Coding Plan key 通道；zai JWT 通道**不启用**）

网关 `getAutoClawClientSignTarget()` 判定：`model.provider === "zai"` 直接跳过签名；
仅当 baseUrl host ∈ {`bigmodel.cn`, `z.ai`}（含子域）且请求带 `{id}.{secret}` 形态 apiKey
（读自 `Authorization`/`x-api-key`）时启用。对应补丁 `patchOpenAICompletionsClientSign` /
`patchAnthropicClientSign`（OpenAI 与 Anthropic 两条传输都注入了同一套实现）。

### 5.1 常量（实测提取）

```
KDF_SALT        = "WD_CLIENT_SIGN_KDF_SALT"        // HKDF-SHA256 salt
INFO_HANDSHAKE  = "getSignKey_hmac"                // 握手 HMAC key 的 HKDF info
INFO_PRIV       = "ed25519_priv"                   // 私钥解封 KEK 的 HKDF info
APP_ID          = "autoclaw"
SIGN_VERSION    = "1.18.1"                         // X-Client-Version
POW_BITS        = 8                                // PoW 难度：SHA-256 前导 8 个零 bit
POW_MAX_ITER    = 5,000,000
KEY_TTL         = 6h                               // 签名私钥缓存时长
HANDSHAKE_PATH  = /api/paas/c1f3a7e2/v2/client     // 拼在模型 baseUrl 的 origin 后
```

### 5.2 握手（取签名私钥）

```
reqKek = HKDF-SHA256(secret, salt=KDF_SALT, info=INFO_HANDSHAKE, 32B)
message = "get_sign_key\n" + id + "\n" + ts + "\n" + nonce        // nonce = 16 字节随机 hex
sig     = HMAC-SHA256(reqKek, message) → base64

POST {origin}/api/paas/c1f3a7e2/v2/client        (超时 10s)
  Authorization: Bearer {id}.{secret}
  body: {"apiKey":"{id}.{secret}", "ts":…, "nonce":…, "sig":…}
  → {"code":200, "data":{"privateCipher":"<base64>"}}

kek        = HKDF-SHA256(secret, salt=KDF_SALT, info=INFO_PRIV, 32B)
blob       = base64decode(privateCipher)          // [0:12]=IV, [12:-16]=密文, [-16:]=tag
私钥PKCS8   = AES-256-GCM-Decrypt(kek, IV, 密文, tag, AAD=id)
Ed25519PrivateKey = createPrivateKey(PKCS8 DER)   // 缓存 6h，失败冷却 10min
```

### 5.3 每请求签名 + PoW

```
sessionId = 取会话 ID（读自请求头/上下文）
message   = id + "\n" + ts + "\n" + SIGN_VERSION + "\n" + sessionId + "\n" + nonce
X-Client-Sig    = base64( Ed25519Sign(私钥, message) )
X-Client-Id     = id
X-Client-Ts     = ts
X-Client-Version= "1.18.1"
X-Client-Nonce  = nonce
X-Session-Id    = sessionId

challenge = SHA256(id + "\n" + APP_ID + "\n" + sessionId + "\n" + ts).hex[:32]
遍历 candidate=0…：SHA256(challenge + "\n" + candidate) 前导零 bit ≥ 8 → X-Client-Pow = candidate
（平均 256 次哈希，实测 <1ms；注释注明出自智谱"接入文档 §5.2"）
```

### 5.4 验签失败自愈（401 + body 含 `VERIFY_*`）

| 分类 | 错误码 | 动作 |
|---|---|---|
| rekey | `VERIFY_SIGNATURE_INVALID`、`VERIFY_APIKEY_EXPIRED` | 失效私钥缓存 → 重握手 → 重签，重试一次 |
| hard | `VERIFY_POW_REQUIRED/INVALID`、`VERIFY_TS_OUT_OF_WINDOW`、`VERIFY_MISSING_FIELD`、`VERIFY_INVALID_FORMAT`、`VERIFY_PROTOCOL_ERROR`、`VERIFY_APIKEY_DISABLED` | 立即停签 30min（请求继续但不带签名），到期自动恢复 |
| 未知码 | 其余 `VERIFY_*` | 仅计数，10min 窗口内连续 ≥2 次才停签 |

## 6. 令牌链路总览

```
手机号登录 (autoglm-api.zhipuai.cn /userapi)
   └→ auth.json: token/refreshToken = enc:v10 DPAPI 密文 (长效)
        └→ 主进程解密 → 铸 24h HS256 JWT
             ├→ ~/.openclaw-autoclaw/openclaw.json      models.providers.zai.models[].headers.X-Authorization (明文)
             ├→ ~/.openclaw-autoclaw/request-headers.json headers.X-Authorization (明文, 刷新回写点)
             └→ 网关请求时: buildAutoClawRequestHeaders 合并静态头 + X-Request-Id/X-Session-Id 等动态头
                  └→ 401 → 等待 request-headers.json 更新 → 重放 (AutoClawZai401Retry)
```

## 7. 安全评估（对自建代理的启示）

1. **明文 JWT 是既定事实**：openclaw.json / request-headers.json 无保护，同用户进程可直接复用
   —— 本项目代理据此实现零侵入取票（只读文件，不碰 DPAPI）。
2. **JWT 仅 24h**：代理必须监听 `request-headers.json` 变更（fs.watch 或轮询 mtime）热加载，
   并在 401 时等待刷新重试，而不是缓存 token 到天荒地老。
3. **AutoClaw 必须保持登录运行**（或由代理自行持 refreshToken 走 DPAPI 解密 + 刷新接口续期，
   复杂度高，暂不实现）。
4. **设备绑定风控**：JWT 含 device_id，直连请求与官方客户端同机同 IP，风控面一致；
   不要把 JWT 导出到其他机器使用（可能触发设备异常风控）。
5. `X-Harness-Type: zcode` 豁免 system-prompt 白名单——自建代理应保持该头，否则复杂
   system prompt 可能被 api-proxy 拒绝（表现为 500 invalid request body）。
6. 遥测：官方客户端会向 `/autoclaw-proxy/proxy/client-report/model` 上报请求摘要
   （messages/tools 概要、耗时、错误）。直连调用不强制上报；是否模拟上报由实现阶段决策。
