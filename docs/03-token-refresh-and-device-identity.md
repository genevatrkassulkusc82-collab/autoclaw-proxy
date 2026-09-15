# 自持 RefreshToken 刷新 AccessToken：协议、凭证读写与设备身份

> 基于 AutoClaw 1.18.4 主进程逆向 + 生产端点非破坏性实测（2026-09-15）。
> 实测原则：未消费真实 refreshToken（用假 rt 探测签名协议），未改写任何凭证文件。
> 配套验证脚本：[scripts/verify-v10.js](../scripts/verify-v10.js)（解密/对比/回环/设备指纹，实测通过）。

## 1. 刷新协议（rt → at）

### 1.1 端点与主机

| 环境 | Host | 说明 |
|---|---|---|
| 生产（默认） | `https://autoglm-acceleration-api.zhipuai.cn` | `getApiRequestHost()` 默认走加速域名，可用环境变量 `AUTOCLAW_USERAPI_PROD_HOST` 覆盖 |
| 生产（备） | `https://autoglm-api.zhipuai.cn` | `USERAPI_PROD_HOST`（会话标题等服务使用） |
| 预发 | `https://autoglm-pre-api.zhipuai.cn` | |
| 刷新 | `POST {host}/userapi/v1/refresh` | 主端点 |
| 刷新降级 | `POST {host}/userapi/v1/agent-refresh` | 仅当主端点返回 `code=400002`（签名校验失败）时尝试；成功后 token 的 `source_id` claim 变为 agent 系 |
| 登录（参考） | `POST {host}/userapi/v1/agent-login/`（验证码登录）、`/userapi/v1/agent-send-code` | body 同样经 `withWebInfo` 包装 |
| 用户信息（参考） | `POST {host}/userapi/v1/user-profile` | 可带 `authorization` 单独指定 at |

### 1.2 请求头（`commonHeaders()` = `authHeaders()` + 登录态）

```
Content-Type:     application/json
Accept:           */*
X-Version:        1.18.4                      # app.getVersion()
X-Tm:             win                         # 平台: win/darwin/linux
X-Product:        autoclaw
X-Auth-Appid:     100003                      # APP_ID（硬编码）
X-Auth-TimeStamp: <unix 秒>
X-Auth-Sign:      md5hex("100003&<unix秒>&38d2391985e2369a5fb8227d8e6cd5e5")   # APP_ID&ts&APP_KEY
X-Trace-Id:       <uuid v4>
X-Lang:           zh-CN
X-Channel:        official                    # official.json 渠道
authorization:    Bearer <当前 at>             # 可选（有则带；commonHeaders 逻辑）
```

签名算法就这一行（`authHeaders()` 原样）：

```js
sign = crypto.createHash("md5").update(`${APP_ID}&${timestamp}&${APP_KEY}`).digest("hex")
// APP_ID = "100003"  APP_KEY = "38d2391985e2369a5fb8227d8e6cd5e5"（bundle 内硬编码）
// timestamp = Math.floor(Date.now()/1000) 字符串
```

### 1.3 请求体（`withWebInfo` 包装）

```json
{
  "source_id": "autoclaw",
  "device_id": "<64hex，取 auth.json 的 deviceId（= JWT device_id claim）>",
  "refresh_token": "<rt JWT，不含 Bearer 前缀也可（tokenPrefix 会补）>"
}
```

### 1.4 响应与错误码

```jsonc
// 成功
{ "code": 0, "data": { "access_token": "<新 at JWT>", "refresh_token": "<新 rt JWT>" }, "time": …, "trace": "…" }
// 失败
{ "code": 400000, "msg": "用户未登录，请重新登录", "data": null }   // rt 无效/过期/设备不匹配
{ "code": 400002, "msg": "请求签名有问题,请检查后重试", "data": null } // MD5 签名错/时钟漂移 → 降级 agent-refresh
```

**rt 轮换**：每次刷新返回**新的 refresh_token**，旧 rt 作废（按轮换语义处理，刷新成功后必须立即持久化新 rt，否则登录态丢失）。

### 1.5 生产端点实测记录（2026-09-15，假 rt 探测，未消费真 rt）

| 用例 | 结果 | 结论 |
|---|---|---|
| 正确 MD5 签名 + `refresh_token:"fake.invalid.rtoken"` | HTTP 200, `code=400000 用户未登录` | **签名算法正确**（通过验签进入业务层，被假 rt 挡住） |
| 错误签名 + 假 rt | HTTP 200, `code=400002 请求签名有问题` | 验签失败码与应用内降级逻辑吻合 |

### 1.6 令牌参数（实测解码）

| 项 | at（access_token） | rt（refresh_token） |
|---|---|---|
| 格式 | JWT HS256 | JWT HS256（同构） |
| claims | `user_id, device_id, source_id, guid, is_guest, power, iat, exp, jti` | 同左 |
| 有效期 | **24h**（exp−iat=86400） | **30 天**（实测剩余 30.0 天） |
| 存储形态 | `Bearer <JWT>`（**含前缀整体加密存储**） | 同左 |

## 2. 凭证读取：`enc:v10` 的真实方案（重要修正）

**不是裸 DPAPI**。实测裸 `CryptUnprotectData` 解 v10 载荷直接报"数据无效"。
Electron safeStorage 在 Windows 上采用 **Chrome 风格 v10 方案**：

```
密钥链:
  %APPDATA%\AutoClaw\Local State → os_crypt.encrypted_key (base64)
    → base64 解码 → 去掉前 5 字节 "DPAPI" 魔数
    → CryptUnprotectData(CurrentUser, 无 entropy) → 32 字节 AES 密钥

令牌密文 (auth.json / token-cache.json 的 token、refreshToken 字段):
  "enc:" + base64( "v10"(3B) + nonce(12B) + ciphertext + tag(16B，末尾) )
  → AES-256-GCM 解密（无 AAD）
```

- 明文值**自带 `Bearer ` 前缀**（`tokenPrefix$1` 幂等处理），写回时保持同样形态。
- 解密/重加密回环已实测一致（见 scripts/verify-v10.js 输出）。
- `auth.json.backup` 的来源：`readJson$3` 每次**读取**成功都会 `copyFileSync` 一份 `.backup`（不是写入时备份）。
- 明文旁路：环境变量 `AUTOCLAW_DEV_PLAINTEXT_AUTH=1`（或 `AUTOCLAW_E2E=1`）时 `encryptSecret` 直接存明文、`decryptSecret` 对非 `enc:` 值原样放行 —— 自建工具链可利用该开关做 E2E，但官方安装默认加密。
- 解密代码路径：`decryptSecret*`（`safeStorage.decryptString`）；Electron 内部即上述 v10 方案，`safeStorage.encryptString` 输出与之互操作。

### 2.1 可复现的解密配方（实测通过）

PowerShell 取 AES key（DPAPI 部分）：

```powershell
$ls = Get-Content "$env:APPDATA\AutoClaw\Local State" -Raw | ConvertFrom-Json
$ek = [Convert]::FromBase64String($ls.os_crypt.encrypted_key)
Add-Type -AssemblyName System.Security
$key = [System.Security.Cryptography.ProtectedData]::Unprotect(
    [byte[]]$ek[5..($ek.Length-1)], $null, 'CurrentUser')   # 32 字节
```

Node 解密字段（AES-GCM 部分）：

```js
function decrypt(enc, key) {              // enc = "enc:..." 字段值
  const raw = Buffer.from(enc.slice(4), 'base64');
  // raw[0..3)=="v10", nonce=raw[3..15), tag=raw 末 16 字节, ct=中间
  const d = crypto.createDecipheriv('aes-256-gcm', key, raw.subarray(3, 15));
  d.setAuthTag(raw.subarray(raw.length - 16));
  return Buffer.concat([d.update(raw.subarray(15, raw.length - 16)), d.final()]).toString('utf8');
}
```

## 3. 刷新后的写回（"恢复 json"）

刷新成功拿到新 at/rt 后，官方链路会同步 **4 个文件**（顺序无关，但必须全做）：

| # | 文件 | 写入内容 | 写入方 |
|---|---|---|---|
| 1 | `%APPDATA%\AutoClaw\auth.json` | `token`、`refreshToken`（`enc:v10` 重加密，值含 `Bearer ` 前缀）、`updatedAt=Date.now()`；保留 `deviceId`、`userInfo` | `setAuthState()` → `withSafeEncryptedSecrets` → `safeWriteJson`（原子写） |
| 2 | `%APPDATA%\AutoClaw\token-cache.json` | 同 1 的 token/refreshToken（`setTokenCache`，同样 `enc:v10`） | `setTokenCache()` |
| 3 | `~/.openclaw-autoclaw/request-headers.json` | `{"headers":{"X-Authorization":"Bearer <at>","X-Client-Type":"pc"}, "sessionHeaders":{…保留}}` | `updateGatewayAuthToken()`（保留已有 sessionHeaders 合并写回） |
| 4 | `~/.openclaw-autoclaw/openclaw.json` | `models.providers.zai.models[*].headers["X-Authorization"]="Bearer <at>"`（每个模型条目），并校正 `X-Request-Model=<model.id>`、删除陈旧 `X-Request-Id`、刷新静态头 X-Tm/X-Version/X-Product/X-Channel/X-Lang | `syncZaiModelAuthHeaders()` |

重加密（写回 auth.json / token-cache.json）：

```js
function encrypt(plain, key) {            // plain = "Bearer eyJ..."
  const nonce = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, nonce);
  const ct = Buffer.concat([c.update(plain, 'utf8'), c.final()]);
  return 'enc:' + Buffer.concat([Buffer.from('v10'), nonce, ct, c.getAuthTag()]).toString('base64');
}
```

### 3.1 与应用进程的并发约束（关键）

| 文件 | 应用读取行为 | 外部写回是否即时生效 |
|---|---|---|
| auth.json | `getAuthState()` **每次从磁盘读**（无内存缓存） | ✅ 即时 |
| token-cache.json | `getTokenCache()` 有内存缓存 `cache$1`（首读后不再回盘） | ❌ 运行中外部写回不生效 |
| request-headers.json | 网关仅在 **401 重试**时重读（`AutoClawZai401Retry` 补丁轮询等待 X-Authorization 变化） | ✅ 401 触发后生效 |
| openclaw.json | 网关启动/配置重载时读取；config-guard 会监控并可能"自愈"回滚未知变更（`BREAKING_KEY_PREFIXES` 含 `models.providers.zai`，但 headers.X-Authorization 在白名单 `BREAKING_IGNORE_PATTERNS` 内，改它不算破坏） | ⚠️ 需网关重载 |

**结论：外部自持刷新的安全窗口 = AutoClaw 未运行。** 应用运行时外部刷新会与
`refreshAuthTokenForRequestRetry`（应用自己的 401 兜底刷新）竞争同一个 rt：
rt 单次有效，谁先刷谁拿新 rt，另一方持有的旧 rt 立即作废 → 应用侧登录态被踢。
若必须共存，二选一：
- **A（推荐）**：代理只在检测到 AutoClaw 进程不存在时执行刷新；应用运行期间代理只读
  `request-headers.json`（应用 401 自愈机制会保持它最新）。
- **B**：代理接管刷新（inflight 锁 + 刷新后立即写回 4 文件），并要求用户关闭 AutoClaw
  的自动重试……不现实，等价于 A。

### 3.2 写回失败的回滚

刷新是**破坏性操作**（旧 rt 即刻作废）。写回必须视为一个事务：
1. 刷新前备份 4 文件（本项目备份于 `.secrets-backup/<ts>/`）；
2. 刷新成功 → 依次原子写 4 文件（临时文件 + rename，同 `safeWriteJson` 语义）；
3. 任一写失败 → 无法回滚服务端轮换，只能用新 rt 重试写回（新 rt 未消费，仍有效）；
4. 全部失败且新 rt 丢失 → 需要重新短信登录（`agent-send-code` + `agent-login`）。

## 4. 设备身份（deviceId / Ed25519）能否生成？

**能，纯本地密码学，无需服务端注册。** 实测验证：

```js
// generateIdentity() 等价实现（Node 实测）
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const der = publicKey.export({ type: 'spki', format: 'der' });
const raw32 = der.subarray(Buffer.from('302a300506032b6570032100','hex').length); // 去 SPKI 前缀
const deviceId = crypto.createHash('sha256').update(raw32).digest('hex');          // 64 hex ✅ 与本机 identity/device.json 完全吻合
```

- **deviceId = SHA-256(Ed25519 公钥原始 32 字节) hex**（实测 `raw32=true`，der/pem 变体均不匹配）。
- 存储：`%APPDATA%\AutoClaw\identity\device.json`：
  `{version:1, deviceId, publicKeyPem(SPKI), privateKeyPem(PKCS8), createdAtMs}`；
  `parseDeviceIdentity` 读取时会**用公钥重新推导 deviceId 校验自洽**，改 deviceId 不改密钥会被纠正。
- 三级副本（`getOrCreateDeviceIdentity` 回退链）：
  1. 主文件 `userData/identity/device.json`
  2. 云 VM 副本 `/root/.openclaw-autoclaw/identity/device.json`（仅 Linux 云环境存在时）
  3. **系统凭据库副本**：Windows 凭据管理器（PowerShell P/Invoke `CredWrite`，
     TargetName=`{BASE_SERVICE_NAME}/{sku=cn}/{env=release}/{channel=official}/default` 风格，账户名 `default`）；
     macOS Keychain / Linux secret-service 同理。
  4. 都没有 → `generateIdentity()` 本地新生成并写全三处。

### 4.1 服务端绑定语义

- 登录（`agent-login`）与刷新（`refresh`）body 均携带 `device_id`；at/rt 的 JWT 内嵌 `device_id` claim。
- **刷新现有账号时 `device_id` 必须与 rt claim 一致**（即 auth.json 里那个）——不能换新设备身份刷新旧 rt；否则预期 `400000`（服务端校验设备绑定，实测假 rt 已触发同码，无法进一步区分，按最严格假设处理）。
- 新生成的设备身份**只用于全新登录流程**（短信验证码 `agent-send-code` → `agent-login`），登录后该设备与账号绑定并出现在新 JWT 中。
- 设备私钥（`privateKeyPem`）在 LLM/userapi 链路中**未参与签名**（区别于 §5 的 Coding Plan 客户端签名）；它服务于网关 device-auth（`identity/device-auth.json` 的 operator token）与设备副本自洽校验。

### 4.2 对代理项目的含义

- 自持刷新**不需要**生成设备信息——直接沿用 `auth.json.deviceId`。
- 若未来做"多开/新账号自动化"，设备身份可离线批量生成（一行 ed25519 + sha256），但每个新设备走短信登录才能拿到 rt。

## 5. 与 LLM 通道客户端签名的关系（澄清）

§1 的 `X-Auth-Sign`（MD5，userapi 业务接口）与 LLM 通道的 `X-Client-Sig`（Ed25519+PoW，
Coding Plan apiKey `{id}.{secret}` 专用，握手 `/api/paas/c1f3a7e2/v2/client`，host 限
`bigmodel.cn`/`z.ai`）是**两套独立体系**。zai JWT 通道（本项目主链路）两者都不需要
Ed25519 签名：LLM 调用只带 JWT 头，userapi 调用只带 MD5 头。详见
[02-credentials-and-encryption.md](02-credentials-and-encryption.md) §5。

## 6. 自持刷新完整时序（目标实现）

```
[前置] AutoClaw 进程未运行（tasklist 校验）
  1. 备份 4 文件 → .secrets-backup/<ts>/
  2. Local State → DPAPI → AES key
  3. auth.json.token / .refreshToken → AES-GCM 解密 → 去 "Bearer " 前缀
  4. POST /userapi/v1/refresh
       headers: §1.2（MD5 签名，authorization 带当前 at）
       body:    {source_id:"autoclaw", device_id:<auth.deviceId>, refresh_token:<rt>}
     ├─ code=0        → data.access_token / data.refresh_token（新）
     ├─ code=400002   → POST /userapi/v1/agent-refresh 同 body 重试一次
     └─ 其他(400000…) → 中止，rt 已失效需重新登录（不动备份）
  5. 写回（原子）：
       auth.json          token/refreshToken = encrypt("Bearer "+新值), updatedAt=now
       token-cache.json   同上
       request-headers.json  headers.X-Authorization = "Bearer "+新 at（保留 sessionHeaders）
       openclaw.json      zai.models[*].headers.X-Authorization 全量替换
  6. 验证：新 at 调 /autoclaw-proxy/proxy/autoclaw/chat/completions（文档 01 §7）
  7. 失败恢复：新 rt 未消费 → 重试 5；彻底失败 → 还原备份（旧 rt 可能已作废，最坏重新登录）
[运行期] at 未过期(24h)直接用；代理收到 401 → 若应用未运行走 4-5；若应用在运行 → 轮询
         request-headers.json 等应用自愈（复刻 AutoClawZai401Retry 语义）
```
