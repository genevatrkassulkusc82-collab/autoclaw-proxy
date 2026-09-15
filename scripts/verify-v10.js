// 验证 AutoClaw enc:v10 (Chrome 风格 AES-256-GCM) 凭证方案 —— 只打印脱敏状态，不输出明文
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const APPDATA = process.env.APPDATA;
const HOME = process.env.USERPROFILE;

let input = '';
process.stdin.on('data', d => input += d);
process.stdin.on('end', () => {
  const key = Buffer.from(input.trim(), 'base64');
  if (key.length !== 32) { console.log('KEY LENGTH UNEXPECTED:', key.length); return; }
  const auth = JSON.parse(fs.readFileSync(path.join(APPDATA, 'AutoClaw', 'auth.json'), 'utf8'));

  function decrypt(enc) {
    if (typeof enc !== 'string') return { plain: '', scheme: 'none' };
    if (!enc.startsWith('enc:')) return { plain: enc, scheme: 'plaintext' };
    const raw = Buffer.from(enc.slice(4), 'base64');
    const scheme = raw.subarray(0, 3).toString();
    const nonce = raw.subarray(3, 15);
    const tag = raw.subarray(raw.length - 16);
    const ct = raw.subarray(15, raw.length - 16);
    const d = crypto.createDecipheriv('aes-256-gcm', key, nonce);
    d.setAuthTag(tag);
    return { plain: Buffer.concat([d.update(ct), d.final()]).toString('utf8'), scheme };
  }

  const at = decrypt(auth.token);
  const rt = decrypt(auth.refreshToken);
  console.log('at : scheme=' + at.scheme + ' len=' + at.plain.length + ' isJWT=' + (at.plain.split('.').length === 3) + ' head=' + at.plain.slice(0, 12) + '...');
  console.log('rt : scheme=' + rt.scheme + ' len=' + rt.plain.length + ' isJWT=' + (rt.plain.split('.').length === 3) + ' head=' + rt.plain.slice(0, 12) + '...');

  const rh = JSON.parse(fs.readFileSync(path.join(HOME, '.openclaw-autoclaw', 'request-headers.json'), 'utf8'));
  const rhTok = (rh.headers['X-Authorization'] || '').replace(/^Bearer /, '');
  console.log('at == request-headers 明文JWT :', at.plain === rhTok);

  try {
    const b64 = rt.plain.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
    const claims = JSON.parse(Buffer.from(b64, 'base64').toString());
    const now = Math.floor(Date.now() / 1000);
    const safe = {};
    for (const k of Object.keys(claims)) {
      if (['exp', 'iat', 'nbf'].includes(k)) safe[k] = claims[k];
      else if (typeof claims[k] === 'string' && claims[k].length > 8) safe[k] = '<len' + claims[k].length + '>';
      else safe[k] = claims[k];
    }
    console.log('rt claims:', JSON.stringify(safe));
    if (claims.exp) console.log('rt 剩余有效期: ' + ((claims.exp - now) / 86400).toFixed(1) + ' 天');
  } catch (e) { console.log('rt claims parse fail:', e.message); }

  // 加密回环: v10 + nonce(12) + ct + tag(16)
  const nonce2 = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, nonce2);
  const ct2 = Buffer.concat([c.update(at.plain, 'utf8'), c.final()]);
  const enc2 = 'enc:' + Buffer.concat([Buffer.from('v10'), nonce2, ct2, c.getAuthTag()]).toString('base64');
  console.log('重加密→再解密 回环一致:', decrypt(enc2).plain === at.plain);

  // 设备身份: deviceId 是否 = SHA-256(Ed25519 公钥原始32字节)
  const dev = JSON.parse(fs.readFileSync(path.join(APPDATA, 'AutoClaw', 'identity', 'device.json'), 'utf8'));
  const der = crypto.createPublicKey(dev.publicKeyPem).export({ type: 'spki', format: 'der' });
  const spkiPrefix = Buffer.from('302a300506032b6570032100', 'hex');
  const raw32 = der.subarray(spkiPrefix.length);
  const fpRaw = crypto.createHash('sha256').update(raw32).digest('hex');
  const fpDer = crypto.createHash('sha256').update(der).digest('hex');
  const fpPem = crypto.createHash('sha256').update(dev.publicKeyPem).digest('hex');
  console.log('deviceId 匹配方式: raw32=' + (fpRaw === dev.deviceId) + ' der=' + (fpDer === dev.deviceId) + ' pem=' + (fpPem === dev.deviceId));
  console.log('auth.deviceId == identity.deviceId :', auth.deviceId === dev.deviceId);

  // 新生成设备身份演示（纯本地，不落盘）
  const { publicKey } = crypto.generateKeyPairSync('ed25519');
  const der2 = publicKey.export({ type: 'spki', format: 'der' });
  const newId = crypto.createHash('sha256').update(der2.subarray(spkiPrefix.length)).digest('hex');
  console.log('本地新生成 deviceId 示例: ' + newId.slice(0, 8) + '... (len=' + newId.length + ')');
});
