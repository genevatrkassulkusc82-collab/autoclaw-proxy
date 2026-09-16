/* autoclaw-proxy 管理台（session cookie 认证，minimax-2api 风格 · 布局优化版） */

const $ = s => document.querySelector(s);

// ---- 基础设施 ----

async function api(path, options = {}) {
  options.headers = Object.assign({ 'Content-Type': 'application/json' }, options.headers || {});
  if (options.body && typeof options.body !== 'string') options.body = JSON.stringify(options.body);
  const r = await fetch(path, options);
  if (r.status === 401 && !path.endsWith('/admin/login')) {
    showLogin();
    throw new Error('未登录或会话已过期');
  }
  let j;
  try { j = await r.json(); } catch (e) { j = {}; }
  if (!r.ok || j.error) throw new Error(j.error?.message || j.error || ('HTTP ' + r.status));
  return j;
}

function toast(msg, type = 'success') {
  const t = $('#toast');
  t.textContent = msg;
  t.className = type;
  t.style.display = 'block';
  clearTimeout(t._timer);
  t._timer = setTimeout(() => (t.style.display = 'none'), 2800);
}

function showLogin() {
  $('#mainApp').style.display = 'none';
  $('#loginPage').style.display = 'flex';
}

function showMain(username) {
  $('#loginPage').style.display = 'none';
  $('#mainApp').style.display = 'block';
  $('#userAvatar').textContent = (username || 'A')[0].toUpperCase();
}

// ---- 登录 / 登出 ----

async function doLogin() {
  const username = $('#loginUser').value.trim();
  const password = $('#loginPass').value.trim();
  const errBox = $('#loginError');
  errBox.className = 'login-error';
  if (!username || !password) {
    errBox.textContent = '请输入用户名和密码';
    errBox.classList.add('show');
    return;
  }
  try {
    const r = await api('/admin/login', { method: 'POST', body: { username, password } });
    showMain(r.username);
    if (r.is_default_password) $('#defaultPassWarn').style.display = 'flex';
    refreshAll();
    toast('登录成功');
  } catch (e) {
    errBox.textContent = e.message;
    errBox.classList.add('show');
  }
}

async function doLogout() {
  try { await api('/admin/logout', { method: 'POST' }); } catch (e) {}
  showLogin();
}

$('#loginPass').addEventListener('keydown', e => { if (e.key === 'Enter') doLogin(); });
$('#loginUser').addEventListener('keydown', e => { if (e.key === 'Enter') doLogin(); });

// 启动探测会话
(async () => {
  try {
    const me = await fetch('/admin/me').then(r => r.ok ? r.json() : Promise.reject());
    showMain(me.username);
    if (me.is_default_password) $('#defaultPassWarn').style.display = 'flex';
    refreshAll();
  } catch (e) {
    showLogin();
  }
})();

// ---- Tab 切换 ----

function switchSection(name) {
  document.querySelectorAll('.nav-link').forEach(a => a.classList.toggle('active', a.dataset.section === name));
  document.querySelectorAll('.section').forEach(s => s.classList.toggle('active', s.id === 'section-' + name));
  const loaders = {
    dashboard: loadStats, accounts: loadAccounts, keys: loadKeys,
    models: loadModels, proxy: loadProxies, logs: loadUsage, test: loadTestTab,
    settings: loadSettings,
  };
  (loaders[name] || (() => {}))();
}

function refreshAll() {
  loadStats();
  loadAccounts();
  loadKeys();
  loadModels();
  loadProxies();
  loadUsage();
  loadTestTab();
  loadSettings();
  api('/admin/accounts/import-local/preview').then(p => {
    if (p.found && (p.user_id || p.phone)) {
      $('#import-preview').textContent = `检测到本机登录态: user=${p.user_id || '-'} phone=${p.phone || '-'}`;
    } else if (p.found) {
      $('#import-preview').textContent = '检测到本机 AutoClaw 登录态（可直接导入）';
    } else {
      $('#import-preview').textContent = '未检测到: ' + (p.error || '本机无 AutoClaw 登录数据');
    }
  }).catch(() => {});
}

// ---- 弹窗 ----

function showModal(id) { document.getElementById(id).classList.add('show'); }
function hideModal(id) { document.getElementById(id).classList.remove('show'); }
document.querySelectorAll('.modal-overlay').forEach(o =>
  o.addEventListener('click', e => { if (e.target === o) o.classList.remove('show'); }));

// ---- 工具函数 ----

function esc(s) {
  return String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
}
function fmtTime(s) {
  if (!s) return '-';
  const d = new Date(s);
  return isNaN(d) ? String(s) : d.toLocaleString();
}
function fmtTs(ms) { return ms ? new Date(ms).toLocaleString() : '-'; }
function fmtNum(n) { return Number(n || 0).toLocaleString(); }
function fmtDurH(h) {
  if (h == null) return '-';
  if (h < 0) return '<span class="badge badge-danger">已过期</span>';
  if (h < 1) return Math.round(h * 60) + '分';
  return h.toFixed(1) + 'h';
}
function fmtRemainD(d) {
  if (d == null) return '<span class="dim">-</span>';
  if (d < 0) return '<span class="badge badge-danger">已过期</span>';
  const cls = d < 3 ? 'remain-danger' : (d < 7 ? 'remain-low' : 'remain-ok');
  return `<span class="${cls}">${d.toFixed(1)} 天</span>`;
}
function statusBadge(status) {
  const m = {
    active: ['badge-success', '可用'], cooldown: ['badge-warning', '冷却'],
    needs_login: ['badge-danger', '需重登'], disabled: ['badge-muted', '停用'],
    refreshing: ['badge-info', '刷新中'],
  };
  const [c, t] = m[status] || ['badge-muted', status];
  return `<span class="badge ${c}">${t}</span>`;
}

// ---- 仪表盘 ----

async function loadStats() {
  try {
    const [s, keys, accts, usage] = await Promise.all([
      api('/admin/stats'), api('/admin/keys'), api('/admin/accounts'), api('/admin/usage')]);
    $('#st-acc').textContent = s.accounts ?? 0;
    const activeN = (s.accounts_by_status || {}).active || 0;
    $('#st-acc-sub').textContent = activeN + ' 个可用';
    $('#st-ok').textContent = s.ok_24h ?? 0;
    $('#st-fail').textContent = s.fail_24h ?? 0;
    $('#st-tok').textContent = fmtNum(s.tokens_24h);
    $('#st-total').textContent = fmtNum(s.total_requests);
    const keyList = keys.keys || [];
    $('#st-keys').textContent = keyList.length;
    $('#st-keys-sub').textContent = keyList.filter(k => k.is_enabled).length + ' 个启用';
    const dist = Object.entries(s.accounts_by_status || {}).map(([k, v]) => statusBadge(k) + '×' + v).join(' ') || '<span class="dim">暂无账号</span>';
    $('#hint-acc-status').innerHTML = '<b>账号状态分布：</b> ' + dist;
    // RT 到期预警
    const accounts = accts.accounts || [];
    const expiring = accounts.filter(a => a.rt_remaining_d != null && a.rt_remaining_d < 3);
    if (expiring.length > 0) {
      $('#rtExpireWarn').style.display = 'flex';
      $('#rtExpireText').innerHTML = '<b>RefreshToken 即将到期：</b>' +
        expiring.map(a => `账号 #${a.id}（${esc(a.phone || a.user_id)}）剩 ${a.rt_remaining_d.toFixed(1)} 天`).join('、') +
        '。到期后需重新登录，请提前在账号管理中处理。';
    } else {
      $('#rtExpireWarn').style.display = 'none';
    }
    $('#usage-hint').innerHTML =
`<span class="hl"># OpenAI 兼容端点（任何 OpenAI SDK / 客户端可直接接入）</span>
POST ${location.origin}/v1/chat/completions
GET  ${location.origin}/v1/models

<span class="hl"># 鉴权：LLM API Key（在「API 密钥」页新建，Key 仅可调用 LLM 接口）</span>
Authorization: Bearer sk-…

<span class="hl"># curl 示例</span>
curl ${location.origin}/v1/chat/completions \\
  -H "Authorization: Bearer sk-…" -H "Content-Type: application/json" \\
  -d '{"model":"auto","messages":[{"role":"user","content":"你好"}],"stream":true}'`;
    // 最近调用迷你表（前 10）
    $('#dash-usage-tbody').innerHTML = (usage.logs || []).slice(0, 10).map(u => `<tr>
      <td class="mono">${fmtTs(u.created_at)}</td>
      <td>${u.account_id || '-'}</td>
      <td class="mono">${esc(u.model || '-')}</td>
      <td>${u.status === 200 ? '<span class="badge badge-success">200</span>' : '<span class="badge badge-danger">' + u.status + '</span>'}</td>
      <td>${u.prompt_tokens}/${u.completion_tokens}</td>
      <td>${u.ttft_ms ? u.ttft_ms + 'ms' : '-'}</td>
      <td>${u.latency_ms}ms</td></tr>`).join('')
      || '<tr><td colspan="7"><div class="empty"><p>暂无调用记录</p></div></td></tr>';
  } catch (e) { /* 会话失效已由 api() 处理 */ }
}

// ---- 账号管理 ----

async function loadAccounts() {
  try {
    const r = await api('/admin/accounts');
    const list = r.accounts || [];
    $('#accCount').textContent = `共 ${list.length} 个`;
    $('#acct-tbody').innerHTML = list.map(a => `<tr>
      <td>${a.id}</td>
      <td><div class="mono">${a.user_id || '-'}</div><div class="dim mono">${a.phone || ''}</div></td>
      <td>${a.device_spoofed ? '<span class="badge badge-warning">伪造</span>' : '<span class="badge badge-muted">真实(导入)</span>'}
          <div class="dev-id">${esc((a.device_id || '').slice(0, 10))}…</div></td>
      <td>${esc(a.group) || '-'}</td>
      <td>${statusBadge(a.status)}${a.last_error ? `<div class="dim mono" title="${esc(a.last_error)}">${esc(a.last_error.slice(0, 24))}</div>` : ''}</td>
      <td>${fmtDurH(a.at_remaining_h)}</td>
      <td>${fmtRemainD(a.rt_remaining_d)}</td>
      <td>${a.total_requests} / ${fmtNum(a.total_tokens)}</td>
      <td style="white-space:nowrap">
        <button class="btn btn-sm btn-secondary" onclick="refreshAcct(${a.id}, this)">刷新</button>
        <button class="btn btn-sm btn-secondary" onclick="toggleAcct(${a.id}, ${!a.enabled})">${a.enabled ? '停用' : '启用'}</button>
        <button class="btn btn-sm btn-danger" onclick="delAcct(${a.id})">删除</button>
      </td></tr>`).join('')
      || '<tr><td colspan="9"><div class="empty"><div class="icon">🪪</div><p>暂无账号 —— 「📱 验证码登录」新建或「📥 导入本机登录态」</p></div></td></tr>';
  } catch (e) {}
}

async function importLocal() {
  try {
    const r = await api('/admin/accounts/import-local', { method: 'POST', body: { group: '' } });
    toast('导入成功: account=' + r.account.id);
    loadAccounts(); loadStats();
  } catch (e) { toast('导入失败: ' + e.message, 'error'); }
}

async function refreshAcct(id, btn) {
  btn.disabled = true; const old = btn.textContent; btn.textContent = '…';
  try {
    const r = await api(`/admin/accounts/${id}/refresh`, { method: 'POST' });
    toast(`刷新成功，AT 剩余 ${r.remaining_h.toFixed(1)}h`);
  } catch (e) { toast(e.message, 'error'); }
  btn.disabled = false; btn.textContent = old;
  loadAccounts();
}

async function toggleAcct(id, en) {
  try { await api(`/admin/accounts/${id}/${en ? 'enable' : 'disable'}`, { method: 'POST' }); loadAccounts(); }
  catch (e) { toast(e.message, 'error'); }
}

async function delAcct(id) {
  if (!confirm('删除账号 ' + id + '？（仅删除本网关记录，不影响官方客户端）')) return;
  try { await api('/admin/accounts/' + id, { method: 'DELETE' }); loadAccounts(); loadStats(); }
  catch (e) { toast(e.message, 'error'); }
}

// ---- 验证码登录向导（弹窗） ----

let flowID = '';
let lgUseReal = 1; // 1=复用本机真实设备 0=伪造新设备

function setDeviceMode(real) {
  lgUseReal = real;
  document.querySelectorAll('#lg-device-toggle .seg').forEach(s =>
    s.classList.toggle('active', Number(s.dataset.real) === real));
  $('#lg-device-hint').textContent = real
    ? '复用本机 AutoClaw 已绑定的真实设备身份，最不易触发风控；适合给已在本机登录过的账号补录/换绑。'
    : '现场生成全新 Ed25519 设备身份（deviceId = SHA-256(公钥32字节)），与官方客户端设备隔离；若服务端有换设备风控可能被拒。';
}

function openSmsModal() {
  flowID = '';
  $('#lg-phone').value = ''; $('#lg-code').value = '';
  $('#lg-status').textContent = '';
  setDeviceMode(1);
  $('#sms-step1').style.display = 'block';
  $('#sms-step2').style.display = 'none';
  $('#step1-ind').className = 'step active';
  $('#step2-ind').className = 'step';
  $('#btn-send').disabled = false;
  $('#btn-send').textContent = '发送验证码 →';
  showModal('smsModal');
}

function smsBack() {
  $('#sms-step1').style.display = 'block';
  $('#sms-step2').style.display = 'none';
  $('#step1-ind').className = 'step active';
  $('#step2-ind').className = 'step';
  flowID = '';
}

async function sendCode() {
  const phone = $('#lg-phone').value.trim();
  if (!/^1\d{10}$/.test(phone)) return toast('手机号格式不正确', 'error');
  const btn = $('#btn-send');
  btn.disabled = true;
  btn.textContent = '发送中…';
  try {
    const r = await api('/admin/login/send-code', { method: 'POST', body: { phone, group: $('#lg-group').value.trim(), use_real_device: lgUseReal === 1 } });
    flowID = r.flow_id;
    $('#lg-phone-echo').textContent = phone;
    $('#sms-step1').style.display = 'none';
    $('#sms-step2').style.display = 'block';
    $('#step1-ind').className = 'step';
    $('#step2-ind').className = 'step active';
    $('#lg-status').textContent = 'flow=' + flowID.slice(0, 8) + '… · 填入 6 位验证码后点「登录并入库」';
    $('#lg-code').focus();
    toast('验证码已发送');
  } catch (e) {
    btn.disabled = false;
    btn.textContent = '发送验证码 →';
    toast(e.message, 'error');
  }
}

async function verifyLogin() {
  const code = $('#lg-code').value.trim();
  if (!flowID) return toast('流程已失效，请返回重发', 'error');
  if (code.length !== 6) return toast('请填写 6 位数字验证码', 'error');
  $('#lg-status').textContent = '登录中…';
  try {
    const r = await api('/admin/login/verify', { method: 'POST', body: { flow_id: flowID, code, group: $('#lg-group').value.trim() } });
    hideModal('smsModal');
    flowID = '';
    toast('登录成功，账号已入库 (id=' + r.account.id + ')');
    loadAccounts(); loadStats();
  } catch (e) {
    let msg = e.message;
    if (/400001|请求数据有问题/.test(msg)) {
      msg += ' —— 通常是验证码已过期或输入有误，请点「← 返回重发」获取新码后立即提交。';
    }
    $('#lg-status').textContent = '❌ ' + msg;
  }
}

// ---- 在线测试 ----

async function loadTestTab() {
  try {
    const [m, a] = await Promise.all([api('/admin/models'), api('/admin/accounts')]);
    $('#t-model').innerHTML = (m.models || []).map(x =>
      `<option value="${x.id}">${esc(x.name || x.id)} (${x.id})</option>`).join('');
    $('#t-account').innerHTML = '<option value="0">自动（轮询池）</option>' +
      (a.accounts || []).map(x => `<option value="${x.id}">#${x.id} ${esc(x.phone || x.user_id)}</option>`).join('');
  } catch (e) {}
}

async function runTest() {
  $('#t-result').innerHTML = '<span class="loading"></span> <span class="dim">请求中…</span>';
  try {
    const r = await api('/admin/test/chat', { method: 'POST', body: {
      model: $('#t-model').value, prompt: $('#t-prompt').value, account_id: Number($('#t-account').value) } });
    $('#t-result').innerHTML = `
      <div class="result-meta">
        <span class="badge badge-success">HTTP ${r.status}</span>
        <span class="badge badge-info">路由 ${r.route}</span>
        <span class="badge badge-info">上游 ${esc(r.upstream_model || '')}</span>
        <span class="badge badge-muted">账号 #${r.account_id}</span>
        <span class="badge badge-muted">${r.elapsed_ms}ms</span>
        <span class="badge badge-muted">tokens ${esc(JSON.stringify(r.usage || {}))}</span>
      </div>
      ${r.reasoning_preview ? `<label class="form-label">思考链（预览）</label><pre class="out">${esc(r.reasoning_preview)}</pre>` : ''}
      <label class="form-label">回复</label><pre class="out">${esc(r.content || '(空)')}</pre>`;
  } catch (e) {
    $('#t-result').innerHTML = `<span style="color:var(--c-danger)">❌ ${esc(e.message)}</span>`;
  }
}

// ---- API 密钥 ----

async function loadKeys() {
  try {
    const r = await api('/admin/keys');
    const list = r.keys || [];
    $('#keys-tbody').innerHTML = list.map(k => `<tr>
      <td>${esc(k.name)}</td>
      <td class="mono">${esc(k.key_prefix)}…</td>
      <td>${k.is_enabled ? '<span class="badge badge-success">启用</span>' : '<span class="badge badge-muted">停用</span>'}</td>
      <td>${fmtNum(k.used_requests)}${k.max_requests > 0 ? ' / ' + fmtNum(k.max_requests) : ''}</td>
      <td class="mono dim">${k.last_used_at ? fmtTime(k.last_used_at) : '从未使用'}</td>
      <td class="mono dim">${k.expires_at ? fmtTime(k.expires_at) : '永久'}</td>
      <td class="mono dim">${fmtTime(k.created_at)}</td>
      <td style="white-space:nowrap">
        <button class="btn btn-sm btn-secondary" onclick="toggleKey('${k.id}', ${!k.is_enabled})">${k.is_enabled ? '停用' : '启用'}</button>
        <button class="btn btn-sm btn-danger" onclick="delKey('${k.id}', '${esc(k.name)}')">删除</button>
      </td></tr>`).join('')
      || '<tr><td colspan="8"><div class="empty"><div class="icon">🔑</div><p>暂无密钥，点击「+ 新建密钥」创建</p></div></td></tr>';
  } catch (e) {}
}

async function createKey() {
  const name = $('#nk-name').value.trim();
  if (!name) return toast('请输入名称', 'error');
  try {
    const r = await api('/admin/keys', { method: 'POST', body: {
      name, max_requests: Number($('#nk-max').value) || 0, expires_days: Number($('#nk-days').value) || 0 } });
    $('#keyForm').style.display = 'none';
    $('#keyResult').style.display = 'block';
    $('#nk-fullkey').textContent = r.key;
    loadKeys();
  } catch (e) { toast(e.message, 'error'); }
}

function copyFullKey() {
  navigator.clipboard.writeText($('#nk-fullkey').textContent).then(() => toast('已复制'));
}

function closeKeyModal() {
  hideModal('createKeyModal');
  $('#keyForm').style.display = 'block';
  $('#keyResult').style.display = 'none';
  $('#nk-name').value = ''; $('#nk-max').value = 0; $('#nk-days').value = 0;
}

async function toggleKey(id, enabled) {
  try { await api(`/admin/keys/${id}/toggle`, { method: 'POST', body: { enabled } }); loadKeys(); }
  catch (e) { toast(e.message, 'error'); }
}

async function delKey(id, name) {
  if (!confirm(`删除密钥「${name}」？使用该 Key 的客户端将立即失效。`)) return;
  try { await api('/admin/keys/' + id, { method: 'DELETE' }); loadKeys(); }
  catch (e) { toast(e.message, 'error'); }
}

// ---- 模型 ----

async function loadModels() {
  try {
    const r = await api('/admin/models');
    $('#model-tbody').innerHTML = (r.models || []).map(m => `<tr>
      <td class="mono">${esc(m.id)}</td><td>${esc(m.name || '-')}</td>
      <td>${m.reasoning ? '✓' : ''}</td><td>${(m.input || []).join(',')}</td>
      <td>${m.contextWindow ? fmtNum(m.contextWindow) : '-'}</td>
      <td>${m.maxTokens ? fmtNum(m.maxTokens) : '-'}</td>
      <td class="dim" title="${esc(m.tooltip || '')}">${esc((m.tooltip || '').slice(0, 40))}</td></tr>`).join('')
      || '<tr><td colspan="7"><div class="empty"><p>暂无模型目录</p></div></td></tr>';
  } catch (e) {}
}

async function syncModels() {
  try {
    const r = await api('/admin/models/sync', { method: 'POST' });
    toast('同步成功: ' + r.count + ' 个模型');
    loadModels();
  } catch (e) { toast(e.message, 'error'); }
}

// ---- 出口代理 ----

function openProxyModal() {
  $('#px-id').value = 0;
  $('#proxyModalTitle').textContent = '添加代理节点';
  ['px-name', 'px-host', 'px-port', 'px-user', 'px-pass', 'px-group'].forEach(i => $('#' + i).value = '');
  showModal('proxyModal');
}

function editProxy(n) {
  $('#px-id').value = n.id;
  $('#proxyModalTitle').textContent = '编辑代理节点 #' + n.id;
  $('#px-name').value = n.name; $('#px-type').value = n.type;
  $('#px-host').value = n.host; $('#px-port').value = n.port; $('#px-user').value = n.username;
  $('#px-pass').value = ''; $('#px-group').value = n.group;
  showModal('proxyModal');
}

async function loadProxies() {
  try {
    const r = await api('/admin/proxies');
    $('#proxy-tbody').innerHTML = (r.nodes || []).map(n => `<tr>
      <td>${n.id}</td><td>${esc(n.name)}</td><td>${n.type}</td>
      <td class="mono">${esc(n.host)}:${n.port}${n.username ? ' (' + esc(n.username) + ')' : ''}</td>
      <td>${esc(n.group) || '<span class="dim">默认</span>'}</td>
      <td>${n.enabled ? '<span class="badge badge-success">启用</span>' : '<span class="badge badge-muted">停用</span>'}</td>
      <td style="white-space:nowrap">
        <button class="btn btn-sm btn-secondary" onclick='editProxy(${JSON.stringify(n)})'>编辑</button>
        <button class="btn btn-sm btn-secondary" onclick="testProxy(${n.id})">测出口IP</button>
        <button class="btn btn-sm btn-danger" onclick="delProxy(${n.id})">删除</button></td></tr>`).join('')
      || '<tr><td colspan="7"><div class="empty"><div class="icon">🌐</div><p>暂无节点（留空=直连），点击「+ 添加节点」创建</p></div></td></tr>';
  } catch (e) {}
}

async function saveProxy() {
  try {
    await api('/admin/proxies', { method: 'POST', body: {
      id: Number($('#px-id').value), name: $('#px-name').value, type: $('#px-type').value,
      host: $('#px-host').value, port: Number($('#px-port').value),
      username: $('#px-user').value, password: $('#px-pass').value,
      group: $('#px-group').value, enabled: 1 } });
    hideModal('proxyModal');
    toast('已保存');
    loadProxies();
  } catch (e) { toast(e.message, 'error'); }
}

async function delProxy(id) {
  if (!confirm('删除节点 ' + id + '？')) return;
  try { await api('/admin/proxies/' + id, { method: 'DELETE' }); loadProxies(); }
  catch (e) { toast(e.message, 'error'); }
}

async function testProxy(id) {
  const nodes = (await api('/admin/proxies')).nodes || [];
  const n = nodes.find(x => x.id === id);
  if (!n) return;
  toast('测试中…', 'info');
  try {
    const r = await api('/admin/proxies/test', { method: 'POST', body: { url: `${n.type}://${n.host}:${n.port}` } });
    toast(r.ok ? `出口 IP: ${r.exit_ip} (${r.elapsed_ms}ms)` : '失败: ' + r.error, r.ok ? 'success' : 'error');
  } catch (e) { toast(e.message, 'error'); }
}

async function detectProxy() {
  try {
    const r = await api('/admin/proxies/detect', { method: 'POST' });
    const parts = [];
    if (r.system_proxy.enabled) parts.push('系统代理: ' + r.system_proxy.url);
    (r.local_ports || []).forEach(p => parts.push(p.label + ' ' + p.url));
    $('#proxy-detect').textContent = parts.length ? parts.join(' | ') : '未探测到本机代理';
  } catch (e) { toast(e.message, 'error'); }
}

// ---- 设置 ----

async function loadSettings() {
  try {
    const s = await api('/admin/settings');
    ['upstream_host', 'upstream_proxy', 'pool_strategy', 'tls_ja3', 'captcha_prefix',
     'captcha_region', 'captcha_scene_id', 'captcha_page_url', 'listen_addr', 'login_proxy'].forEach(k => {
      const el = $('#st-' + k);
      if (el) el.value = s[k] || '';
    });
    $('#st-captcha_enabled').value = s.captcha_enabled || '';
    $('#st-tls_mode').innerHTML = (s.fingerprint_presets || []).map(p =>
      `<option value="${p.id}" ${p.id === (s.tls_mode || 'chrome') ? 'selected' : ''}>${esc(p.label)}</option>`).join('');
  } catch (e) {}
}

async function saveSettings() {
  const body = {};
  ['upstream_host', 'upstream_proxy', 'pool_strategy', 'tls_ja3', 'captcha_enabled',
   'captcha_prefix', 'captcha_region', 'captcha_scene_id', 'captcha_page_url', 'listen_addr', 'login_proxy'].forEach(k => {
    body[k] = ($('#st-' + k).value || '').trim();
  });
  body.tls_mode = $('#st-tls_mode').value;
  try { await api('/admin/settings', { method: 'POST', body }); toast('设置已保存'); }
  catch (e) { toast(e.message, 'error'); }
}

async function changePassword() {
  const oldP = $('#pw-old').value.trim(), newP = $('#pw-new').value.trim();
  if (!oldP || !newP) return toast('请输入当前密码和新密码', 'error');
  if (newP.length < 6) return toast('新密码至少 6 位', 'error');
  try {
    await api('/admin/password', { method: 'POST', body: { old_password: oldP, new_password: newP } });
    $('#pw-old').value = ''; $('#pw-new').value = '';
    $('#defaultPassWarn').style.display = 'none';
    toast('密码已修改');
  } catch (e) { toast(e.message, 'error'); }
}

async function browserCheck() {
  $('#browser-out').style.display = 'block';
  $('#browser-out').textContent = '启动隐身浏览器自检中（首次较慢）…';
  try {
    const r = await api('/admin/browser/fingerprint-check', { method: 'POST' });
    $('#browser-out').textContent = JSON.stringify(r, null, 1);
  } catch (e) { $('#browser-out').textContent = '❌ ' + e.message; }
}

// ---- 调用日志 ----

async function loadUsage() {
  try {
    const r = await api('/admin/usage');
    $('#usage-tbody').innerHTML = (r.logs || []).map(u => `<tr>
      <td class="mono">${fmtTs(u.created_at)}</td>
      <td>${u.account_id || '-'}</td>
      <td class="mono">${esc(u.model || '-')}</td>
      <td class="mono">${esc(u.route_model || '-')}</td>
      <td>${u.status === 200 ? '<span class="badge badge-success">200</span>' : '<span class="badge badge-danger">' + u.status + '</span>'}</td>
      <td>${u.stream ? '✓' : ''}</td>
      <td>${u.prompt_tokens}/${u.completion_tokens}</td>
      <td>${u.ttft_ms ? u.ttft_ms + 'ms' : '-'}</td>
      <td>${u.latency_ms}ms</td>
      <td class="mono dim" title="${esc(u.error || '')}">${esc((u.error || '').slice(0, 30))}</td></tr>`).join('')
      || '<tr><td colspan="10"><div class="empty"><p>暂无记录</p></div></td></tr>';
  } catch (e) {}
}

// ---- 本机设备身份重置（供官方手动登录新设备） ----

async function resetDevice() {
  if (!confirm('将重新生成官方 AutoClaw 的本机设备身份并移走旧登录态（自动备份）。
请先完全退出官方 AutoClaw。
之后打开官方客户端手动登录（新设备），再回本页导入。
继续？')) return;
  try {
    const r = await api('/admin/device/reset', { method: 'POST' });
    toast('设备身份已重置：' + (r.new_device_id || '').slice(0, 12) + '…');
    alert('重置完成。
旧 deviceId: ' + (r.old_device_id || '(无)') + '
新 deviceId: ' + r.new_device_id + '
已清除登录态: ' + ((r.cleared||[]).join(', ') || '(无)') + '
备份: ' + r.backupDir + '

现在打开官方 AutoClaw 手动登录（将以新设备绑定），登录后回本页「导入本机登录态」。');
  } catch (e) { toast(e.message, 'error'); }
}

async function restoreDevice() {
  let list = [];
  try { list = (await api('/admin/device/backups')).backups || []; } catch (e) { toast(e.message, 'error'); return; }
  if (!list.length) return toast('暂无设备备份', 'error');
  const name = prompt('可恢复的备份（输入名称）:
' + list.join('
'), list[list.length - 1]);
  if (!name) return;
  try { await api('/admin/device/restore', { method: 'POST', body: { name } }); toast('已恢复备份 ' + name); } catch (e) { toast(e.message, 'error'); }
}

// ---- 客户端配对码 ----

async function showPairModal() {
  showModal('pairModal');
  await issuePairCode();
}

async function issuePairCode() {
  try {
    const r = await api('/admin/client/code', { method: 'POST' });
    $('#pair-code').textContent = r.code;
    $('#pair-ttl').textContent = '有效期 ' + Math.round(r.ttl_seconds / 60) + ' 分钟';
  } catch (e) { toast(e.message, 'error'); }
}
