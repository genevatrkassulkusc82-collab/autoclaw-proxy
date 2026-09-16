package main

// ---- SQLite 存储层（modernc 纯 Go，无 CGO）----

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

type DB struct {
	conn *sql.DB
	mu   sync.Mutex // 写序列化（sqlite 单写者）
}

// Account 账号记录
// 状态机: active → cooldown(429/5xx 退避) → active
//
//	active → refreshing → active | needs_login(rt 失效) | disabled(手动)
type Account struct {
	ID            int64  `json:"id"`
	UserID        string `json:"user_id"`
	Phone         string `json:"phone"`
	AccessToken   string `json:"-"` // 裸 JWT，不出 API
	RefreshToken  string `json:"-"`
	DeviceID      string `json:"device_id"`
	PublicKeyPem  string `json:"public_key_pem,omitempty"`
	PrivateKeyPem string `json:"private_key_pem,omitempty"`
	DeviceSpoofed int    `json:"device_spoofed"` // 1=网关伪造设备 0=导入的真实设备
	AccountGroup  string `json:"group"`
	Status        string `json:"status"` // active|cooldown|refreshing|needs_login|disabled
	Strategy      string `json:"strategy"`
	Enabled       int    `json:"enabled"`
	AtExp         int64  `json:"at_exp"`
	RtExp         int64  `json:"rt_exp"`
	CooldownUntil int64  `json:"cooldown_until"`
	LastError     string `json:"last_error"`
	TotalRequests int64  `json:"total_requests"`
	TotalTokens   int64  `json:"total_tokens"`
	FailedStreak  int    `json:"failed_streak"`
	Source        string `json:"source"` // sms_login|local_import|manual|client_import
	Region        string `json:"region"` // cn|oversea —— 决定上游 host 与 X-Lang（默认 cn）
	CreatedAt     int64  `json:"created_at"`
	UpdatedAt     int64  `json:"updated_at"`
}

// ProxyNode 出口代理节点（组绑定）
type ProxyNode struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	Group    string `json:"group"` // 空=默认节点
	Type     string `json:"type"`  // socks5|http
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	Enabled  int    `json:"enabled"`
}

// UsageLog 单次 LLM 调用记录
type UsageLog struct {
	ID          int64  `json:"id"`
	AccountID   int64  `json:"account_id"`
	Model       string `json:"model"`
	RouteModel  string `json:"route_model"`
	Status      int    `json:"status"`
	Stream      int    `json:"stream"`
	PromptTok   int64  `json:"prompt_tokens"`
	CompleteTok int64  `json:"completion_tokens"`
	LatencyMs   int64  `json:"latency_ms"`
	TtftMs      int64  `json:"ttft_ms"`
	Error       string `json:"error"`
	CreatedAt   int64  `json:"created_at"`
}

func OpenDB(dataDir string) (*DB, error) {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, err
	}
	path := filepath.Join(dataDir, "autoclaw-proxy.db")
	conn, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	conn.SetMaxOpenConns(1) // sqlite 写单连接，避免锁竞争
	d := &DB{conn: conn}
	if err := d.migrate(); err != nil {
		return nil, err
	}
	return d, nil
}

func (d *DB) migrate() error {
	ddl := `
CREATE TABLE IF NOT EXISTS accounts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL DEFAULT '',
  phone TEXT NOT NULL DEFAULT '',
  access_token TEXT NOT NULL DEFAULT '',
  refresh_token TEXT NOT NULL DEFAULT '',
  device_id TEXT NOT NULL DEFAULT '',
  public_key_pem TEXT NOT NULL DEFAULT '',
  private_key_pem TEXT NOT NULL DEFAULT '',
  device_spoofed INTEGER NOT NULL DEFAULT 1,
  account_group TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'active',
  strategy TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1,
  at_exp INTEGER NOT NULL DEFAULT 0,
  rt_exp INTEGER NOT NULL DEFAULT 0,
  cooldown_until INTEGER NOT NULL DEFAULT 0,
  last_error TEXT NOT NULL DEFAULT '',
  total_requests INTEGER NOT NULL DEFAULT 0,
  total_tokens INTEGER NOT NULL DEFAULT 0,
  failed_streak INTEGER NOT NULL DEFAULT 0,
  source TEXT NOT NULL DEFAULT 'manual',
  region TEXT NOT NULL DEFAULT 'cn',
  created_at INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL DEFAULT 0,
  UNIQUE(user_id, device_id)
);
CREATE TABLE IF NOT EXISTS proxy_nodes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL DEFAULT '',
  account_group TEXT NOT NULL DEFAULT '',
  type TEXT NOT NULL DEFAULT 'socks5',
  host TEXT NOT NULL DEFAULT '',
  port INTEGER NOT NULL DEFAULT 0,
  username TEXT NOT NULL DEFAULT '',
  password TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS usage_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id INTEGER NOT NULL DEFAULT 0,
  model TEXT NOT NULL DEFAULT '',
  route_model TEXT NOT NULL DEFAULT '',
  status INTEGER NOT NULL DEFAULT 0,
  stream INTEGER NOT NULL DEFAULT 0,
  prompt_tokens INTEGER NOT NULL DEFAULT 0,
  completion_tokens INTEGER NOT NULL DEFAULT 0,
  latency_ms INTEGER NOT NULL DEFAULT 0,
  ttft_ms INTEGER NOT NULL DEFAULT 0,
  error TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_usage_created ON usage_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_accounts_status ON accounts(status, enabled);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  username TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT '',
  expires_at TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS api_keys (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL DEFAULT '',
  key_hash TEXT NOT NULL DEFAULT '',
  key_prefix TEXT NOT NULL DEFAULT '',
  is_enabled INTEGER NOT NULL DEFAULT 1,
  max_requests INTEGER NOT NULL DEFAULT 0,
  used_requests INTEGER NOT NULL DEFAULT 0,
  expires_at TEXT NOT NULL DEFAULT '',
  last_used_at TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(key_prefix);
`
	_, err := d.conn.Exec(ddl)
	if err != nil {
		return err
	}
	// 老库补列：CREATE TABLE IF NOT EXISTS 不会给已存在的表加新列
	d.ensureColumn("accounts", "region", "TEXT NOT NULL DEFAULT 'cn'")
	return nil
}

// ensureColumn 若表缺少某列则 ALTER TABLE 补上（幂等，用于平滑升级老库）
func (d *DB) ensureColumn(table, column, decl string) {
	rows, err := d.conn.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notnull, pk int
		var name, ctype string
		var dflt sql.NullString
		if rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk) == nil && name == column {
			return // 已存在
		}
	}
	if _, err := d.conn.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, decl)); err != nil {
		fmt.Printf("[db] ensureColumn %s.%s 失败: %v\n", table, column, err)
	}
}

// ---------------- settings ----------------

func (d *DB) GetSetting(key string) (string, error) {
	var v string
	err := d.conn.QueryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}

func (d *DB) SetSetting(key, value string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.conn.Exec(
		`INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
		key, value)
	return err
}

// ---------------- accounts ----------------

// UpsertAccount 按 (user_id, device_id) upsert；返回记录 ID
func (d *DB) UpsertAccount(a *Account) (int64, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now().UnixMilli()
	var id int64
	err := d.conn.QueryRow(`SELECT id FROM accounts WHERE user_id=? AND device_id=?`, a.UserID, a.DeviceID).Scan(&id)
	if err == sql.ErrNoRows {
		a.CreatedAt = now
		res, ierr := d.conn.Exec(`INSERT INTO accounts
	(user_id,phone,access_token,refresh_token,device_id,public_key_pem,private_key_pem,device_spoofed,
	 account_group,status,enabled,at_exp,rt_exp,source,region,created_at,updated_at)
	 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			a.UserID, a.Phone, a.AccessToken, a.RefreshToken, a.DeviceID, a.PublicKeyPem, a.PrivateKeyPem,
			a.DeviceSpoofed, a.AccountGroup, orDefault(a.Status, "active"), orDefaultInt(a.Enabled, 1),
			a.AtExp, a.RtExp, orDefault(a.Source, "manual"), string(accountRegion(a)), now, now)
		if ierr != nil {
			return 0, ierr
		}
		return res.LastInsertId()
	}
	if err != nil {
		return 0, err
	}
	_, err = d.conn.Exec(`UPDATE accounts SET
	  phone=?, access_token=?, refresh_token=?, public_key_pem=?, private_key_pem=?, device_spoofed=?,
	  account_group=?, at_exp=?, rt_exp=?, source=?,
	  region=CASE WHEN ?='' THEN region ELSE ? END, updated_at=?,
	  status=CASE WHEN status IN ('needs_login','refreshing') THEN 'active' ELSE status END
	 WHERE id=?`,
		a.Phone, a.AccessToken, a.RefreshToken, a.PublicKeyPem, a.PrivateKeyPem, a.DeviceSpoofed,
		a.AccountGroup, a.AtExp, a.RtExp, orDefault(a.Source, a.Source),
		a.Region, string(NormalizeRegion(a.Region)), now, id)
	return id, err
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
func orDefaultInt(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}

func (d *DB) ListAccounts() ([]*Account, error) {
	rows, err := d.conn.Query(`SELECT id,user_id,phone,access_token,refresh_token,device_id,
	 public_key_pem,private_key_pem,device_spoofed,account_group,status,strategy,enabled,
	 at_exp,rt_exp,cooldown_until,last_error,total_requests,total_tokens,failed_streak,source,region,created_at,updated_at
	 FROM accounts ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Account
	for rows.Next() {
		a := &Account{}
		if err := rows.Scan(&a.ID, &a.UserID, &a.Phone, &a.AccessToken, &a.RefreshToken, &a.DeviceID,
			&a.PublicKeyPem, &a.PrivateKeyPem, &a.DeviceSpoofed, &a.AccountGroup, &a.Status, &a.Strategy,
			&a.Enabled, &a.AtExp, &a.RtExp, &a.CooldownUntil, &a.LastError, &a.TotalRequests,
			&a.TotalTokens, &a.FailedStreak, &a.Source, &a.Region, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (d *DB) GetAccount(id int64) (*Account, error) {
	all, err := d.ListAccounts()
	if err != nil {
		return nil, err
	}
	for _, a := range all {
		if a.ID == id {
			return a, nil
		}
	}
	return nil, fmt.Errorf("账号 %d 不存在", id)
}

func (d *DB) UpdateAccountTokens(id int64, at, rt string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.conn.Exec(`UPDATE accounts SET access_token=?, refresh_token=?, at_exp=?, rt_exp=?,
 status='active', last_error='', failed_streak=0, updated_at=? WHERE id=?`,
		at, rt, TokenExpiresAt(at), TokenExpiresAt(rt), time.Now().UnixMilli(), id)
	return err
}

func (d *DB) SetAccountStatus(id int64, status, lastError string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.conn.Exec(`UPDATE accounts SET status=?, last_error=?, updated_at=? WHERE id=?`,
		status, lastError, time.Now().UnixMilli(), id)
	return err
}

func (d *DB) SetAccountEnabled(id int64, enabled bool) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	v := 0
	if enabled {
		v = 1
	}
	_, err := d.conn.Exec(`UPDATE accounts SET enabled=?, status=CASE WHEN ? THEN 'active' ELSE 'disabled' END,
 updated_at=? WHERE id=?`, v, enabled, time.Now().UnixMilli(), id)
	return err
}

func (d *DB) SetAccountCooldown(id int64, until time.Time, reason string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.conn.Exec(`UPDATE accounts SET status='cooldown', cooldown_until=?, last_error=?, updated_at=? WHERE id=?`,
		until.UnixMilli(), reason, time.Now().UnixMilli(), id)
	return err
}

func (d *DB) BumpAccountFailure(id int64, errMsg string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.conn.Exec(`UPDATE accounts SET failed_streak=failed_streak+1, last_error=?, updated_at=? WHERE id=?`,
		errMsg, time.Now().UnixMilli(), id)
	return err
}

func (d *DB) DeleteAccount(id int64) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.conn.Exec(`DELETE FROM accounts WHERE id=?`, id)
	return err
}

// SetAccountRegion 切换账号区域（国内/海外）；非法值归一化为默认区域
func (d *DB) SetAccountRegion(id int64, region string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.conn.Exec(`UPDATE accounts SET region=?, updated_at=? WHERE id=?`,
		string(NormalizeRegion(region)), time.Now().UnixMilli(), id)
	return err
}

// ---------------- proxy nodes ----------------

func (d *DB) UpsertProxyNode(n *ProxyNode) (int64, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if n.ID > 0 {
		_, err := d.conn.Exec(`UPDATE proxy_nodes SET name=?,account_group=?,type=?,host=?,port=?,username=?,password=?,enabled=? WHERE id=?`,
			n.Name, n.Group, n.Type, n.Host, n.Port, n.Username, n.Password, n.Enabled, n.ID)
		return n.ID, err
	}
	res, err := d.conn.Exec(`INSERT INTO proxy_nodes(name,account_group,type,host,port,username,password,enabled) VALUES(?,?,?,?,?,?,?,?)`,
		n.Name, n.Group, n.Type, n.Host, n.Port, n.Username, n.Password, orDefaultInt(n.Enabled, 1))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (d *DB) ListProxyNodes() ([]*ProxyNode, error) {
	rows, err := d.conn.Query(`SELECT id,name,account_group,type,host,port,username,password,enabled FROM proxy_nodes ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ProxyNode
	for rows.Next() {
		n := &ProxyNode{}
		if err := rows.Scan(&n.ID, &n.Name, &n.Group, &n.Type, &n.Host, &n.Port, &n.Username, &n.Password, &n.Enabled); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func (d *DB) DeleteProxyNode(id int64) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.conn.Exec(`DELETE FROM proxy_nodes WHERE id=?`, id)
	return err
}

// ProxyNodeForGroup 组绑定节点 → 默认节点（group 空）
func (d *DB) ProxyNodeForGroup(group string) (*ProxyNode, error) {
	nodes, err := d.ListProxyNodes()
	if err != nil {
		return nil, err
	}
	var fallback *ProxyNode
	for _, n := range nodes {
		if n.Enabled != 1 {
			continue
		}
		if n.Group == group && group != "" {
			return n, nil
		}
		if n.Group == "" {
			fallback = n
		}
	}
	return fallback, nil
}

// ---------------- usage ----------------

func (d *DB) InsertUsage(u *UsageLog) {
	d.mu.Lock()
	defer d.mu.Unlock()
	u.CreatedAt = time.Now().UnixMilli()
	d.conn.Exec(`INSERT INTO usage_logs(account_id,model,route_model,status,stream,prompt_tokens,completion_tokens,latency_ms,ttft_ms,error,created_at)
 VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		u.AccountID, u.Model, u.RouteModel, u.Status, u.Stream, u.PromptTok, u.CompleteTok, u.LatencyMs, u.TtftMs, u.Error, u.CreatedAt)
	d.conn.Exec(`UPDATE accounts SET total_requests=total_requests+1, total_tokens=total_tokens+? WHERE id=?`,
		u.PromptTok+u.CompleteTok, u.AccountID)
}

func (d *DB) RecentUsage(limit int) ([]*UsageLog, error) {
	rows, err := d.conn.Query(`SELECT id,account_id,model,route_model,status,stream,prompt_tokens,completion_tokens,latency_ms,ttft_ms,error,created_at
 FROM usage_logs ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*UsageLog
	for rows.Next() {
		u := &UsageLog{}
		if err := rows.Scan(&u.ID, &u.AccountID, &u.Model, &u.RouteModel, &u.Status, &u.Stream,
			&u.PromptTok, &u.CompleteTok, &u.LatencyMs, &u.TtftMs, &u.Error, &u.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// Stats 仪表盘统计
func (d *DB) Stats() map[string]interface{} {
	out := map[string]interface{}{}
	var total, ok24h, fail24h int64
	var tok24h int64
	since := time.Now().Add(-24 * time.Hour).UnixMilli()
	d.conn.QueryRow(`SELECT COUNT(*) FROM usage_logs`).Scan(&total)
	d.conn.QueryRow(`SELECT COUNT(*), COALESCE(SUM(prompt_tokens+completion_tokens),0) FROM usage_logs WHERE created_at>=? AND status=200`, since).Scan(&ok24h, &tok24h)
	d.conn.QueryRow(`SELECT COUNT(*) FROM usage_logs WHERE created_at>=? AND status!=200`, since).Scan(&fail24h)
	out["total_requests"] = total
	out["ok_24h"] = ok24h
	out["fail_24h"] = fail24h
	out["tokens_24h"] = tok24h
	accounts, _ := d.ListAccounts()
	byStatus := map[string]int{}
	for _, a := range accounts {
		byStatus[a.Status]++
	}
	out["accounts"] = len(accounts)
	out["accounts_by_status"] = byStatus
	return out
}

// ModelCatalogCache 模型目录缓存（settings 表 JSON，按区域分键）
// 国内/海外模型清单可能不同，分别缓存于 model_catalog:cn / model_catalog:oversea。
func (d *DB) SaveModelCatalog(region Region, models json.RawMessage) error {
	return d.SetSetting("model_catalog:"+string(region), string(models))
}

func (d *DB) LoadModelCatalog(region Region) json.RawMessage {
	v, _ := d.GetSetting("model_catalog:" + string(region))
	if v == "" && region == RegionCN {
		v, _ = d.GetSetting("model_catalog") // 兼容老库的单一缓存键
	}
	if v == "" {
		return nil
	}
	return json.RawMessage(v)
}
