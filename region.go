package main

// ---- 区域（国内/海外）配置 ----
// 逆向实证（docs/04）：海外版 AutoClaw 与国内版是同一份代码、由编译期 isOversea 区分的两个构建，
// 内置 LLM 通道协议完全相同，唯一差异是：① 上游 host（*.zhipuai.cn ↔ *.autoglm.ai）
// ② X-Lang（zh-CN ↔ en）③ 登录方式（短信 ↔ Google/Z.ai OAuth，本网关靠导入故不区分）。
// 因此把全部差异集中到下面这张表：新增区域 = 加一行；其余代码只问 RegionHost/RegionLang，零分支。

import (
	"os"
	"path/filepath"
	"strings"
)

// Region 账号所属发行区域
type Region string

const (
	RegionCN      Region = "cn"      // 国内：autoglm-acceleration-api.zhipuai.cn，X-Lang zh-CN
	RegionOversea Region = "oversea" // 海外：autoglm-api.autoglm.ai，X-Lang en
)

// DefaultRegion 新账号/未知区域的默认值（向后兼容：老库无 region 列时按国内处理）
const DefaultRegion = RegionCN

// RegionProfile 一个区域的全部差异点
type RegionProfile struct {
	Label string // UI 显示名
	Host  string // 内置加速通道 + userapi 同主机（含 scheme，不含 path）
	Lang  string // X-Lang
}

var regionProfiles = map[Region]RegionProfile{
	RegionCN:      {Label: "国内", Host: "https://autoglm-acceleration-api.zhipuai.cn", Lang: "zh-CN"},
	RegionOversea: {Label: "海外", Host: "https://autoglm-api.autoglm.ai", Lang: "en"},
}

// NormalizeRegion 容错解析区域字符串；空/未知 → DefaultRegion
func NormalizeRegion(s string) Region {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case string(RegionOversea), "overseas", "global", "intl", "z.ai", "autoglm.ai", "海外":
		return RegionOversea
	case string(RegionCN), "china", "domestic", "zhipuai", "zhipuai.cn", "国内":
		return RegionCN
	default:
		return DefaultRegion
	}
}

// Profile 返回区域配置；未知区域回退默认
func (r Region) Profile() RegionProfile {
	if p, ok := regionProfiles[r]; ok {
		return p
	}
	return regionProfiles[DefaultRegion]
}

// accountRegion 取账号区域（nil 安全）
func accountRegion(a *Account) Region {
	if a == nil {
		return DefaultRegion
	}
	return NormalizeRegion(a.Region)
}

// RegionHost 该账号的上游 host。
// 优先级：全局 upstream_host 设置（高级覆盖，测预发/自定义）> 区域默认 host。
func RegionHost(db *DB, a *Account) string {
	if db != nil {
		if v, _ := db.GetSetting("upstream_host"); strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return accountRegion(a).Profile().Host
}

// RegionLang 该账号的 X-Lang
func RegionLang(a *Account) string { return accountRegion(a).Profile().Lang }

// AllRegions UI 下拉/徽标用（稳定顺序）
func AllRegions() []map[string]string {
	order := []Region{RegionCN, RegionOversea}
	out := make([]map[string]string, 0, len(order))
	for _, r := range order {
		p := r.Profile()
		out = append(out, map[string]string{
			"value": string(r),
			"label": p.Label,
			"host":  p.Host,
			"lang":  p.Lang,
		})
	}
	return out
}

// DetectRegionFromHost 从导入来源的 baseUrl/host 推断区域
func DetectRegionFromHost(host string) Region {
	h := strings.ToLower(host)
	if strings.Contains(h, "autoglm.ai") || strings.Contains(h, "z.ai") {
		return RegionOversea
	}
	return RegionCN
}

// ---- 本地区域数据目录 ----
// 国内/海外是编译期 isOversea 的两个构建，Electron userData 与 openclaw home 目录名不同。
// 海外构建目录名无法从国内包确证，故用候选列表探测 + settings 覆盖（oversea_appdata / oversea_openclaw_home）。
func RegionAppDataCandidates(r Region, db *DB) []string {
	appdata := os.Getenv("APPDATA")
	if r == RegionOversea {
		names := []string{"autoclaw", "AutoClaw-Oversea", "AutoClaw-Global", "AutoClaw"}
		if v, _ := db.GetSetting("oversea_appdata"); v != "" {
			names = append([]string{v}, names...)
		}
		out := []string{}
		for _, n := range names {
			out = append(out, filepath.Join(appdata, n))
		}
		return out
	}
	return []string{filepath.Join(appdata, "AutoClaw")}
}

func RegionOpenclawHomeCandidates(r Region, db *DB) []string {
	home := os.Getenv("USERPROFILE")
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	if r == RegionOversea {
		names := []string{".eclaw", ".openclaw-autoclaw-oversea", ".openclaw-autoclaw-global", ".openclaw-autoclaw"}
		if v, _ := db.GetSetting("oversea_openclaw_home"); v != "" {
			names = append([]string{v}, names...)
		}
		out := []string{}
		for _, n := range names {
			out = append(out, filepath.Join(home, n))
		}
		return out
	}
	return []string{filepath.Join(home, ".openclaw-autoclaw")}
}
