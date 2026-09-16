package main

// ---- 本机设备身份重置（供官方客户端手动登录新设备）----
// 场景：本机设备身份被上游风控拉黑（登录 400001）时，重新生成官方 AutoClaw 本地的
// 设备身份（identity/device.json 的 Ed25519 密钥对 + deviceId），并移走旧登录态
// （auth.json），使官方客户端以"全新设备"弹出登录页；用户手动完成官方登录（官方风控
// 正常执行），绑定新设备后再回本网关「导入本机登录态」。
//
// 安全：操作前强制备份 identity/device.json 与 auth.json 到 data/device-reset-backups/<ts>/；
// 官方 AutoClaw 进程运行中拒绝执行（避免文件被占用/回写覆盖）。

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// DeviceResetReport 重置结果
type DeviceResetReport struct {
	OldDeviceID string `json:"old_device_id"`
	NewDeviceID string `json:"new_device_id"`
	BackupDir   string `json:"backup_dir"`
	AuthMoved   bool   `json:"auth_moved"`
	IdentityRW  bool   `json:"identity_rewritten"`
}

// autoClawRunning 检测官方 AutoClaw 进程是否在运行（Windows 用 tasklist）
func autoClawRunning() bool {
	out, err := exec.Command("tasklist", "/FI", "IMAGENAME eq AutoClaw.exe").Output()
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(out)), "autoclaw.exe")
}

// ResetLocalDeviceIdentity 重新生成本机设备身份并移走旧登录态
func ResetLocalDeviceIdentity(dataDir string) (*DeviceResetReport, error) {
	if autoClawRunning() {
		return nil, fmt.Errorf("官方 AutoClaw 正在运行，请先完全退出（托盘也退出）后再重置设备身份")
	}
	paths, err := DetectLocalAutoClaw()
	if err != nil {
		return nil, fmt.Errorf("未检测到 AutoClaw 本地数据: %w", err)
	}
	identityPath := filepath.Join(paths.AppDataDir, "identity", "device.json")
	authPath := filepath.Join(paths.AppDataDir, "auth.json")

	// 读旧 deviceId（可缺省）
	oldID := ""
	if raw, err := os.ReadFile(identityPath); err == nil {
		var old struct {
			DeviceID string `json:"deviceId"`
		}
		if json.Unmarshal(raw, &old) == nil {
			oldID = old.DeviceID
		}
	}

	// 备份
	ts := time.Now().Format("20060102-150405")
	backupDir := filepath.Join(dataDir, "device-reset-backups", ts)
	if err := os.MkdirAll(backupDir, 0o755); err != nil {
		return nil, err
	}
	rep := &DeviceResetReport{OldDeviceID: oldID, BackupDir: backupDir}
	if _, err := os.Stat(identityPath); err == nil {
		if err := copyFile(identityPath, filepath.Join(backupDir, "device.json")); err != nil {
			return nil, fmt.Errorf("备份 device.json 失败: %w", err)
		}
	}
	if _, err := os.Stat(authPath); err == nil {
		if err := copyFile(authPath, filepath.Join(backupDir, "auth.json")); err != nil {
			return nil, fmt.Errorf("备份 auth.json 失败: %w", err)
		}
	}

	// 生成新设备身份并写入
	dev, err := GenerateDeviceIdentity()
	if err != nil {
		return nil, fmt.Errorf("生成新设备身份失败: %w", err)
	}
	stored := map[string]interface{}{
		"version":       1,
		"deviceId":      dev.DeviceID,
		"publicKeyPem":  dev.PublicKeyPem,
		"privateKeyPem": dev.PrivateKeyPem,
		"createdAtMs":   time.Now().UnixMilli(),
	}
	blob, _ := json.MarshalIndent(stored, "", "  ")
	if err := os.MkdirAll(filepath.Dir(identityPath), 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(identityPath, blob, 0o600); err != nil {
		return nil, fmt.Errorf("写入新 device.json 失败: %w", err)
	}
	rep.NewDeviceID = dev.DeviceID
	rep.IdentityRW = true

	// 移走旧登录态（让官方客户端弹出登录页）；已备份
	if _, err := os.Stat(authPath); err == nil {
		if err := os.Remove(authPath); err != nil {
			return nil, fmt.Errorf("移除旧 auth.json 失败: %w", err)
		}
		rep.AuthMoved = true
	}
	return rep, nil
}

// RestoreLocalDeviceIdentity 从备份恢复（撤销重置）
func RestoreLocalDeviceIdentity(dataDir, backupName string) error {
	if autoClawRunning() {
		return fmt.Errorf("请先完全退出官方 AutoClaw 再恢复")
	}
	paths, err := DetectLocalAutoClaw()
	if err != nil {
		// 即使检测失败也允许恢复到默认路径
		appdata := os.Getenv("APPDATA")
		paths = &LocalAutoClawPaths{AppDataDir: filepath.Join(appdata, "AutoClaw")}
	}
	src := filepath.Join(dataDir, "device-reset-backups", backupName)
	identityPath := filepath.Join(paths.AppDataDir, "identity", "device.json")
	authPath := filepath.Join(paths.AppDataDir, "auth.json")
	if _, err := os.Stat(filepath.Join(src, "device.json")); err == nil {
		if err := os.MkdirAll(filepath.Dir(identityPath), 0o755); err != nil {
			return err
		}
		if err := copyFile(filepath.Join(src, "device.json"), identityPath); err != nil {
			return err
		}
	}
	if _, err := os.Stat(filepath.Join(src, "auth.json")); err == nil {
		if err := copyFile(filepath.Join(src, "auth.json"), authPath); err != nil {
			return err
		}
	}
	return nil
}

// ListDeviceBackups 列出设备重置备份
func ListDeviceBackups(dataDir string) []string {
	root := filepath.Join(dataDir, "device-reset-backups")
	ents, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		if e.IsDir() {
			out = append(out, e.Name())
		}
	}
	return out
}

func copyFile(src, dst string) error {
	in, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, in, 0o600)
}
