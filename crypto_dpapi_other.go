//go:build !windows

package main

import "errors"

// cryptUnprotectData 非 Windows 不支持 DPAPI（本地导入/设备重置仅 Windows；Linux 用客户端远程导入）
func cryptUnprotectData(in []byte) ([]byte, error) {
	return nil, errors.New("DPAPI 仅 Windows 支持")
}
