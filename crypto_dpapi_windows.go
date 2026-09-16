//go:build windows

package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

// ---------------- DPAPI (Windows) ----------------

type dataBlob struct {
	cbData uint32
	pbData *byte
}

func newBlob(b []byte) *dataBlob {
	if len(b) == 0 {
		return &dataBlob{}
	}
	return &dataBlob{cbData: uint32(len(b)), pbData: &b[0]}
}

func (b *dataBlob) bytes() []byte {
	if b == nil || b.cbData == 0 {
		return nil
	}
	return unsafe.Slice(b.pbData, b.cbData)
}

// cryptUnprotectData DPAPI CryptUnprotectData(CurrentUser)
func cryptUnprotectData(data []byte) ([]byte, error) {
	dll := syscall.MustLoadDLL("crypt32.dll")
	defer dll.Release()
	proc := dll.MustFindProc("CryptUnprotectData")
	in := newBlob(data)
	// pDataOut 是 DATA_BLOB 结构体出参（API 原地填充 cbData/pbData 16 字节），
	// 必须传结构体值的地址，而不是指针变量的地址
	var out dataBlob
	r1, _, err := proc.Call(
		uintptr(unsafe.Pointer(in)),
		0,   // szDataDescr
		0,   // pOptionalEntropy
		0,   // pvReserved
		0,   // pPromptStruct
		0x1, // CRYPTPROTECT_UI_FORBIDDEN
		uintptr(unsafe.Pointer(&out)),
	)
	if r1 == 0 || out.pbData == nil {
		return nil, fmt.Errorf("CryptUnprotectData failed: %w", err)
	}
	defer localFree(uintptr(unsafe.Pointer(out.pbData)))
	res := out.bytes()
	cp := make([]byte, len(res))
	copy(cp, res)
	return cp, nil
}

func localFree(p uintptr) {
	if p == 0 {
		return
	}
	k32 := syscall.NewLazyDLL("kernel32.dll")
	k32.NewProc("LocalFree").Call(p)
}
