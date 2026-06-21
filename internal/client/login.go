package client

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/term"
)

type loginResponse struct {
	Token string `json:"token"`
}

type Credentials struct {
	ServerURL string `json:"server_url"`
	Token     string `json:"token"`
}

func GetCredentialsPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".gotunnel")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return filepath.Join(dir, "credentials.json"), nil
}

func InteractivePrompt(prompt string, isPassword bool) (string, error) {
	fmt.Print(prompt)
	if isPassword {
		bytePassword, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println() // new line after typing password
		if err != nil {
			return "", err
		}
		return string(bytePassword), nil
	}

	reader := bufio.NewReader(os.Stdin)
	text, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(text), nil
}

func Login(serverURL, username, password string) error {
	var err error

	if username == "" {
		username, err = InteractivePrompt("Username: ", false)
		if err != nil {
			return err
		}
	}
	if password == "" {
		password, err = InteractivePrompt("Password: ", true)
		if err != nil {
			return err
		}
	}

	// Normalize server URL
	serverURL = strings.TrimRight(serverURL, "/")

	endpoint := fmt.Sprintf("%s/api/cli/login", serverURL)

	data := url.Values{}
	data.Set("username", username)
	data.Set("password", password)

	resp, err := http.PostForm(endpoint, data)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("login failed (status %d): %s", resp.StatusCode, string(bytes.TrimSpace(body)))
	}

	var res loginResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	credPath, err := GetCredentialsPath()
	if err != nil {
		return fmt.Errorf("failed to get credentials path: %w", err)
	}

	creds := Credentials{
		ServerURL: serverURL,
		Token:     res.Token,
	}

	b, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode credentials: %w", err)
	}

	if err := os.WriteFile(credPath, b, 0600); err != nil {
		return fmt.Errorf("failed to save credentials: %w", err)
	}

	// Cleanup old token file if it exists
	home, _ := os.UserHomeDir()
	oldTokenPath := filepath.Join(home, ".gotunnel", "token")
	os.Remove(oldTokenPath)

	fmt.Printf("Login successful. Credentials saved to %s\n", credPath)
	return nil
}

func ReadCredentials() (*Credentials, error) {
	credPath, err := GetCredentialsPath()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(credPath)
	if err != nil {
		return nil, fmt.Errorf("could not read credentials (have you logged in?): %w", err)
	}

	var creds Credentials
	if err := json.Unmarshal(b, &creds); err != nil {
		return nil, fmt.Errorf("failed to decode credentials: %w", err)
	}

	if creds.Token == "" || creds.ServerURL == "" {
		return nil, fmt.Errorf("invalid credentials file, please login again")
	}

	return &creds, nil
}
