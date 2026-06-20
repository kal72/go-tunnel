package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
)

type loginResponse struct {
	Token string `json:"token"`
}

func GetTokenPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".gotunnel")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return filepath.Join(dir, "token"), nil
}

func Login(serverURL, username, password string) error {
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

	tokenPath, err := GetTokenPath()
	if err != nil {
		return fmt.Errorf("failed to get token path: %w", err)
	}

	if err := os.WriteFile(tokenPath, []byte(res.Token), 0600); err != nil {
		return fmt.Errorf("failed to save token: %w", err)
	}

	fmt.Printf("Login successful. Token saved to %s\n", tokenPath)
	return nil
}

func ReadToken() (string, error) {
	tokenPath, err := GetTokenPath()
	if err != nil {
		return "", err
	}
	b, err := os.ReadFile(tokenPath)
	if err != nil {
		return "", fmt.Errorf("could not read token (have you logged in?): %w", err)
	}
	return string(bytes.TrimSpace(b)), nil
}
