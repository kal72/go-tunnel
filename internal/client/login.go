package client

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/term"
)

type loginResponse struct {
	Token string `json:"token"`
}

type Credentials struct {
	Token string `json:"token"`
}

func GetCredentialsPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".gotunnel")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return filepath.Join(dir, "credentials.json"), nil
}

func InteractivePrompt(prompt string, isPassword bool) (string, error) {
	fmt.Print(prompt)
	if isPassword {
		bytePassword, err := term.ReadPassword(int(os.Stdin.Fd()))
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

	endpoint := serverURL + "/api/cli/login"

	data := url.Values{}
	data.Set("username", username)
	data.Set("password", password)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

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

	creds := Credentials(res)

	b, err := json.Marshal(creds)
	if err != nil {
		return fmt.Errorf("failed to encode credentials: %w", err)
	}

	encryptedStr, err := encryptData(b)
	if err != nil {
		return fmt.Errorf("failed to encrypt credentials: %w", err)
	}

	if err := os.WriteFile(credPath, []byte(encryptedStr), 0o600); err != nil {
		return fmt.Errorf("failed to save credentials: %w", err)
	}

	// Cleanup old token file if it exists
	home, _ := os.UserHomeDir()
	oldTokenPath := filepath.Join(home, ".gotunnel", "token")
	_ = os.Remove(oldTokenPath)

	fmt.Printf("Login successful.\n")
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

	decrypted, err := decryptData(string(bytes.TrimSpace(b)))
	if err != nil {
		return nil, errors.New("invalid or corrupted credentials, please login again")
	}

	var creds Credentials
	if err := json.Unmarshal(decrypted, &creds); err != nil {
		return nil, fmt.Errorf("failed to decode credentials: %w", err)
	}

	if strings.TrimSpace(creds.Token) == "" {
		return nil, errors.New("invalid credentials file, please login again")
	}

	return &creds, nil
}

func Logout() error {
	credPath, err := GetCredentialsPath()
	if err != nil {
		return err
	}

	err = os.Remove(credPath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("Already logged out.")
			return nil
		}
		return fmt.Errorf("failed to logout: %w", err)
	}

	fmt.Println("Successfully logged out.")
	return nil
}

func getEncryptionKey() []byte {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "unknown_user"
	}
	hash := sha256.Sum256([]byte("gotunnel-client-super-secret-key-123" + home))
	return hash[:]
}

func encryptData(data []byte) (string, error) {
	block, err := aes.NewCipher(getEncryptionKey())
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decryptData(cryptoText string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(cryptoText)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(getEncryptionKey())
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(data) < gcm.NonceSize() {
		return nil, errors.New("malformed ciphertext")
	}

	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
