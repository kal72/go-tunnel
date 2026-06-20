package client

import (
	"encoding/json"
	"fmt"
	"net/http"

	"gotunnel/internal/tunnel/config"
)

type ListConfigsResponse []struct {
	Name string `json:"name"`
}

func ListConfigs() error {
	creds, err := ReadCredentials()
	if err != nil {
		return err
	}

	endpoint := fmt.Sprintf("%s/api/cli/configs", creds.ServerURL)
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+creds.Token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch configs: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	var configs ListConfigsResponse
	if err := json.NewDecoder(resp.Body).Decode(&configs); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	fmt.Println("Available configurations:")
	if len(configs) == 0 {
		fmt.Println("  (none)")
	} else {
		for _, c := range configs {
			fmt.Printf("  - %s\n", c.Name)
		}
	}

	return nil
}

func FetchConfig(name string) (*config.ClientConfig, error) {
	creds, err := ReadCredentials()
	if err != nil {
		return nil, err
	}

	endpoint := fmt.Sprintf("%s/api/cli/config/%s", creds.ServerURL, name)
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+creds.Token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch config: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("configuration '%s' not found", name)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	var cfg config.ClientConfig
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("failed to decode configuration: %w", err)
	}

	// Use the CLI credentials token as the tunnel authentication token
	cfg.AuthToken = creds.Token

	return &cfg, nil
}
