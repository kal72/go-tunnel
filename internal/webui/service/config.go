package service

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const configDir = "assets/configs/"

// ListConfigs returns all .yaml config file names (without extension).
func ListConfigs() ([]string, error) {
	entries, err := os.ReadDir(configDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read config dir: %w", err)
	}

	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".yaml") {
			names = append(names, strings.TrimSuffix(e.Name(), ".yaml"))
		}
	}
	return names, nil
}

// ReadConfig reads and parses a YAML config file into a generic map.
func ReadConfig(name string) (map[string]any, error) {
	path := filepath.Join(configDir, name+".yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config not found: %w", err)
	}

	var result map[string]any
	if err := yaml.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("invalid yaml: %w", err)
	}
	return result, nil
}

// ReadConfigRaw reads a YAML config file and returns the raw bytes.
func ReadConfigRaw(name string) ([]byte, error) {
	path := filepath.Join(configDir, name+".yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config not found: %w", err)
	}
	return data, nil
}

// WriteConfig writes a map back to a YAML config file.
// It automatically creates a .bak backup of the previous version.
func WriteConfig(name string, data map[string]any) error {
	path := filepath.Join(configDir, name+".yaml")

	// Backup existing file before overwrite
	if _, err := os.Stat(path); err == nil {
		existing, _ := os.ReadFile(path)
		_ = os.WriteFile(path+".bak", existing, 0644)
	}

	out, err := yaml.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal yaml: %w", err)
	}
	return os.WriteFile(path, out, 0644)
}

// DeleteConfig removes a configuration file and its backup if it exists.
func DeleteConfig(name string) error {
	path := filepath.Join(configDir, name+".yaml")
	
	// Remove backup first if exists
	_ = os.Remove(path + ".bak")
	
	err := os.Remove(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete config: %w", err)
	}
	return nil
}

// CreateConfig creates a new YAML config file with default values if it doesn't exist.
func CreateConfig(name string) error {
	path := filepath.Join(configDir, name+".yaml")

	// Check if already exists
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("config already exists")
	}

	defaultConfig := map[string]any{
		"tunnel_addr":     "example.com:9443",
		"skip_tls_verify": false,
		"client_id":       name,
		"auth_token":      "",
		"tunnels":         []any{},
	}

	out, err := yaml.Marshal(defaultConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal default config: %w", err)
	}

	return os.WriteFile(path, out, 0644)
}
