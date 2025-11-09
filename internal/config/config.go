package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type TunnelEntry struct {
	Hostname string `yaml:"hostname"`
	Target   string `yaml:"target"`
	Mode     string `yaml:"mode"`
}

type ClientConfig struct {
	TunnelAddr      string   `yaml:"tunnel_addr"`
	SkipTLSVerify   bool     `yaml:"skip_tls_verify"`
	TunnelHostnames []string `yaml:"tunnel_hostnames"`

	JWTSecret    string `yaml:"jwt_secret"`
	JWTIssuer    string `yaml:"jwt_issuer"`
	JWTExpireSec int    `yaml:"jwt_expire_sec"`

	Tunnels []TunnelEntry `yaml:"tunnels"`
}

func LoadClientConfig(path string) (*ClientConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c ClientConfig
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}
