package config

import (
	"fmt"
	"os"

	"strconv"
	"strings"

	"github.com/joho/godotenv"
	"gopkg.in/yaml.v3"
)

type TunnelEntry struct {
	Hostname string `yaml:"hostname"`
	Target   string `yaml:"target"`
	Mode     string `yaml:"mode"`
}

type ServerConfig struct {
	ServerPort    int
	TunnelPort    int
	DashboardPort int

	JWTSecret string

	ACMEDomains []string
	ACMECache   string
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

func LoadServerConfig(path string) (*ServerConfig, error) {
	_ = godotenv.Load(path)

	get := func(key, def string) string {
		if v := os.Getenv(key); v != "" {
			return v
		}
		return def
	}

	parsePort := func(val string, def int) int {
		if n, err := strconv.Atoi(val); err == nil {
			return n
		}
		return def
	}

	s := &ServerConfig{
		ServerPort:    parsePort(get("SERVER_PORT", "8443"), 8443),
		TunnelPort:    parsePort(get("TUNNEL_PORT", "9443"), 9443),
		DashboardPort: parsePort(get("DASHBOARD_PORT", "8081"), 8081),
		JWTSecret:     get("JWT_SECRET", "changeme"),
		ACMECache:     get("ACME_CACHE", "./cert-cache"),
		ACMEDomains:   strings.Split(get("ACME_DOMAINS", ""), ","),
	}

	if len(s.ACMEDomains) == 0 || s.ACMEDomains[0] == "" {
		return nil, fmt.Errorf("ACME_DOMAINS not set in .env")
	}

	return s, nil
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
