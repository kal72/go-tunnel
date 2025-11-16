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
	GatewayHost   string
	GatewayPort   int
	DashboardPort int

	TunnelHost string
	TunnelPort int

	JWTSecret string
	ACMECache string
}

type ClientConfig struct {
	TunnelAddr    string `yaml:"tunnel_addr"`
	SkipTLSVerify bool   `yaml:"skip_tls_verify"`

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
		GatewayHost:   get("GATEWAY_HOST", ""),
		GatewayPort:   parsePort(get("GATEWAY_PORT", "443"), 443),
		DashboardPort: parsePort(get("DASHBOARD_PORT", "8080"), 8080),
		TunnelHost:    get("TUNNEL_HOST", ""),
		TunnelPort:    parsePort(get("TUNNEL_PORT", "9443"), 9443),
		JWTSecret:     get("JWT_SECRET", "defaultjwtsecret"),
		ACMECache:     get("ACME_CACHE", "./cert-cache"),
	}

	if strings.TrimSpace(s.GatewayHost) == "" {
		fmt.Println("[Warning] GATEWAY_HOST not set in environment")
	}
	if strings.TrimSpace(s.TunnelHost) == "" {
		fmt.Println("[Warning] TUNNEL_HOST not set in environment")
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
