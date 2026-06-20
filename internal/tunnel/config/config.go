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
	Hostname string `yaml:"hostname" json:"hostname"`
	Target   string `yaml:"target" json:"target"`
	Mode     string `yaml:"mode" json:"mode"`
}

type ServerConfig struct {
	GatewayHost string
	GatewayPort int

	TunnelHost string
	TunnelPort int

	WebUIDomain string
	WebUIPort   int

	JWTSecret string
	ACMECache string
	ACMEEnv   string
	ACMEPort  int

	RedisAddr string
	RedisPass string
	RedisDB   int

	WildcardDomain string
	DomainRedisDB  int

	DBHost string
	DBPort int
	DBUser string
	DBPass string
	DBName string
}

type ClientConfig struct {
	TunnelAddr    string `yaml:"tunnel_addr" json:"tunnel_addr"`
	SkipTLSVerify bool   `yaml:"skip_tls_verify" json:"skip_tls_verify"`

	ClientID  string `yaml:"client_id" json:"client_id"`
	JWTSecret string `yaml:"jwt_secret" json:"jwt_secret"`
	AuthToken string `yaml:"auth_token" json:"auth_token"`

	Tunnels []TunnelEntry `yaml:"tunnels" json:"tunnels"`
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
		GatewayHost:    get("GATEWAY_HOST", ""),
		GatewayPort:    parsePort(get("GATEWAY_PORT", "443"), 443),
		TunnelHost:     get("TUNNEL_HOST", ""),
		TunnelPort:     parsePort(get("TUNNEL_PORT", "9443"), 9443),
		WebUIDomain:    get("WEBUI_DOMAIN", "localhost"),
		WebUIPort:      parsePort(get("WEBUI_PORT", "8080"), 8080),
		JWTSecret:      get("JWT_SECRET", "defaultjwtsecret"),
		ACMECache:      get("ACME_CACHE", "./cert-cache"),
		ACMEEnv:        get("ACME_ENV", "staging"), // production or staging
		ACMEPort:       parsePort(get("ACME_PORT", "80"), 80),
		RedisAddr:      get("REDIS_ADDR", "localhost:6379"),
		RedisPass:      get("REDIS_PASS", ""),
		RedisDB:        parsePort(get("REDIS_DB", "0"), 0),
		WildcardDomain: get("WILDCARD_DOMAIN", ""),
		DomainRedisDB:  parsePort(get("DOMAIN_REDIS_DB", "1"), 1),
		DBHost:         get("DB_HOST", "localhost"),
		DBPort:         parsePort(get("DB_PORT", "5432"), 5432),
		DBUser:         get("DB_USER", "postgres"),
		DBPass:         get("DB_PASS", "postgres"),
		DBName:         get("DB_NAME", "gotunnel"),
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
