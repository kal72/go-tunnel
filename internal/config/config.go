package config

import (
	"fmt"
	"gotunnel/internal/model"
	"os"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
	"gopkg.in/yaml.v3"
)

func LoadServerConfig(path string) (*model.ServerConfig, error) {
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

	s := &model.ServerConfig{
		GatewayHost:    get("GATEWAY_HOST", ""),
		GatewayPort:    parsePort(get("GATEWAY_PORT", "443"), 443),
		TunnelHost:     get("TUNNEL_HOST", ""),
		TunnelPort:     parsePort(get("TUNNEL_PORT", "9443"), 9443),
		WebUIDomain:    get("WEBUI_DOMAIN", "localhost"),
		WebUIPort:      parsePort(get("WEBUI_PORT", "8080"), 8080),
		JWTSecret:      get("JWT_SECRET", "defaultjwtsecret"),
		ACMEEnable:     strings.ToLower(get("ACME_ENABLE", "false")) == "true",
		ACMECache:      get("ACME_CACHE", "./cert-cache"),
		ACMEEnv:        get("ACME_ENV", "staging"), // production or staging
		ACMEPort:       parsePort(get("ACME_PORT", "80"), 80),
		RedisAddr:      get("REDIS_ADDR", "localhost:6379"),
		RedisPass:      get("REDIS_PASS", ""),
		RedisDB:        parsePort(get("REDIS_DB", "0"), 0),
		WildcardDomain:   get("WILDCARD_DOMAIN", ""),
		WildcardCertPath: get("WILDCARD_CERT_PATH", ""),
		WildcardKeyPath:  get("WILDCARD_KEY_PATH", ""),
		DomainRedisDB:    parsePort(get("DOMAIN_REDIS_DB", "1"), 1),
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

func LoadClientConfig(path string) (*model.ClientAppConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c model.ClientAppConfig
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}
