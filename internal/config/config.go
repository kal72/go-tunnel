package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	domainConfig "gotunnel/internal/domain/config"

	"github.com/joho/godotenv"
	"gopkg.in/yaml.v3"
)

func LoadServerConfig(path string) (*domainConfig.ServerConfig, error) {
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

	s := &domainConfig.ServerConfig{
		GatewayDomain:  get("GATEWAY_DOMAIN", ""),
		GatewayPort:    parsePort(get("GATEWAY_PORT", "8443"), 8443),
		TunnelDomain:   get("TUNNEL_DOMAIN", ""),
		TunnelPort:     parsePort(get("TUNNEL_PORT", "9443"), 9443),
		WebUIDomain:    get("WEBUI_DOMAIN", "localhost"),
		WebUIPort:      parsePort(get("WEBUI_PORT", "8080"), 8080),
		ProxyHttpPort:  parsePort(get("PROXY_HTTP_PORT", "80"), 80),
		ProxyHttpsPort: parsePort(get("PROXY_HTTPS_PORT", "443"), 443),

		MaxFreeDomains: parsePort(get("MAX_FREE_DOMAINS", "5"), 5),

		JWTSecret:        get("JWT_SECRET", "defaultjwtsecret"),
		JWTExpireHours:   parsePort(get("JWT_EXPIRE_HOURS", "24"), 24),
		ACMEEnable:       strings.ToLower(get("ACME_ENABLE", "false")) == "true",
		CLILatestVersion: get("CLI_LATEST_VERSION", "v1.0"),
		ACMECache:        get("ACME_CACHE", "./cert-cache"),
		ACMEEnv:          get("ACME_ENV", "staging"), // production or staging
		RedisAddr:        get("REDIS_ADDR", "localhost:6379"),
		RedisPass:        get("REDIS_PASS", ""),
		RedisDB:          parsePort(get("REDIS_DB", "0"), 0),
		WildcardDomain:   get("WILDCARD_DOMAIN", ""),
		WildcardCertPath: get("WILDCARD_CERT_PATH", ""),
		WildcardKeyPath:  get("WILDCARD_KEY_PATH", ""),
		DomainRedisDB:    parsePort(get("DOMAIN_REDIS_DB", "1"), 1),
		DBHost:           get("DB_HOST", "localhost"),
		DBPort:           parsePort(get("DB_PORT", "5432"), 5432),
		DBUser:           get("DB_USER", "postgres"),
		DBPass:           get("DB_PASS", "postgres"),
		DBName:           get("DB_NAME", "gotunnel"),
		DBSSLMode:        get("DB_SSLMODE", "disable"),
	}

	if strings.TrimSpace(s.GatewayDomain) == "" {
		fmt.Println("[Warning] GATEWAY_DOMAIN not set in environment")
	}
	if strings.TrimSpace(s.TunnelDomain) == "" {
		fmt.Println("[Warning] TUNNEL_DOMAIN not set in environment")
	}

	return s, nil
}

func LoadClientConfig(path string) (*domainConfig.ClientAppConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c domainConfig.ClientAppConfig
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}
