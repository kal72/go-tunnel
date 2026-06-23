package config

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type TunnelEntry struct {
	Hostname string `json:"hostname"`
	Target   string `json:"target"`
	Mode     string `json:"mode"`
}

type TunnelsJSONB []TunnelEntry

func (t *TunnelsJSONB) Scan(val interface{}) error {
	switch v := val.(type) {
	case []byte:
		return json.Unmarshal(v, t)
	case string:
		return json.Unmarshal([]byte(v), t)
	default:
		return fmt.Errorf("unsupported type: %T", v)
	}
}

func (t TunnelsJSONB) Value() (driver.Value, error) {
	if t == nil {
		return []byte("[]"), nil
	}
	return json.Marshal(t)
}

type ClientConfig struct {
	ID        uuid.UUID    `db:"id" json:"id"`
	UserID    uuid.UUID    `db:"user_id" json:"user_id"`
	Name      string       `db:"name" json:"name"`
	Tunnels   TunnelsJSONB `db:"tunnels" json:"tunnels"`
	CreatedAt time.Time    `db:"created_at" json:"created_at"`
	UpdatedAt time.Time    `db:"updated_at" json:"updated_at"`
}

type ServerConfig struct {
	GatewayDomain string
	GatewayPort   int

	TunnelDomain string
	TunnelPort   int

	WebUIDomain string
	WebUIPort   int

	ProxyHttpPort  int
	ProxyHttpsPort int

	MaxFreeDomains int

	JWTSecret      string
	JWTExpireHours int
	ACMEEnable     bool
	ACMECache  string
	ACMEEnv    string

	RedisAddr string
	RedisPass string
	RedisDB   int

	WildcardDomain   string
	WildcardCertPath string
	WildcardKeyPath  string
	DomainRedisDB    int

	DBHost    string
	DBPort    int
	DBUser    string
	DBPass    string
	DBName    string
	DBSSLMode string
}

type ClientAppConfig struct {
	TunnelAddr    string `yaml:"tunnel_addr" json:"tunnel_addr"`
	SkipTLSVerify bool   `yaml:"skip_tls_verify" json:"skip_tls_verify"`

	ClientID   string `yaml:"client_id" json:"client_id"`
	ClientName string `yaml:"client_name" json:"client_name"`
	AuthToken  string `yaml:"auth_token" json:"auth_token"`

	Tunnels []TunnelEntry `yaml:"tunnels" json:"tunnels"`
}
