package dto

import domainConfig "gotunnel/internal/domain/config"

type ClientConfigDTO struct {
	TunnelAddr    string                     `yaml:"tunnel_addr" json:"tunnel_addr"`
	ClientID      string                     `yaml:"client_id" json:"client_id"`
	ClientName    string                     `yaml:"client_name" json:"client_name"`
	AuthToken     string                     `yaml:"auth_token" json:"auth_token"`
	Tunnels       []domainConfig.TunnelEntry `yaml:"tunnels" json:"tunnels"`
	SkipTLSVerify bool                       `yaml:"skip_tls_verify" json:"skip_tls_verify"`
}
