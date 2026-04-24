package model

// TunnelEntry represents a single tunnel mapping.
type TunnelEntry struct {
	Hostname string `yaml:"hostname" json:"hostname"`
	Target   string `yaml:"target"   json:"target"`
	Mode     string `yaml:"mode"     json:"mode"`
}

// ClientConfig is the typed representation of client.yaml.
type ClientConfig struct {
	TunnelAddr    string        `yaml:"tunnel_addr"     json:"tunnel_addr"`
	SkipTLSVerify bool          `yaml:"skip_tls_verify" json:"skip_tls_verify"`
	JWTSecret     string        `yaml:"jwt_secret"      json:"jwt_secret"`
	JWTIssuer     string        `yaml:"jwt_issuer"      json:"jwt_issuer"`
	JWTExpireSec  int           `yaml:"jwt_expire_sec"  json:"jwt_expire_sec"`
	Tunnels       []TunnelEntry `yaml:"tunnels"         json:"tunnels"`
}
