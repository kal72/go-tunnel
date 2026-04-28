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
	ClientID      string        `yaml:"client_id"       json:"client_id"`
	AuthToken     string        `yaml:"auth_token"      json:"auth_token"`
	Tunnels       []TunnelEntry `yaml:"tunnels"         json:"tunnels"`
}
