package edge

import (
	"crypto/tls"
	"fmt"
	"strings"
)

func cloneTLSConfig(cfg *tls.Config) *tls.Config {
	if cfg == nil {
		return &tls.Config{}
	}
	return cfg.Clone()
}

func ensureProto(list []string, proto string) []string {
	for _, p := range list {
		if p == proto {
			return list
		}
	}
	return append(list, proto)
}

func ensureDefaultServerName(cfg *tls.Config, fallback string) {
	fallback = strings.TrimSpace(fallback)
	if cfg == nil || fallback == "" {
		return
	}
	baseGetCert := cfg.GetCertificate
	cfg.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if hello != nil && hello.ServerName == "" {
			cloned := *hello
			cloned.ServerName = fallback
			hello = &cloned
		}
		if baseGetCert != nil {
			return baseGetCert(hello)
		}
		if len(cfg.Certificates) > 0 {
			return &cfg.Certificates[0], nil
		}
		return nil, fmt.Errorf("no certificates configured")
	}
}
