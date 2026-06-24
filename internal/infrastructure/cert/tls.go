package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"
)

func CloneTLSConfig(cfg *tls.Config) *tls.Config {
	if cfg == nil {
		return &tls.Config{}
	}
	return cfg.Clone()
}

func EnsureProto(list []string, proto string) []string {
	for _, p := range list {
		if p == proto {
			return list
		}
	}
	return append(list, proto)
}

func EnsureDefaultServerName(cfg *tls.Config, fallback string) {
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

func WrapWithWildcardCert(cfg *tls.Config, wildcardDomain, certPath, keyPath string) {
	if wildcardDomain == "" || certPath == "" || keyPath == "" {
		return
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		fmt.Printf("[edge] warning: failed to load wildcard cert from %s: %v\n", certPath, err)
		return
	}

	baseGetCert := cfg.GetCertificate
	cfg.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if hello != nil && MatchWildcard(strings.ToLower(hello.ServerName), wildcardDomain) {
			return &cert, nil
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

func GenerateSelfSignedCert(host string) (*tls.Config, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Go Tunnel Auto-Generated"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	hosts := strings.Split(host, ",")
	for _, h := range hosts {
		template.DNSNames = append(template.DNSNames, h)
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	b, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}
