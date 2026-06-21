package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"gotunnel/internal/model"
	tunnelhandler "gotunnel/internal/handler/tunnel"
	"gotunnel/internal/repository/memory"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

type Edge struct {
	cfg      *model.ServerConfig
	httpsSrv *http.Server
	acmeSrv  *http.Server
	tunnelLn net.Listener
}

func New(env *model.ServerConfig, hostRegistry *memory.HostRegistry, domainStore model.DomainStore, srv *tunnelhandler.Server) (*Edge, error) {
	// Autocert
	var m interface{ TLSConfig() *tls.Config }
	if env.ACMEEnable {
		m = NewAutocertManager(env, hostRegistry, domainStore, env.WildcardDomain)
	}

	// WebUI Reverse Proxy
	var webuiProxy http.Handler
	if env.WebUIDomain != "" {
		target, _ := url.Parse(fmt.Sprintf("http://0.0.0.0:%d", env.WebUIPort))

		proxy := &httputil.ReverseProxy{
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.SetURL(target)
				pr.Out.Host = target.Host
			},
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				log.Printf("[edge] WebUI Proxy error: %v", err)
				w.WriteHeader(http.StatusBadGateway)
				fmt.Fprintf(w, "WebUI Proxy Error: %v", err)
			},
		}

		webuiProxy = proxy
	}

	// Route based on Host
	mainHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := strings.ToLower(strings.Split(r.Host, ":")[0])
		webuiDomain := strings.ToLower(strings.TrimSpace(env.WebUIDomain))

		isWebUI := (webuiDomain != "" && host == webuiDomain) || host == "localhost" || host == "127.0.0.1"

		if isWebUI {
			if webuiProxy == nil {
				log.Printf("[edge] WebUI Domain matched (%s) but proxy is nil", host)
				http.Error(w, "WebUI Proxy not initialized", http.StatusInternalServerError)
				return
			}
			log.Printf("[edge] Proxying request for %s to WebUI", host)
			webuiProxy.ServeHTTP(w, r)
			return
		}
		srv.ServeHTTP(w, r)
	})

	// Public Gateway
	var httpsSrv *http.Server
	var acmeSrv *http.Server

	if env.ACMEEnable {
		httpsSrv = buildHTTPSServer(env, m, mainHandler)
		acmeSrv = buildACMEServer(m.(*autocert.Manager), env.ACMEPort)
	} else {
		// Serve standard HTTP if ACME is disabled
		httpsSrv = buildHTTPServer(env, mainHandler)
	}

	// Tunnel TLS listener
	tunnelTLS := buildTunnelTLS(m, env.TunnelHost, !env.ACMEEnable)
	tunnelAddr := fmt.Sprintf("0.0.0.0:%d", env.TunnelPort)
	tunnelLn, err := srv.ListenTunnelTLS(tunnelAddr, tunnelTLS)
	if err != nil {
		return nil, fmt.Errorf("tunnel listener: %w", err)
	}

	return &Edge{
		cfg:      env,
		httpsSrv: httpsSrv,
		acmeSrv:  acmeSrv,
		tunnelLn: tunnelLn,
	}, nil
}

// Run starts all servers and blocks until ctx is cancelled or a fatal error occurs.
func (e *Edge) Run(ctx context.Context) error {
	errCh := make(chan error, 1)

	if e.cfg.ACMEEnable && e.acmeSrv != nil {
		go func() {
			log.Printf("[edge] acme-http listening on :%d", e.cfg.ACMEPort)
			if err := e.acmeSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Println("[acme-http]", err)
			}
		}()
	}

	go func() {
		if e.cfg.ACMEEnable {
			log.Printf("[edge] HTTPS public listening on :%d", e.cfg.GatewayPort)
			if err := e.httpsSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				errCh <- err
			}
		} else {
			log.Printf("[edge] HTTP public listening on :%d", e.cfg.GatewayPort)
			if err := e.httpsSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				errCh <- err
			}
		}
	}()

	select {
	case <-ctx.Done():
		log.Println("[edge] shutdown signal received")
	case err := <-errCh:
		return fmt.Errorf("HTTPS server fatal: %w", err)
	}

	return e.shutdown()
}

func (e *Edge) shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if e.httpsSrv != nil {
		if err := e.httpsSrv.Shutdown(ctx); err != nil {
			log.Printf("[edge] Gateway shutdown error: %v", err)
		}
	}
	if e.acmeSrv != nil {
		if err := e.acmeSrv.Shutdown(ctx); err != nil {
			log.Printf("[edge] acme-http shutdown error: %v", err)
		}
	}
	if e.tunnelLn != nil {
		_ = e.tunnelLn.Close()
	}

	log.Println("[edge] shutdown complete")
	return nil
}

// --- helpers ---

func buildHTTPSServer(env *model.ServerConfig, m interface{ TLSConfig() *tls.Config }, srv http.Handler) *http.Server {
	tlsCfg := cloneTLSConfig(m.TLSConfig())
	wrapWithWildcardCert(tlsCfg, env.WildcardDomain, env.WildcardCertPath, env.WildcardKeyPath)
	tlsCfg.MinVersion = tls.VersionTLS12
	tlsCfg.ClientSessionCache = tls.NewLRUClientSessionCache(128)
	tlsCfg.NextProtos = ensureProto(tlsCfg.NextProtos, "h2")
	tlsCfg.NextProtos = ensureProto(tlsCfg.NextProtos, "http/1.1")
	ensureDefaultServerName(tlsCfg, env.GatewayHost)

	return &http.Server{
		Addr:              fmt.Sprintf("0.0.0.0:%d", env.GatewayPort),
		TLSConfig:         tlsCfg,
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    1 << 20,
	}
}

func buildHTTPServer(env *model.ServerConfig, srv http.Handler) *http.Server {
	return &http.Server{
		Addr:              fmt.Sprintf("0.0.0.0:%d", env.GatewayPort),
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    1 << 20,
	}
}

func buildACMEServer(m interface {
	HTTPHandler(http.Handler) http.Handler
}, port int) *http.Server {
	acmeHandler := m.HTTPHandler(nil)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
			http.Redirect(w, r, "https://"+r.Host+r.URL.String(), http.StatusMovedPermanently)
			return
		}
		acmeHandler.ServeHTTP(w, r)
	})

	return &http.Server{
		Addr:         fmt.Sprintf("0.0.0.0:%d", port),
		Handler:      handler,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  30 * time.Second,
	}
}

func buildTunnelTLS(m interface{ TLSConfig() *tls.Config }, tunnelHost string, generateSelfSigned bool) *tls.Config {
	var tlsCfg *tls.Config
	if generateSelfSigned {
		log.Printf("[edge] ACME disabled, generating self-signed certificate for tunnel: %s", tunnelHost)
		cfg, err := generateSelfSignedCert(tunnelHost)
		if err != nil {
			log.Fatalf("[edge] Failed to generate self-signed cert for tunnel: %v", err)
		}
		tlsCfg = cfg
	} else {
		tlsCfg = cloneTLSConfig(m.TLSConfig())
	}
	
	tlsCfg.MinVersion = tls.VersionTLS12
	tlsCfg.ClientSessionCache = tls.NewLRUClientSessionCache(64)
	ensureDefaultServerName(tlsCfg, tunnelHost)
	return tlsCfg
}
