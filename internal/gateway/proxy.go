package gateway

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	domainConfig "gotunnel/internal/domain/config"
	domainTunnel "gotunnel/internal/domain/tunnel"
	"gotunnel/internal/infrastructure/cert"

	"golang.org/x/crypto/acme/autocert"
)

type ProxyServer struct {
	cfg         *domainConfig.ServerConfig
	domainStore domainTunnel.DomainStore
	acmeManager interface{ TLSConfig() *tls.Config }
	httpSrv     *http.Server
	acmeSrv     *http.Server
	ln          net.Listener
	chanLn      *ChanListener
}

func NewProxy(env *domainConfig.ServerConfig, domainStore domainTunnel.DomainStore, hostPolicy cert.HostPolicyFunc) (*ProxyServer, error) {
	p := &ProxyServer{
		cfg:         env,
		domainStore: domainStore,
	}

	if env.ACMEEnable {
		p.acmeManager = cert.NewAutocertManager(env.ACMECache, env.ACMEEnv, hostPolicy)
	}

	// Setup Reverse Proxies
	tunnelTarget, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", env.GatewayPort))
	tunnelProxy := httputil.NewSingleHostReverseProxy(tunnelTarget)

	webuiTarget, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", env.WebUIPort))
	webuiProxy := httputil.NewSingleHostReverseProxy(webuiTarget)

	// Main HTTP Handler
	mainHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := strings.ToLower(strings.Split(r.Host, ":")[0])
		webuiDomain := strings.ToLower(strings.TrimSpace(env.WebUIDomain))

		isWebUI := (webuiDomain != "" && host == webuiDomain) || host == "localhost" || host == "127.0.0.1"

		if isWebUI {
			webuiProxy.ServeHTTP(w, r)
			return
		}

		// If using Redis for Domain Filter
		if p.domainStore != nil {
			allowed, err := p.domainStore.IsDomainAllowed(r.Context(), host)
			if err != nil || !allowed {
				http.Error(w, "Forbidden Domain", http.StatusForbidden)
				return
			}
		}

		tunnelProxy.ServeHTTP(w, r)
	})

	var tlsCfg *tls.Config
	if p.acmeManager != nil {
		tlsCfg = cert.CloneTLSConfig(p.acmeManager.TLSConfig())
	} else if env.WildcardCertPath != "" && env.WildcardKeyPath != "" {
		tlsCfg = cert.CloneTLSConfig(nil)
	}

	if tlsCfg == nil {
		tlsCfg = &tls.Config{}
	}

	cert.WrapWithWildcardCert(tlsCfg, env.WildcardDomain, env.WildcardCertPath, env.WildcardKeyPath)
	
	if len(tlsCfg.Certificates) == 0 && tlsCfg.GetCertificate == nil {
		log.Println("[proxy] Dev Mode / Fallback: Generating self-signed certificate.")
		fallback, err := cert.GenerateSelfSignedCert(env.GatewayDomain + "," + env.TunnelDomain + "," + env.WebUIDomain + ",localhost,127.0.0.1")
		if err == nil {
			tlsCfg.Certificates = fallback.Certificates
		}
	}

	tlsCfg.MinVersion = tls.VersionTLS12
	tlsCfg.NextProtos = cert.EnsureProto(tlsCfg.NextProtos, "h2")
	tlsCfg.NextProtos = cert.EnsureProto(tlsCfg.NextProtos, "http/1.1")
	cert.EnsureDefaultServerName(tlsCfg, env.GatewayDomain)

	p.httpSrv = &http.Server{
		Handler:           mainHandler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    1 << 20,
		TLSConfig:         tlsCfg,
	}

	if env.ACMEEnable {
		p.acmeSrv = buildACMEServer(p.acmeManager.(*autocert.Manager), env.ProxyHttpPort)
	} else {
		p.httpSrv.Addr = fmt.Sprintf("0.0.0.0:%d", env.ProxyHttpPort)
	}

	return p, nil
}

func (p *ProxyServer) Run(ctx context.Context) error {
	errCh := make(chan error, 1)

	if p.cfg.ACMEEnable && p.acmeSrv != nil {
		go func() {
			log.Printf("[proxy] acme-http listening on :%d", p.cfg.ProxyHttpPort)
			if err := p.acmeSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Println("[acme-http]", err)
			}
		}()
	}

	if p.httpSrv.TLSConfig != nil {
		// Listen raw TCP for SNI multiplexing
		addr := fmt.Sprintf("0.0.0.0:%d", p.cfg.ProxyHttpsPort)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return err
		}
		p.ln = ln
		p.chanLn = NewChanListener(ln.Addr())
		go func() {
			log.Printf("[proxy] HTTPS serving multiplexed connections on :%d", p.cfg.ProxyHttpsPort)
			if err := p.httpSrv.Serve(p.chanLn); err != nil && err != http.ErrServerClosed {
				errCh <- err
			}
		}()
		log.Printf("[proxy] SNI Multiplexer listening on %s", addr)

		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					select {
					case <-ctx.Done():
						return
					default:
						log.Printf("[proxy] accept error: %v", err)
						continue
					}
				}
				go p.handleConnection(conn)
			}
		}()
	} 

	if p.acmeSrv == nil {
		go func() {
			log.Printf("[proxy] HTTP public listening on :%d", p.cfg.ProxyHttpPort)
			if err := p.httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				errCh <- err
			}
		}()
	}

	select {
	case <-ctx.Done():
		log.Println("[proxy] shutdown signal received")
	case err := <-errCh:
		return fmt.Errorf("proxy server fatal: %w", err)
	}

	return p.shutdown()
}

func (p *ProxyServer) handleConnection(conn net.Conn) {
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	sni, bConn, err := peekSNI(conn)
	bConn.SetReadDeadline(time.Time{}) // reset deadline

	if err != nil {
		// Could not read SNI, maybe plain HTTP or malformed. We let HTTPS server handle it to throw error.
		// Or if plain HTTP was sent to 443, it will fail TLS handshake.
		tlsConn := tls.Server(bConn, p.httpSrv.TLSConfig)
		p.chanLn.SendConn(tlsConn)
		return
	}

	if sni == p.cfg.TunnelDomain {
		// Tunnel Client connection, route to localhost:9443
		log.Printf("[proxy] SNI matched TunnelDomain %s, routing to localhost:%d", sni, p.cfg.TunnelPort)
		target, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", p.cfg.TunnelPort))
		if err != nil {
			log.Printf("[proxy] tunnel dial error: %v", err)
			bConn.Close()
			return
		}
		go proxyConn(bConn, target)
		return
	}

	// Normal HTTPS traffic
	tlsConn := tls.Server(bConn, p.httpSrv.TLSConfig)
	p.chanLn.SendConn(tlsConn)
}

func proxyConn(src, dst net.Conn) {
	defer src.Close()
	defer dst.Close()
	errc := make(chan error, 1)
	go func() {
		_, err := io.Copy(src, dst)
		errc <- err
	}()
	go func() {
		_, err := io.Copy(dst, src)
		errc <- err
	}()
	<-errc
}

// DummyListener adapts a single connection to a net.Listener

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

func (p *ProxyServer) shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if p.httpSrv != nil {
		p.httpSrv.Shutdown(ctx)
	}
	if p.acmeSrv != nil {
		p.acmeSrv.Shutdown(ctx)
	}
	if p.ln != nil {
		p.ln.Close()
	}
	log.Println("[proxy] shutdown complete")
	return nil
}
