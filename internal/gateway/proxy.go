package gateway

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"gotunnel/internal/config"
	domainTunnel "gotunnel/internal/domain/tunnel"
	"gotunnel/internal/infrastructure/cert"
	"gotunnel/internal/shared/netutil"

	"github.com/google/uuid"
	"golang.org/x/crypto/acme/autocert"
)

type ProxyServer struct {
	cfg         *config.ServerConfig
	domainStore domainTunnel.DomainStore
	acmeManager interface{ TLSConfig() *tls.Config }
	httpSrv     *http.Server
	acmeSrv     *http.Server
	ln          net.Listener
	chanLn      *ChanListener
}

func NewProxy(env *config.ServerConfig, domainStore domainTunnel.DomainStore, hostPolicy cert.HostPolicyFunc) (*ProxyServer, error) {
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
			allowed, err := p.domainStore.IsDomainAllowed(r.Context(), host, uuid.Nil, 1)
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
		lc := net.ListenConfig{}
		ln, err := lc.Listen(ctx, "tcp", addr)
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
	netutil.SetTCPNoDelay(conn)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	sni, bConn, err := peekSNI(conn)
	_ = bConn.SetReadDeadline(time.Time{}) // reset deadline

	if err != nil {
		// Could not read SNI, check if it is a Minecraft Handshake packet
		_ = bConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		mcHost, mcConn, mcErr := peekMinecraft(bConn)
		_ = mcConn.SetReadDeadline(time.Time{}) // reset deadline

		if mcErr == nil && mcHost != "" {
			log.Printf("[proxy] Minecraft Handshake detected for host %s, routing to gateway :%d", mcHost, p.cfg.GatewayPort)
			dialer := &net.Dialer{Timeout: 5 * time.Second}
			gwConn, dialErr := dialer.DialContext(context.Background(), "tcp", fmt.Sprintf("127.0.0.1:%d", p.cfg.GatewayPort))
			if dialErr != nil {
				log.Printf("[proxy] gateway dial error for Minecraft host %s: %v", mcHost, dialErr)
				_ = mcConn.Close()
				return
			}
			clientAddr := mcConn.RemoteAddr().String()
			clientIP, clientPortStr, errSplit := net.SplitHostPort(clientAddr)
			if errSplit != nil {
				clientIP = clientAddr
				clientPortStr = "54321"
			}
			reqStr := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nX-Real-IP: %s\r\nX-Real-Port: %s\r\nX-Forwarded-For: %s\r\n\r\n", mcHost, mcHost, clientIP, clientPortStr, clientIP)
			if _, wErr := gwConn.Write([]byte(reqStr)); wErr != nil {
				log.Printf("[proxy] failed to send upgrade to gateway for %s: %v", mcHost, wErr)
				_ = gwConn.Close()
				_ = mcConn.Close()
				return
			}
			br := bufio.NewReader(gwConn)
			resp, rErr := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
			if resp != nil && resp.Body != nil {
				_ = resp.Body.Close()
			}
			if rErr != nil || (resp.StatusCode != http.StatusSwitchingProtocols && resp.StatusCode != http.StatusOK) {
				if resp != nil {
					log.Printf("[proxy] gateway rejected Minecraft host %s with status %d", mcHost, resp.StatusCode)
				} else {
					log.Printf("[proxy] failed to read upgrade response for %s: %v", mcHost, rErr)
				}
				_ = gwConn.Close()
				_ = mcConn.Close()
				return
			}
			targetConn := gwConn
			if br.Buffered() > 0 {
				bufferedData, _ := br.Peek(br.Buffered())
				bufCopy := make([]byte, len(bufferedData))
				copy(bufCopy, bufferedData)
				targetConn = &bufferedConn{Conn: gwConn, buf: bufCopy}
			}
			go proxyConn(mcConn, targetConn)
			return
		}

		// Not TLS and not Minecraft, let HTTPS server handle it to throw error.
		tlsConn := tls.Server(bConn, p.httpSrv.TLSConfig)
		p.chanLn.SendConn(tlsConn)
		return
	}

	if sni == p.cfg.TunnelDomain {
		// Tunnel Client connection, route to localhost:9443
		log.Printf("[proxy] SNI matched TunnelDomain %s, routing to localhost:%d", sni, p.cfg.TunnelPort)
		dialer := &net.Dialer{Timeout: 5 * time.Second}
		target, err := dialer.DialContext(context.Background(), "tcp", fmt.Sprintf("127.0.0.1:%d", p.cfg.TunnelPort))
		if err != nil {
			log.Printf("[proxy] tunnel dial error: %v", err)
			_ = bConn.Close()
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
	netutil.SetTCPNoDelay(src)
	netutil.SetTCPNoDelay(dst)
	defer func() { _ = src.Close() }()
	defer func() { _ = dst.Close() }()
	errc := make(chan error, 1)
	go func() {
		_, err := netutil.CopyBuffer(src, dst)
		errc <- err
	}()
	go func() {
		_, err := netutil.CopyBuffer(dst, src)
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
			target := &url.URL{
				Scheme:   "https",
				Host:     r.Host,
				Path:     r.URL.Path,
				RawQuery: r.URL.RawQuery,
			}
			http.Redirect(w, r, target.String(), http.StatusMovedPermanently)
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
	log.Println("[proxy] starting graceful shutdown (waiting up to 30s for active requests to drain)...")
	if p.ln != nil {
		_ = p.ln.Close()
	}
	if p.chanLn != nil {
		_ = p.chanLn.Close()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if p.httpSrv != nil {
		_ = p.httpSrv.Shutdown(ctx)
	}
	if p.acmeSrv != nil {
		_ = p.acmeSrv.Shutdown(ctx)
	}
	log.Println("[proxy] graceful shutdown complete")
	return nil
}
