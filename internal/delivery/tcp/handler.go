package tunnel

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	domainSetting "gotunnel/internal/domain/setting"
	domainTunnel "gotunnel/internal/domain/tunnel"
	domainUser "gotunnel/internal/domain/user"
	"gotunnel/internal/shared/protocol"
	"gotunnel/internal/shared/ratelimit"
	usecaseSetting "gotunnel/internal/usecase/setting"
	usecaseTunnel "gotunnel/internal/usecase/tunnel"
	usecaseUser "gotunnel/internal/usecase/user"

	"github.com/hashicorp/yamux"
	"go.uber.org/zap"
)

type TunnelSession struct {
	Connected  time.Time
	Session    *yamux.Session
	Ctrl       *yamux.Stream
	Hostnames  map[string]struct{}
	Modes      map[string]string
	ClientName string
	Username   string
	ClientIP   string
	Role       int16
}

type Server struct {
	lastRateLimitFetch time.Time
	hostRegistry       domainTunnel.HostRegistry
	tunnelUsecase      usecaseTunnel.TunnelUsecase
	authUsecase        usecaseUser.AuthUsecase
	settingUsecase     usecaseSetting.SettingUsecase
	logger             *zap.Logger
	hostToSes          map[string]*TunnelSession
	limiter            *ratelimit.Limiter
	dashboardDomain    string
	wildcardDomain     string
	jwtSecret          []byte
	cachedRateLimitCfg domainSetting.RateLimitConfig
	heartbeatInterval  time.Duration
	mu                 sync.RWMutex
	rateLimitMu        sync.RWMutex
}

func NewServerJWT(jwtSecret string, hostRegistry domainTunnel.HostRegistry, serverDomain, wildcardDomain string, tunnelUsecase usecaseTunnel.TunnelUsecase, authUsecase usecaseUser.AuthUsecase, settingUsecase usecaseSetting.SettingUsecase) (*Server, error) {
	logger, _ := zap.NewProduction()
	return &Server{
		jwtSecret:       []byte(jwtSecret),
		hostToSes:       map[string]*TunnelSession{},
		logger:          logger,
		hostRegistry:    hostRegistry,
		dashboardDomain: canonicalHost(serverDomain),
		wildcardDomain:  wildcardDomain,
		tunnelUsecase:   tunnelUsecase,
		authUsecase:     authUsecase,
		settingUsecase:  settingUsecase,
		limiter:         ratelimit.NewLimiter(),
	}, nil
}

func (s *Server) getRateLimitConfig(ctx context.Context) domainSetting.RateLimitConfig {
	s.rateLimitMu.RLock()
	if !s.lastRateLimitFetch.IsZero() && time.Since(s.lastRateLimitFetch) < 3*time.Second {
		cfg := s.cachedRateLimitCfg
		s.rateLimitMu.RUnlock()
		return cfg
	}
	s.rateLimitMu.RUnlock()

	s.rateLimitMu.Lock()
	defer s.rateLimitMu.Unlock()
	if !s.lastRateLimitFetch.IsZero() && time.Since(s.lastRateLimitFetch) < 3*time.Second {
		return s.cachedRateLimitCfg
	}
	if s.settingUsecase != nil {
		s.cachedRateLimitCfg = s.settingUsecase.GetRateLimitConfig(ctx)
	} else {
		s.cachedRateLimitCfg = domainSetting.RateLimitConfig{Enabled: true, Rate: 100, Burst: 20, AdminAllowed: false}
	}
	s.lastRateLimitFetch = time.Now()
	return s.cachedRateLimitCfg
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	ses := s.sessionForHost(host)
	if ses == nil {
		http.Error(w, "no tunnel for host", http.StatusBadGateway)
		return
	}

	cfg := s.getRateLimitConfig(r.Context())
	enabled := cfg.Enabled
	if ses.Role != 1 && ses.Username != "" {
		enabled = false
		if s.tunnelUsecase != nil {
			if val, err := s.tunnelUsecase.GetRateLimitSetting(r.Context(), ses.Username); err == nil && val != "" {
				enabled = val == "true"
			} else if s.settingUsecase != nil {
				if val, err := s.settingUsecase.GetSetting(r.Context(), "rate_limit_enabled:"+ses.Username); err == nil && val != "" {
					enabled = val == "true"
				}
			}
		} else if s.settingUsecase != nil {
			if val, err := s.settingUsecase.GetSetting(r.Context(), "rate_limit_enabled:"+ses.Username); err == nil && val != "" {
				enabled = val == "true"
			}
		}
	}
	if enabled && s.limiter != nil {
		if ses.Role != 1 || cfg.AdminAllowed {
			if !s.limiter.Allow(host, cfg.Rate, cfg.Burst) {
				w.Header().Set("Retry-After", "1")
				http.Error(w, "429 Too Many Requests", http.StatusTooManyRequests)
				return
			}
		}
	}
	mode := ses.modeForHost(host)

	if ses.Session == nil {
		http.Error(w, "session unavailable", http.StatusBadGateway)
		return
	}
	stream, err := ses.Session.OpenStream()
	if err != nil {
		http.Error(w, "open stream failed", http.StatusBadGateway)
		return
	}
	defer func() { _ = stream.Close() }()

	// Header biner: hostname
	if err := protocol.WriteDataHeader(stream, host); err != nil {
		http.Error(w, "write header failed", http.StatusBadGateway)
		return
	}

	// --- jika HTTP (default): kirim HTTP request ---
	if mode != "tcp" && mode != "minecraft-proxy" {
		start := time.Now()
		if err := r.Write(stream); err != nil {
			http.Error(w, "write req failed", http.StatusBadGateway)
			return
		}
		resp, err := http.ReadResponse(bufio.NewReader(stream), r)
		if err != nil {
			http.Error(w, "bad response from agent", http.StatusBadGateway)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		copyHeader(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)

		duration := time.Since(start).Milliseconds()
		clientIP := r.RemoteAddr
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			clientIP = strings.Split(xff, ",")[0]
		}
		eventData := map[string]any{
			"host":        host,
			"method":      r.Method,
			"path":        r.URL.Path,
			"status_code": resp.StatusCode,
			"duration_ms": duration,
			"client_ip":   clientIP,
			"timestamp":   time.Now().Format("15:04:05"),
		}
		if b, err := json.Marshal(eventData); err == nil && s.tunnelUsecase != nil {
			go func() {
				defer func() {
					if rec := recover(); rec != nil {
						s.logger.Error("panic in publish inspect event", zap.Any("recover", rec))
					}
				}()
				ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 2*time.Second)
				defer cancel()
				_ = s.tunnelUsecase.PublishInspectEvent(ctx, host, string(b))
			}()
		}
		return
	}

	// --- jika TCP / Minecraft: relay langsung ---
	s.logger.Info("new raw TCP/Minecraft tunnel", zap.String("host", host), zap.String("mode", mode))
	hij, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	conn, _, err := hij.Hijack()
	if err != nil {
		http.Error(w, "hijack failed", http.StatusInternalServerError)
		return
	}

	if r.Method == "CONNECT" || strings.ToLower(r.Header.Get("Upgrade")) == "tcp" {
		_, _ = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n")
	}

	if mode == "minecraft-proxy" {
		clientIP := r.RemoteAddr
		clientPort := 0
		if xff := r.Header.Get("X-Real-IP"); xff != "" {
			clientIP = xff
			if portStr := r.Header.Get("X-Real-Port"); portStr != "" {
				if p, err := strconv.Atoi(portStr); err == nil {
					clientPort = p
				}
			}
		} else if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			clientIP = strings.Split(xff, ",")[0]
		}

		clientHost, clientPortStr, _ := net.SplitHostPort(clientIP)
		if clientHost == "" {
			clientHost = clientIP
		} else if clientPort == 0 {
			if p, err := strconv.Atoi(clientPortStr); err == nil {
				clientPort = p
			}
		}

		if clientPort <= 0 || clientPort > 65535 {
			if _, remPortStr, remErr := net.SplitHostPort(r.RemoteAddr); remErr == nil {
				if rp, err := strconv.Atoi(remPortStr); err == nil && rp > 0 && rp <= 65535 {
					clientPort = rp
				}
			}
			if clientPort <= 0 || clientPort > 65535 {
				clientPort = 54321
			}
		}

		proto := "TCP4"
		dstIP := "127.0.0.1"
		if ip := net.ParseIP(clientHost); ip != nil {
			if ip.To4() != nil {
				proto = "TCP4"
				dstIP = "127.0.0.1"
				clientHost = ip.To4().String()
			} else if ip.To16() != nil {
				proto = "TCP6"
				dstIP = "::1"
				clientHost = ip.To16().String()
			}
		} else {
			clientHost = "127.0.0.1"
		}

		proxyLine := fmt.Sprintf("PROXY %s %s %s %d 25565\r\n", proto, clientHost, dstIP, clientPort)
		_, _ = io.WriteString(stream, proxyLine)
	}

	go func() {
		_, _ = io.Copy(stream, conn)
		_ = stream.Close()
	}()
	_, _ = io.Copy(conn, stream)
	_ = conn.Close()
}

func (s *Server) updateState(ts *TunnelSession) {
	if s.tunnelUsecase == nil {
		return
	}
	var hosts []string
	for h := range ts.Hostnames {
		hosts = append(hosts, h)
	}
	info := domainTunnel.TunnelInfo{
		Name:        ts.ClientName,
		ClientName:  ts.Username,
		Hosts:       hosts,
		ConnectedAt: ts.Connected,
		LastPing:    time.Now(),
	}
	sessionID := fmt.Sprintf("%p", ts)
	if err := s.tunnelUsecase.RegisterTunnel(context.Background(), sessionID, info); err != nil {
		s.logger.Error("failed to update tunnel state in store", zap.Error(err))
	}
	if len(hosts) > 0 {
		if err := s.tunnelUsecase.RefreshActiveDomains(context.Background(), hosts, sessionID, 3*time.Minute); err != nil {
			s.logger.Warn("failed to refresh active domains ttl", zap.Error(err))
		}
	}
}

// client listening.
func (s *Server) ListenTunnelTLS(addr string, tlsCfg *tls.Config) (net.Listener, error) {
	ln, err := tls.Listen("tcp", addr, tlsCfg)
	if err != nil {
		return nil, err
	}
	s.logger.Info("[edge] tunnel TLS listening", zap.String("addr", addr))

	go s.serveListener(ln)
	return ln, nil
}

func (s *Server) serveListener(ln net.Listener) {
	defer func() { _ = recover() }()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "use of closed network connection") {
				break
			}
			s.logger.Error("[edge] accept tunnel", zap.Error(err))
			continue
		}

		go func(c net.Conn) {
			defer func() { _ = recover() }()
			s.handleClientConn(c)
		}(conn)
	}
}

func (s *Server) activeTunnelsForUser(username string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	uniqueSessions := make(map[*yamux.Session]struct{})
	for _, ts := range s.hostToSes {
		if ts.Username == username {
			uniqueSessions[ts.Session] = struct{}{}
		}
	}
	return len(uniqueSessions)
}

func (s *Server) handleClientConn(conn net.Conn) {
	session, _ := yamux.Server(conn, nil)
	ip := conn.RemoteAddr().String()
	s.logger.Info("new tunnel", zap.String("addr", ip))

	// Control stream: pertama harus REGISTER
	ctrl, err := session.AcceptStream()
	if err != nil {
		s.logger.Error("[edge] no control stream", zap.Error(err))
		_ = session.Close()
		return
	}

	// REGISTER
	msg, err := protocol.ReadJSON(ctrl)
	if err != nil {
		s.logger.Error("[edge] read register", zap.Error(err))
		_ = session.Close()
		return
	}
	typ, _ := protocol.GetString(msg, "type")
	if typ != protocol.MsgTypeRegister {
		s.logger.Warn("[edge] first msg not register")
		_ = session.Close()
		return
	}
	authToken, _ := protocol.GetString(msg, "auth_token")
	clientID, _ := protocol.GetString(msg, "client_id")
	clientName, _ := protocol.GetString(msg, "client_name")
	if clientName == "" {
		clientName = clientID // fallback
	}

	user, err := s.verifyAuthToken(authToken)
	if err != nil {
		s.logger.Warn("[edge] auth failed", zap.String("client_name", clientName), zap.Error(err))
		_ = protocol.SendJSON(ctrl, protocol.AckMessage{Type: protocol.MsgTypeAck, OK: false, Error: "auth failed"})
		_ = session.Close()
		return
	}

	maxActive := s.settingUsecase.GetMaxTunnelsPerUser(context.Background(), 5)
	if s.activeTunnelsForUser(user.Username) >= maxActive {
		s.logger.Warn("[edge] max active tunnels limit reached", zap.String("username", user.Username))
		_ = protocol.SendJSON(ctrl, protocol.AckMessage{Type: protocol.MsgTypeAck, OK: false, Error: "max active tunnels limit reached"})
		_ = session.Close()
		return
	}

	rawRoutes, ok := msg["routes"].(map[string]any)
	if !ok || len(rawRoutes) == 0 {
		_ = protocol.SendJSON(ctrl, protocol.AckMessage{Type: protocol.MsgTypeAck, OK: false, Error: "no routes"})
		_ = session.Close()
		return
	}

	ts := &TunnelSession{
		Session:    session,
		ClientName: clientName,
		Username:   user.Username,
		Role:       user.Role,
		Hostnames:  map[string]struct{}{},
		Modes:      map[string]string{},
		Ctrl:       ctrl,
		ClientIP:   ip,
		Connected:  time.Now(),
	}

	rawModes := map[string]string{}
	if m, ok := msg["modes"].(map[string]any); ok {
		for hn, modeVal := range m {
			if modeStr, ok := modeVal.(string); ok && modeStr != "" {
				rawModes[hn] = strings.ToLower(modeStr)
			}
		}
	}
	getMode := func(host string) string {
		if mode, ok := rawModes[host]; ok && mode != "" {
			return mode
		}
		return "http"
	}

	s.mu.Lock()
	var (
		addedHosts []string
		conflict   string
	)
RouteLoop:
	for hn := range rawRoutes {
		// 1. Check if it's a system domain (Dashboard/Gateway)
		switch {
		case hn == s.dashboardDomain:
			// Allowed automatically
		case s.tunnelUsecase != nil:
			// 2. Check Database allowlist based on RBAC (Admin or specific User)
			allowed, err := s.tunnelUsecase.IsDomainAllowed(context.Background(), hn, user.ID, user.Role)
			if err != nil || !allowed {
				conflict = hn + " (not authorized or you do not own this domain)"
				break RouteLoop
			}
		default:
			// No domain store and not dashboard domain
			conflict = hn + " (no authorization store)"
			break RouteLoop
		}

		// 3. Check if already active locally
		if _, exists := s.hostToSes[hn]; exists {
			conflict = hn
			break RouteLoop
		}
		if s.hostRegistry != nil && !s.hostRegistry.Register(hn) {
			conflict = hn
			break RouteLoop
		}

		// 4. Check if already active globally (Redis Active Lock)
		if s.tunnelUsecase != nil {
			err := s.tunnelUsecase.SetActiveDomain(context.Background(), hn, fmt.Sprintf("%p", ts))
			if err != nil {
				// Unlock locally registered memory before breaking
				if s.hostRegistry != nil {
					s.hostRegistry.Unregister(hn)
				}
				conflict = hn + " (domain is currently actively tunneled)"
				break
			}
		}
		ts.Hostnames[hn] = struct{}{}
		ts.Modes[hn] = getMode(hn)
		s.hostToSes[hn] = ts
		addedHosts = append(addedHosts, hn)
		s.logger.Info("[edge] registered host: "+hn+"->"+ip, zap.String("addr", ip))
	}
	if conflict != "" {
		for _, hn := range addedHosts {
			delete(ts.Hostnames, hn)
			delete(ts.Modes, hn)
			if cur, ok := s.hostToSes[hn]; ok && cur == ts {
				delete(s.hostToSes, hn)
			}
			if s.hostRegistry != nil {
				s.hostRegistry.Unregister(hn)
			}
			if s.tunnelUsecase != nil {
				_ = s.tunnelUsecase.RemoveActiveDomain(context.Background(), hn)
			}
		}
		s.mu.Unlock()
		_ = protocol.SendJSON(ctrl, protocol.AckMessage{Type: protocol.MsgTypeAck, OK: false, Error: "host already registered: " + conflict})
		_ = session.Close()
		return
	}
	s.mu.Unlock()

	if user.Role != 1 && user.Username != "" && s.settingUsecase != nil && s.tunnelUsecase != nil {
		if val, err := s.settingUsecase.GetSetting(context.Background(), "rate_limit_enabled:"+user.Username); err == nil && val != "" {
			_ = s.tunnelUsecase.SetRateLimitSetting(context.Background(), user.Username, val)
		}
	}

	s.updateState(ts)

	_ = protocol.SendJSON(ctrl, protocol.AckMessage{Type: protocol.MsgTypeAck, OK: true})

	// Heartbeat: server → ping; client balas → pong
	go func() {
		defer func() { _ = recover() }()
		hb := s.heartbeatInterval
		if hb == 0 {
			hb = 15 * time.Second
		}
		ticker := time.NewTicker(hb)
		defer ticker.Stop()
		for range ticker.C {
			if err := protocol.SendJSON(ctrl, protocol.PingMessage{Type: protocol.MsgTypePing, Ts: protocol.NowMillis()}); err != nil {
				s.logger.Error("[edge] ping err", zap.Error(err))
				_ = session.Close() // trigger cleanup
				return
			}
			_ = ctrl.SetReadDeadline(time.Now().Add(20 * time.Second))
			m, err := protocol.ReadJSON(ctrl)
			if err != nil {
				s.logger.Error("[edge] read pong err", zap.Error(err))
				_ = session.Close()
				return
			}
			t, _ := protocol.GetString(m, "type")
			if t != protocol.MsgTypePong {
				s.logger.Warn("[edge] expected pong, got: " + t)
				_ = session.Close()
				return
			}
			_ = ctrl.SetReadDeadline(time.Time{})
			s.updateState(ts)
		}
	}()

	// Tunggu sampai session tutup → bersihkan mapping
	go func() {
		defer func() { _ = recover() }()
		<-session.CloseChan()
		s.logger.Warn("[edge] session closed", zap.String("addr", ip))
		s.cleanup(ts)
	}()
}

func (s *Server) cleanup(ts *TunnelSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for hn := range ts.Hostnames {
		cur, ok := s.hostToSes[hn]
		if !ok || cur != ts {
			continue
		}
		delete(s.hostToSes, hn)
		if s.hostRegistry != nil {
			s.hostRegistry.Unregister(hn)
		}
		if s.tunnelUsecase != nil {
			_ = s.tunnelUsecase.RemoveActiveDomain(context.Background(), hn)
		}
		delete(ts.Modes, hn)
		s.logger.Info("[edge] deregistered host", zap.String("host", hn))
	}
	if s.tunnelUsecase != nil {
		_ = s.tunnelUsecase.UnregisterTunnel(context.Background(), fmt.Sprintf("%p", ts))
	}
	if ts.Role != 1 && ts.Username != "" && s.tunnelUsecase != nil {
		hasRemaining := false
		for _, cur := range s.hostToSes {
			if cur != nil && cur.Username == ts.Username {
				hasRemaining = true
				break
			}
		}
		if !hasRemaining {
			_ = s.tunnelUsecase.DeleteRateLimitSetting(context.Background(), ts.Username)
		}
	}
}

// StartupCleanup purges any stale tunnel sessions and active domain locks from previous server runs.
func (s *Server) StartupCleanup(ctx context.Context) {
	if s.tunnelUsecase != nil {
		s.logger.Info("[edge] performing startup cleanup of stale tunnels and domains")
		if err := s.tunnelUsecase.FlushAllTunnelsAndDomains(ctx); err != nil {
			s.logger.Warn("[edge] startup cleanup failed", zap.Error(err))
		}
	}
}

// Shutdown gracefully closes all active tunnel sessions and unregisters them from storage.
func (s *Server) Shutdown(ctx context.Context) {
	s.mu.Lock()
	sessions := make([]*TunnelSession, 0, len(s.hostToSes))
	for _, ts := range s.hostToSes {
		if ts != nil {
			sessions = append(sessions, ts)
		}
	}
	s.mu.Unlock()

	for _, ts := range sessions {
		if ts.Session != nil {
			_ = ts.Session.Close()
		}
		s.cleanup(ts)
	}

	if s.tunnelUsecase != nil {
		_ = s.tunnelUsecase.FlushAllTunnelsAndDomains(ctx)
	}
}

func (s *Server) sessionForHost(host string) *TunnelSession {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Exact match
	if ts, ok := s.hostToSes[host]; ok {
		return ts
	}

	// Wildcard match
	parts := strings.SplitN(host, ".", 2)
	if len(parts) == 2 {
		wildcard := "*." + parts[1]
		if ts, ok := s.hostToSes[wildcard]; ok {
			return ts
		}
	}

	return nil
}

func (ts *TunnelSession) modeForHost(host string) string {
	if ts == nil {
		return "http"
	}
	if ts.Modes != nil {
		// Exact match
		if mode, ok := ts.Modes[host]; ok && mode != "" {
			return mode
		}
		// Wildcard match
		parts := strings.SplitN(host, ".", 2)
		if len(parts) == 2 {
			wildcard := "*." + parts[1]
			if mode, ok := ts.Modes[wildcard]; ok && mode != "" {
				return mode
			}
		}
	}
	return "http"
}

func (s *Server) verifyAuthToken(providedToken string) (*domainUser.User, error) {
	user, err := s.authUsecase.VerifyToken(context.Background(), providedToken)
	if err != nil {
		return nil, fmt.Errorf("invalid auth token: %w", err)
	}

	return user, nil
}

func copyHeader(dst, src http.Header) {
	for k, v := range src {
		for _, vv := range v {
			dst.Add(k, vv)
		}
	}
}

func canonicalHost(hostport string) string {
	hostport = strings.TrimSpace(hostport)
	if hostport == "" {
		return ""
	}
	if strings.Contains(hostport, ":") {
		if h, _, err := net.SplitHostPort(hostport); err == nil {
			hostport = h
		}
	}
	return strings.ToLower(hostport)
}
