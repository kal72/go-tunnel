package server

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"gotunnel/internal/protocol"
	"gotunnel/internal/registry"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hashicorp/yamux"
	"go.uber.org/zap"
)

type TunnelSession struct {
	Session   *yamux.Session
	Hostnames map[string]struct{}
	Modes     map[string]string
	Ctrl      *yamux.Stream
	ClientIP  string
	Connected time.Time
}

type Server struct {
	jwtSecret    []byte
	logger       *zap.Logger
	hostRegistry *registry.HostRegistry

	// host -> session
	mu        sync.RWMutex
	hostToSes map[string]*TunnelSession

	// dashboard cache
	dashMu  sync.RWMutex
	summary []dashItem
}

type dashItem struct {
	Client      string
	Hosts       string
	ConnectedAt string
	LastPing    string
}

func NewServerJWT(jwtSecret string, hostRegistry *registry.HostRegistry) (*Server, error) {
	logger, _ := zap.NewProduction()
	return &Server{
		jwtSecret:    []byte(jwtSecret),
		hostToSes:    map[string]*TunnelSession{},
		logger:       logger,
		hostRegistry: hostRegistry,
	}, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	ses := s.sessionForHost(host)
	if ses == nil {
		http.Error(w, "no tunnel for host", http.StatusBadGateway)
		return
	}
	mode := ses.modeForHost(host)

	stream, err := ses.Session.OpenStream()
	if err != nil {
		http.Error(w, "open stream failed", http.StatusBadGateway)
		return
	}
	defer stream.Close()

	// Header biner: hostname
	if err := protocol.WriteDataHeader(stream, host); err != nil {
		http.Error(w, "write header failed", http.StatusBadGateway)
		return
	}

	// --- jika HTTP (default): kirim HTTP request ---
	if mode != "tcp" {
		if err := r.Write(stream); err != nil {
			http.Error(w, "write req failed", http.StatusBadGateway)
			return
		}
		resp, err := http.ReadResponse(bufio.NewReader(stream), r)
		if err != nil {
			http.Error(w, "bad response from agent", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		copyHeader(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
		return
	}

	// --- jika TCP: relay langsung ---
	s.logger.Info("new raw TCP tunnel", zap.String("host", host))
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
	go func() {
		io.Copy(stream, conn)
		stream.Close()
	}()
	io.Copy(conn, stream)
	conn.Close()
}

func (s *Server) DashboardHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.refreshDashboard()
		s.dashMu.RLock()
		defer s.dashMu.RUnlock()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<html><head><title>Tunnel Dashboard</title><style>
		body{font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif;padding:24px}
		table{border-collapse:collapse;width:100%}
		th,td{border:1px solid #ddd;padding:8px}
		th{background:#f3f4f6;text-align:left}
		</style></head><body>`)
		fmt.Fprint(w, "<h1>Active Tunnels</h1><table><tr><th>Client</th><th>Hosts</th><th>Connected</th><th>Last Ping</th></tr>")
		for _, it := range s.summary {
			fmt.Fprintf(w, "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>",
				html(it.Client), html(it.Hosts), html(it.ConnectedAt), html(it.LastPing))
		}
		fmt.Fprint(w, "</table></body></html>")
	})
}

func html(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "&", "&amp;"), "<", "&lt;")
}

func (s *Server) refreshDashboard() {
	s.dashMu.Lock()
	defer s.dashMu.Unlock()

	var out []dashItem
	s.mu.RLock()
	for hn, ses := range s.hostToSes {
		_ = hn // we’ll aggregate per session
		_ = ses
	}
	// Aggregate per session:
	type key struct{ ptr *TunnelSession }
	uniq := map[*TunnelSession][]string{}
	for hn, ses := range s.hostToSes {
		uniq[ses] = append(uniq[ses], hn)
	}
	for ses, hosts := range uniq {
		out = append(out, dashItem{
			Client:      ses.ClientIP,
			Hosts:       strings.Join(hosts, ", "),
			ConnectedAt: ses.Connected.Format(time.RFC3339),
			LastPing:    "~15s", // simple static info; could be tracked precisely
		})
	}
	s.mu.RUnlock()
	s.summary = out
}

// client listening
func (s *Server) ListenTunnelTLS(addr string, tlsCfg *tls.Config) (net.Listener, error) {
	ln, err := tls.Listen("tcp", addr, tlsCfg)
	if err != nil {
		return nil, err
	}
	s.logger.Info("[edge] tunnel TLS listening", zap.String("addr", addr))

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				s.logger.Error("[edge] accept tunnel", zap.Error(err))
				continue
			}
			go s.handleClientConn(conn)
		}
	}()
	return ln, nil
}

func (s *Server) handleClientConn(conn net.Conn) {
	ip := conn.RemoteAddr().String()
	s.logger.Info("new tunnel", zap.String("addr", ip))

	session, err := yamux.Server(conn, nil)
	if err != nil {
		s.logger.Error("[edge] yamux server", zap.Error(err))
		conn.Close()
		return
	}

	// Control stream: pertama harus REGISTER
	ctrl, err := session.AcceptStream()
	if err != nil {
		s.logger.Error("[edge] no control stream", zap.Error(err))
		session.Close()
		return
	}

	// REGISTER
	msg, err := protocol.ReadJSON(ctrl)
	if err != nil {
		s.logger.Error("[edge] read register", zap.Error(err))
		session.Close()
		return
	}
	typ, _ := protocol.GetString(msg, "type")
	if typ != protocol.MsgTypeRegister {
		s.logger.Warn("[edge] first msg not register")
		session.Close()
		return
	}
	tokenStr, _ := protocol.GetString(msg, "token")
	if err := s.verifyJWT(tokenStr); err != nil {
		_ = protocol.SendJSON(ctrl, protocol.AckMessage{Type: protocol.MsgTypeAck, OK: false, Error: "auth failed"})
		session.Close()
		return
	}
	rawRoutes, ok := msg["routes"].(map[string]any)
	if !ok || len(rawRoutes) == 0 {
		_ = protocol.SendJSON(ctrl, protocol.AckMessage{Type: protocol.MsgTypeAck, OK: false, Error: "no routes"})
		session.Close()
		return
	}

	ts := &TunnelSession{
		Session:   session,
		Hostnames: map[string]struct{}{},
		Modes:     map[string]string{},
		Ctrl:      ctrl,
		ClientIP:  ip,
		Connected: time.Now(),
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
	for hn := range rawRoutes {
		if _, exists := s.hostToSes[hn]; exists {
			conflict = hn
			break
		}
		if s.hostRegistry != nil && !s.hostRegistry.Add(hn) {
			conflict = hn
			break
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
				s.hostRegistry.Remove(hn)
			}
		}
		s.mu.Unlock()
		_ = protocol.SendJSON(ctrl, protocol.AckMessage{Type: protocol.MsgTypeAck, OK: false, Error: fmt.Sprintf("host already registered: %s", conflict)})
		session.Close()
		return
	}
	s.mu.Unlock()

	_ = protocol.SendJSON(ctrl, protocol.AckMessage{Type: protocol.MsgTypeAck, OK: true})

	// Heartbeat: server → ping; client balas → pong
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if err := protocol.SendJSON(ctrl, protocol.PingMessage{Type: protocol.MsgTypePing, Ts: protocol.NowMillis()}); err != nil {
				s.logger.Error("[edge] ping err", zap.Error(err))
				session.Close() // trigger cleanup
				return
			}
			_ = ctrl.SetReadDeadline(time.Now().Add(20 * time.Second))
			m, err := protocol.ReadJSON(ctrl)
			if err != nil {
				s.logger.Error("[edge] read pong err", zap.Error(err))
				session.Close()
				return
			}
			t, _ := protocol.GetString(m, "type")
			if t != protocol.MsgTypePong {
				s.logger.Warn("[edge] expected pong, got: " + t)
				session.Close()
				return
			}
			_ = ctrl.SetReadDeadline(time.Time{})
		}
	}()

	// Tunggu sampai session tutup → bersihkan mapping
	go func() {
		defer func() { _ = recover() }()
		if session == nil {
			return
		}
		<-session.CloseChan()
		s.logger.Warn("[edge] session closed", zap.String("addr", ip))
		s.cleanup(ts)
	}()
}

// func (s *Server) handleClientTunnel(conn net.Conn, hostRegistry *registry.HostRegistry) {
// 	defer conn.Close()

// 	// baca handshake sederhana dari client
// 	buf := make([]byte, 1024)
// 	n, _ := conn.Read(buf)
// 	req := string(buf[:n])

// 	// format handshake sederhana: "DOMAIN:app.vpskamu.com"
// 	if strings.HasPrefix(req, "DOMAIN:") {
// 		domain := strings.TrimSpace(strings.TrimPrefix(req, "DOMAIN:"))
// 		log.Printf("[client] registered domain: %s", domain)
// 		hostRegistry.Add(domain)
// 		conn.Write([]byte("OK\n"))
// 	} else {
// 		conn.Write([]byte("ERR\n"))
// 	}
// }

func (s *Server) cleanup(ts *TunnelSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for hn := range ts.Hostnames {
		if cur, ok := s.hostToSes[hn]; ok && cur == ts {
			delete(s.hostToSes, hn)
			if s.hostRegistry != nil {
				s.hostRegistry.Remove(hn)
			}
			delete(ts.Modes, hn)
			s.logger.Info("[edge] deregistered host", zap.String("host", hn))
		}
	}
}

func (s *Server) sessionForHost(host string) *TunnelSession {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.hostToSes[host]
}

func (ts *TunnelSession) modeForHost(host string) string {
	if ts == nil {
		return "http"
	}
	if ts.Modes != nil {
		if mode, ok := ts.Modes[host]; ok && mode != "" {
			return mode
		}
	}
	return "http"
}

func (s *Server) verifyJWT(tokenStr string) error {
	_, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return s.jwtSecret, nil
	})
	return err
}

func copyHeader(dst, src http.Header) {
	for k, v := range src {
		for _, vv := range v {
			dst.Add(k, vv)
		}
	}
}
