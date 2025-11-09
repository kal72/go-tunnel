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

	"github.com/golang-jwt/jwt/v5"
	"github.com/hashicorp/yamux"
	"go.uber.org/zap"
)

type TunnelSession struct {
	Session   *yamux.Session
	Hostnames map[string]struct{}
	Ctrl      *yamux.Stream
	ClientIP  string
	Connected time.Time
}

type Server struct {
	jwtSecret []byte
	logger    *zap.Logger

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

func NewServerJWT(jwtSecret string) (*Server, error) {
	logger, _ := zap.NewProduction()
	return &Server{
		jwtSecret: []byte(jwtSecret),
		hostToSes: map[string]*TunnelSession{},
		logger:    logger,
	}, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	ses := s.sessionForHost(host)
	if ses == nil {
		http.Error(w, "no tunnel for host", http.StatusBadGateway)
		return
	}

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
	if strings.HasSuffix(host, ".http") { // contoh mode deteksi, opsional
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

func (s *Server) ListenTunnelTLS(addr string, tlsCfg *tls.Config) error {
	ln, err := tls.Listen("tcp", addr, tlsCfg)
	if err != nil {
		return err
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
	return nil
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
		Ctrl:      ctrl,
		ClientIP:  ip,
		Connected: time.Now(),
	}

	s.mu.Lock()
	for hn := range rawRoutes {
		ts.Hostnames[hn] = struct{}{}
		s.hostToSes[hn] = ts
		s.logger.Info("[edge] registered host: "+hn+"->"+ip, zap.String("addr", ip))
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

func (s *Server) cleanup(ts *TunnelSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for hn := range ts.Hostnames {
		if cur, ok := s.hostToSes[hn]; ok && cur == ts {
			delete(s.hostToSes, hn)
		}
	}
}

func (s *Server) sessionForHost(host string) *TunnelSession {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.hostToSes[host]
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
