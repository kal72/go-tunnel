package server

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"gotunnel/internal/tunnel/protocol"
	"gotunnel/internal/tunnel/registry"
	"gotunnel/internal/tunnel/state"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

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

	dashboardDomain string
	store           state.Store
}

type dashItem struct {
	Client      string
	Hosts       string
	ConnectedAt string
	LastPing    string
}

func NewServerJWT(jwtSecret string, hostRegistry *registry.HostRegistry, serverDomain string, store state.Store) (*Server, error) {
	logger, _ := zap.NewProduction()
	return &Server{
		jwtSecret:       []byte(jwtSecret),
		hostToSes:       map[string]*TunnelSession{},
		logger:          logger,
		hostRegistry:    hostRegistry,
		dashboardDomain: canonicalHost(serverDomain),
		store:           store,
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

func (s *Server) updateState(ts *TunnelSession) {
	if s.store == nil {
		return
	}
	var hosts []string
	for h := range ts.Hostnames {
		hosts = append(hosts, h)
	}
	info := state.TunnelInfo{
		Client:      ts.ClientIP,
		Hosts:       hosts,
		ConnectedAt: ts.Connected,
		LastPing:    time.Now(),
	}
	if err := s.store.SetTunnel(context.Background(), fmt.Sprintf("%p", ts), info); err != nil {
		s.logger.Error("failed to update tunnel state in store", zap.Error(err))
	}
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
	authToken, _ := protocol.GetString(msg, "auth_token")
	clientID, _ := protocol.GetString(msg, "client_id")

	if err := s.verifyAuthToken(authToken, clientID); err != nil {
		s.logger.Warn("[edge] auth failed", zap.String("client_id", clientID), zap.Error(err))
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

	s.updateState(ts)

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
			s.updateState(ts)
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
			if s.hostRegistry != nil {
				s.hostRegistry.Remove(hn)
			}
			delete(ts.Modes, hn)
			s.logger.Info("[edge] deregistered host", zap.String("host", hn))
		}
	}
	if s.store != nil {
		_ = s.store.DeleteTunnel(context.Background(), fmt.Sprintf("%p", ts))
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

func (s *Server) verifyAuthToken(providedToken string, clientID string) error {
	if clientID == "" {
		return fmt.Errorf("client_id required")
	}

	// Derive expected token: HMAC-SHA256(MasterSecret, ClientID)
	h := hmac.New(sha256.New, s.jwtSecret)
	h.Write([]byte(clientID))
	expected := fmt.Sprintf("%x", h.Sum(nil))

	if providedToken != expected {
		return fmt.Errorf("invalid auth token")
	}
	return nil
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
