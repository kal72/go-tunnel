package client

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/yamux"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	clientconfig "gotunnel/internal/client/config"
	"gotunnel/internal/shared/protocol"
)

type Client struct {
	cfg    *clientconfig.TunnelClientConfig
	logger *zap.Logger
	routes map[string]string // hostname -> target
	modes  map[string]string
}

func NewClient(cfg *clientconfig.TunnelClientConfig) *Client {
	r := make(map[string]string, len(cfg.Tunnels))
	m := make(map[string]string)
	for _, t := range cfg.Tunnels {
		r[t.Hostname] = t.Target
		mode := t.Mode
		if mode == "" {
			mode = "http"
		}
		m[t.Hostname] = mode
	}

	zapCfg := zap.NewProductionConfig()
	zapCfg.Encoding = "console"
	zapCfg.DisableStacktrace = true
	zapCfg.DisableCaller = true
	zapCfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	zapCfg.EncoderConfig.EncodeTime = zapcore.RFC3339TimeEncoder

	logger, _ := zapCfg.Build()
	return &Client{cfg: cfg, routes: r, modes: m, logger: logger}
}

func (c *Client) RunForever() {
	backoff := 1 * time.Second
	maxBackoff := 30 * time.Second

	for {
		start := time.Now()
		if err := c.runOnce(); err != nil {
			c.logger.Error("[agent] tunnel error", zap.Error(err))
		}

		if time.Since(start) > 30*time.Second {
			backoff = 1 * time.Second
		}

		n, _ := rand.Int(rand.Reader, big.NewInt(int64(backoff/2+1)))
		jitter := time.Duration(n.Int64())
		sleepDuration := backoff + jitter

		c.logger.Info("[agent] reconnecting after backoff", zap.Duration("sleep", sleepDuration))
		time.Sleep(sleepDuration)

		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

func (c *Client) runOnce() error {
	// ServerName must match the public tunnel endpoint (SERVER_DOMAIN) so the
	// server-side HostPolicy allows the TLS handshake before routes register.
	serverName := hostOnly(c.cfg.TunnelAddr)

	tlsCfg := &tls.Config{
		InsecureSkipVerify: c.cfg.SkipTLSVerify,
		// Penting: gunakan SNI agar cocok dengan cert ACME (ambil dari hostname tunnel)
		ServerName: serverName,
	}

	c.logger.Info("[agent] connecting to", zap.String("server", c.cfg.TunnelAddr))

	dialAddr := c.cfg.TunnelAddr
	if !strings.Contains(dialAddr, ":") {
		dialAddr += ":443"
	}

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{
			Timeout: 30 * time.Second,
		},
		Config: tlsCfg,
	}
	conn, err := dialer.DialContext(context.Background(), "tcp", dialAddr)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	sess, err := yamux.Client(conn, nil)
	if err != nil {
		return err
	}

	// Control stream
	ctrl, err := sess.OpenStream()
	if err != nil {
		return err
	}

	// Use token provided in config
	token := c.cfg.AuthToken

	// REGISTER
	if err := protocol.SendJSON(ctrl, protocol.RegisterMessage{
		Type:       protocol.MsgTypeRegister,
		ClientID:   c.cfg.ClientID,
		ClientName: c.cfg.ClientName,
		AuthToken:  token,
		Routes:     c.routes,
		Modes:      c.modes,
	}); err != nil {
		return err
	}
	ack, err := protocol.ReadJSON(ctrl)
	if err != nil {
		return err
	}
	if ok, _ := ack["ok"].(bool); !ok {
		return fmt.Errorf("register rejected: %v", ack["error"])
	}
	c.logger.Info("registered routes", zap.Any("routes", c.routes))

	// Heartbeat: baca ping → balas pong
	go func() {
		for {
			m, err := protocol.ReadJSON(ctrl)
			if err != nil {
				c.logger.Error("[agent] ctrl read", zap.Error(err))
				_ = sess.Close()
				return
			}
			t, _ := protocol.GetString(m, "type")
			if t == protocol.MsgTypePing {
				_ = protocol.SendJSON(ctrl, protocol.PongMessage{Type: protocol.MsgTypePong, Ts: protocol.NowMillis()})
			}
		}
	}()

	// Data streams
	for {
		s, err := sess.AcceptStream()
		if err != nil {
			return err
		}
		go c.handleDataStream(s)
	}
}

func (c *Client) handleDataStream(stream *yamux.Stream) {
	defer func() { _ = stream.Close() }()

	hostname, err := protocol.ReadDataHeader(stream)
	if err != nil {
		c.logger.Error("read header", zap.Error(err))
		writeHTTPError(stream, http.StatusBadGateway, "bad tunnel header")
		return
	}

	target, ok := c.routes[hostname]
	if !ok {
		writeHTTPError(stream, http.StatusBadGateway, "no route for hostname")
		return
	}

	mode := c.modes[hostname]
	if mode == "tcp" || mode == "tcp-proxy" || mode == "minecraft-proxy" {
		c.handleTCPStream(stream, target)
		return
	}

	// Default HTTP mode
	if mode == "https" {
		c.handleHTTPSStream(stream, target)
		return
	}
	c.handleHTTPStream(stream, target)

}

func (c *Client) handleHTTPSStream(stream *yamux.Stream, target string) {
	defer func() { _ = stream.Close() }()
	reader := bufio.NewReader(stream)

	// Extract host without port for Host header.
	targetHost := target
	if h, _, err := net.SplitHostPort(target); err == nil {
		targetHost = h
	} else {
		// No port specified — default to 443 for HTTPS.
		target += ":443"
	}

	// Use http.Client so redirects (e.g. google.com → www.google.com)
	// are followed internally instead of being sent back to the browser.
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: c.cfg.SkipTLSVerify,
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}

	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				c.logger.Error("read https request", zap.Error(err))
			}
			return
		}

		// Upstream must see its own Host to serve the right content.
		req.URL.Scheme = "https"
		req.URL.Host = target
		req.Host = targetHost
		req.RequestURI = ""

		resp, err := client.Do(req)
		if err != nil {
			c.logger.Error("https proxy error", zap.Error(err))
			writeHTTPError(stream, http.StatusBadGateway, "upstream error: "+err.Error())
			return
		}

		if err := resp.Write(stream); err != nil {
			c.logger.Error("write response", zap.Error(err))
			_ = resp.Body.Close()
			return
		}
		_ = resp.Body.Close()

		if req.Close || resp.Close {
			return
		}
	}
}

func writeHTTPError(w io.Writer, code int, msg string) {
	status := fmt.Sprintf("HTTP/1.1 %d %s\r\n", code, http.StatusText(code))
	body := []byte(msg)
	headers := fmt.Sprintf("Content-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", len(body))
	_, _ = io.WriteString(w, status)
	_, _ = io.WriteString(w, headers)
	_, _ = w.Write(body)
}

func hostOnly(addr string) string {
	// addr in "host:port"
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i]
		}
	}
	return addr
}

func formatTarget(target string) string {
	if !strings.Contains(target, ":") && target != "" {
		return "127.0.0.1:" + target
	}
	return target
}

func (c *Client) handleTCPStream(stream *yamux.Stream, target string) {
	target = formatTarget(target)
	dialer := &net.Dialer{Timeout: 30 * time.Second}
	local, err := dialer.DialContext(context.Background(), "tcp", target)
	if err != nil {
		c.logger.Error("dial tcp target", zap.Error(err), zap.String("target", target))
		return
	}
	defer func() { _ = local.Close() }()

	bufA := make([]byte, 32*1024)
	bufB := make([]byte, 32*1024)

	go func() {
		_, _ = io.CopyBuffer(local, stream, bufA)
		_ = local.Close()
	}()
	_, _ = io.CopyBuffer(stream, local, bufB)
}

func (c *Client) handleHTTPStream(stream *yamux.Stream, target string) {
	target = formatTarget(target)
	dialer := &net.Dialer{Timeout: 30 * time.Second}
	local, err := dialer.DialContext(context.Background(), "tcp", target)
	if err != nil {
		c.logger.Error("dial local http", zap.Error(err))
		writeHTTPError(stream, http.StatusServiceUnavailable, "cannot reach local target")
		return
	}
	defer func() { _ = local.Close() }()

	bufA := make([]byte, 32*1024)
	bufB := make([]byte, 32*1024)

	go func() {
		_, _ = io.CopyBuffer(local, stream, bufA)
		_ = local.Close()
	}()
	_, _ = io.CopyBuffer(stream, local, bufB)
}
