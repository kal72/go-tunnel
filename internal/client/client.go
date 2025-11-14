package client

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"gotunnel/internal/config"
	"gotunnel/internal/protocol"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hashicorp/yamux"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type Client struct {
	cfg    *config.ClientConfig
	logger *zap.Logger
	routes map[string]string // hostname -> target
	modes  map[string]string
}

func NewClient(cfg *config.ClientConfig) *Client {
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
	for {
		if err := c.runOnce(); err != nil {
			c.logger.Error("[agent] tunnel error", zap.Error(err))
		}
		time.Sleep(2 * time.Second)
	}
}

func (c *Client) runOnce() error {
	serverName := hostOnly(c.cfg.TunnelAddr)
	if sni := c.preferredSNIHost(); sni != "" {
		serverName = sni
	}

	tlsCfg := &tls.Config{
		InsecureSkipVerify: c.cfg.SkipTLSVerify,
		// Penting: gunakan SNI agar cocok dengan cert ACME (ambil dari hostname tunnel)
		ServerName: serverName,
	}

	c.logger.Info("[agent] connecting to", zap.String("server", c.cfg.TunnelAddr))
	conn, err := tls.Dial("tcp", c.cfg.TunnelAddr, tlsCfg)
	if err != nil {
		return err
	}
	defer conn.Close()

	sess, err := yamux.Client(conn, nil)
	if err != nil {
		return err
	}

	// Control stream
	ctrl, err := sess.OpenStream()
	if err != nil {
		return err
	}

	// Buat JWT
	jwtStr, err := c.createJWT()
	if err != nil {
		return err
	}

	// REGISTER
	if err := protocol.SendJSON(ctrl, protocol.RegisterMessage{
		Type:   protocol.MsgTypeRegister,
		Token:  jwtStr,
		Routes: c.routes,
		Modes:  c.modes,
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
				sess.Close()
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
	defer stream.Close()

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
	if mode == "tcp" {
		c.handleTCPStream(stream, target)
		return
	}

	// Default HTTP mode
	c.handleHTTPStream(stream, target)

}

func (c *Client) createJWT() (string, error) {
	if c.cfg.JWTExpireSec <= 0 {
		c.cfg.JWTExpireSec = 3600
	}
	claims := jwt.MapClaims{
		"iss": c.cfg.JWTIssuer,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Duration(c.cfg.JWTExpireSec) * time.Second).Unix(),
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString([]byte(c.cfg.JWTSecret))
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

func (c *Client) preferredSNIHost() string {
	for _, t := range c.cfg.Tunnels {
		if h := strings.TrimSpace(t.Hostname); h != "" {
			return h
		}
	}
	return ""
}

func (c *Client) handleTCPStream(stream *yamux.Stream, target string) {
	local, err := net.Dial("tcp", target)
	if err != nil {
		c.logger.Error("dial tcp target", zap.Error(err), zap.String("target", target))
		return
	}
	defer local.Close()

	bufA := make([]byte, 32*1024)
	bufB := make([]byte, 32*1024)

	go func() {
		io.CopyBuffer(local, stream, bufA)
		local.Close()
	}()
	io.CopyBuffer(stream, local, bufB)
}

func (c *Client) handleHTTPStream(stream *yamux.Stream, target string) {
	local, err := net.Dial("tcp", target)
	if err != nil {
		c.logger.Error("dial local http", zap.Error(err))
		writeHTTPError(stream, http.StatusBadGateway, "cannot reach local target")
		return
	}
	defer local.Close()

	bufA := make([]byte, 32*1024)
	bufB := make([]byte, 32*1024)

	go func() {
		io.CopyBuffer(local, stream, bufA)
		local.Close()
	}()
	io.CopyBuffer(stream, local, bufB)
}
