package client

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// LocalForwarder listens on a local TCP port and forwards each incoming connection
// through the go-tunnel gateway's HTTPS CONNECT mechanism to a registered TCP tunnel.
// This is equivalent to: ssh -L <localPort>:<target> ... -N
type LocalForwarder struct {
	localAddr     string
	hostname      string
	serverAddr    string
	tlsSkipVerify bool
	logger        *zap.Logger
}

// NewLocalForwarder creates a new LocalForwarder.
//   - localAddr:     address to listen on locally, e.g. "localhost:3389"
//   - hostname:      the registered tunnel hostname, e.g. "rdp.domain.com"
//   - serverAddr:    go-tunnel gateway address, e.g. "tunnel.domain.com:443"
//   - tlsSkipVerify: skip TLS certificate verification (for development)
func NewLocalForwarder(localAddr, hostname, serverAddr string, tlsSkipVerify bool) *LocalForwarder {
	zapCfg := zap.NewProductionConfig()
	zapCfg.Encoding = "console"
	zapCfg.DisableStacktrace = true
	zapCfg.DisableCaller = true
	zapCfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	zapCfg.EncoderConfig.EncodeTime = zapcore.RFC3339TimeEncoder
	logger, _ := zapCfg.Build()

	return &LocalForwarder{
		localAddr:     localAddr,
		hostname:      hostname,
		serverAddr:    serverAddr,
		tlsSkipVerify: tlsSkipVerify,
		logger:        logger,
	}
}

// Run starts the local listener and blocks until ctx is cancelled.
func (f *LocalForwarder) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", f.localAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", f.localAddr, err)
	}

	f.logger.Info("[forward] local port forwarder started",
		zap.String("listen", f.localAddr),
		zap.String("tunnel", f.hostname),
		zap.String("via", f.serverAddr),
	)
	f.logger.Info("[forward] press Ctrl+C to stop")

	// Close listener when context is cancelled.
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				f.logger.Info("[forward] stopped")
				return nil
			default:
				f.logger.Error("[forward] accept error", zap.Error(err))
				continue
			}
		}
		go func(c net.Conn) {
			defer func() { _ = recover() }()
			f.handleConn(ctx, c)
		}(conn)
	}
}

// handleConn processes one inbound local connection by opening an HTTPS CONNECT
// tunnel to the go-tunnel gateway and relaying bytes bidirectionally.
func (f *LocalForwarder) handleConn(ctx context.Context, local net.Conn) {
	defer func() { _ = local.Close() }()

	f.logger.Info("[forward] new connection", zap.String("from", local.RemoteAddr().String()))

	// 1. Open a TLS connection to the gateway with the tunnel hostname as SNI.
	tlsCfg := &tls.Config{
		ServerName:         hostOnly(f.serverAddr),
		InsecureSkipVerify: f.tlsSkipVerify, //nolint:gosec // controlled by --insecure flag
		MinVersion:         tls.VersionTLS12,
	}

	dialer := &net.Dialer{Timeout: 15 * time.Second}
	rawConn, err := dialer.DialContext(ctx, "tcp", f.serverAddr)
	if err != nil {
		f.logger.Error("[forward] dial server failed", zap.String("server", f.serverAddr), zap.Error(err))
		return
	}

	tlsConn := tls.Client(rawConn, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		f.logger.Error("[forward] TLS handshake failed", zap.Error(err))
		_ = rawConn.Close()
		return
	}
	defer func() { _ = tlsConn.Close() }()

	// 2. Send HTTP CONNECT request — this is what the go-tunnel gateway expects
	//    to switch to raw TCP relay for mode=tcp tunnels.
	connectReq := fmt.Sprintf(
		"CONNECT %s HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n",
		f.hostname, f.hostname,
	)
	if _, err := tlsConn.Write([]byte(connectReq)); err != nil {
		f.logger.Error("[forward] write CONNECT failed", zap.Error(err))
		return
	}

	// 3. Read 101 Switching Protocols response from the gateway.
	br := bufio.NewReader(tlsConn)
	resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if err != nil {
		f.logger.Error("[forward] read CONNECT response failed", zap.Error(err))
		return
	}
	if resp.Body != nil {
		_ = resp.Body.Close()
	}
	if resp.StatusCode != http.StatusSwitchingProtocols && resp.StatusCode != http.StatusOK {
		f.logger.Error("[forward] gateway rejected tunnel",
			zap.Int("status", resp.StatusCode),
			zap.String("hostname", f.hostname),
		)
		return
	}

	f.logger.Info("[forward] tunnel established", zap.String("hostname", f.hostname))

	// 4. Relay bytes bidirectionally between local connection and gateway TLS conn.
	//    If bufio.Reader has leftover buffered bytes, replay them via prefixedReader.
	var remote io.ReadWriter = tlsConn
	if br.Buffered() > 0 {
		buffered, _ := br.Peek(br.Buffered())
		buf := make([]byte, len(buffered))
		copy(buf, buffered)
		remote = &prefixedReader{prefix: buf, ReadWriter: tlsConn}
	}

	start := time.Now()
	errc := make(chan error, 1)

	go func() {
		bufA := make([]byte, 32*1024)
		_, err := io.CopyBuffer(remote, local, bufA)
		errc <- err
	}()

	bufB := make([]byte, 32*1024)
	_, _ = io.CopyBuffer(local, remote, bufB)
	<-errc

	f.logger.Info("[forward] session closed", zap.Duration("duration", time.Since(start)))
}

// prefixedReader replays buffered bytes before delegating to the underlying ReadWriter.
type prefixedReader struct {
	prefix []byte
	io.ReadWriter
}

func (p *prefixedReader) Read(b []byte) (int, error) {
	if len(p.prefix) > 0 {
		n := copy(b, p.prefix)
		p.prefix = p.prefix[n:]
		return n, nil
	}
	return p.ReadWriter.Read(b)
}

// GatewayAddrFromServerURL derives the gateway address (host:443) from the
// WebUI server URL, e.g. "https://app.domain.com" -> "app.domain.com:443".
func GatewayAddrFromServerURL(serverURL string) string {
	addr := serverURL
	for _, prefix := range []string{"https://", "http://"} {
		if len(addr) > len(prefix) && addr[:len(prefix)] == prefix {
			addr = addr[len(prefix):]
			break
		}
	}
	// Strip path
	for i, c := range addr {
		if c == '/' {
			addr = addr[:i]
			break
		}
	}
	// If no explicit port, default to 443
	if !hasPort(addr) {
		addr += ":443"
	}
	return addr
}

// hasPort reports whether addr contains an explicit port number.
func hasPort(addr string) bool {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return true
		}
		if addr[i] == ']' {
			break // IPv6 literal
		}
	}
	return false
}
