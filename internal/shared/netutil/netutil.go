package netutil

import (
	"io"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
)

var bufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 128*1024) // 128 KB pooled buffer for high-throughput stream copying
		return &buf
	},
}

// YamuxConfig returns a tuned Yamux configuration optimized for high-bandwidth
// and low-latency tunneling (such as RDP, Minecraft world chunk loading, and large files).
func YamuxConfig() *yamux.Config {
	cfg := yamux.DefaultConfig()
	// Double the stream window from 256KB to 2MB to prevent window-update ping-pong latency bottlenecks.
	cfg.MaxStreamWindowSize = 2 * 1024 * 1024
	cfg.AcceptBacklog = 1024
	cfg.EnableKeepAlive = true
	cfg.KeepAliveInterval = 15 * time.Second
	return cfg
}

// SetTCPNoDelay attempts to unwrap net.Conn and enable TCP_NODELAY as well as
// enlarging socket read/write buffers. This eliminates Nagle's algorithm delay
// for real-time interactive packets (mouse moves, keyboard input, game ticks).
func SetTCPNoDelay(c net.Conn) {
	if c == nil {
		return
	}
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetReadBuffer(128 * 1024)
		_ = tc.SetWriteBuffer(128 * 1024)
		return
	}
	// Check if wrapped (e.g. *tls.Conn or custom wrapper implementing NetConn())
	if tc, ok := c.(interface{ NetConn() net.Conn }); ok {
		if underlying, ok := tc.NetConn().(*net.TCPConn); ok {
			_ = underlying.SetNoDelay(true)
			_ = underlying.SetReadBuffer(128 * 1024)
			_ = underlying.SetWriteBuffer(128 * 1024)
		}
	}
}

// CopyBuffer copies from src to dst using a pooled 128 KB buffer to minimize
// Garbage Collection overhead and syscall frequency on high-throughput streams.
func CopyBuffer(dst io.Writer, src io.Reader) (int64, error) {
	bufPtr := bufPool.Get().(*[]byte)
	defer bufPool.Put(bufPtr)
	return io.CopyBuffer(dst, src, *bufPtr)
}
