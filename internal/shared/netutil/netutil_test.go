package netutil_test

import (
	"bytes"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gotunnel/internal/shared/netutil"
)

type mockWrapper struct {
	net.Conn
	underlying net.Conn
}

func (m *mockWrapper) NetConn() net.Conn {
	return m.underlying
}

func TestYamuxConfig(t *testing.T) {
	t.Parallel()
	cfg := netutil.YamuxConfig()
	assert.Equal(t, uint32(2*1024*1024), cfg.MaxStreamWindowSize)
	assert.Equal(t, 1024, cfg.AcceptBacklog)
	assert.True(t, cfg.EnableKeepAlive)
}

func TestSetTCPNoDelay(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		conn func() net.Conn
	}{
		{
			name: "nil connection",
			conn: func() net.Conn { return nil },
		},
		{
			name: "tcp connection",
			conn: func() net.Conn {
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)
				t.Cleanup(func() { _ = ln.Close() })

				go func() {
					c, _ := ln.Accept()
					if c != nil {
						_ = c.Close()
					}
				}()

				c, err := net.Dial("tcp", ln.Addr().String())
				require.NoError(t, err)
				t.Cleanup(func() { _ = c.Close() })
				return c
			},
		},
		{
			name: "wrapped tcp connection",
			conn: func() net.Conn {
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)
				t.Cleanup(func() { _ = ln.Close() })

				go func() {
					c, _ := ln.Accept()
					if c != nil {
						_ = c.Close()
					}
				}()

				c, err := net.Dial("tcp", ln.Addr().String())
				require.NoError(t, err)
				t.Cleanup(func() { _ = c.Close() })
				return &mockWrapper{underlying: c}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := tt.conn()
			assert.NotPanics(t, func() {
				netutil.SetTCPNoDelay(c)
			})
		})
	}
}

func TestCopyBuffer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    []byte
		expected []byte
	}{
		{
			name:     "empty copy",
			input:    []byte(""),
			expected: []byte(""),
		},
		{
			name:     "standard copy",
			input:    []byte("hello world rdp minecraft"),
			expected: []byte("hello world rdp minecraft"),
		},
		{
			name:     "large copy (>128KB)",
			input:    bytes.Repeat([]byte("A"), 250*1024),
			expected: bytes.Repeat([]byte("A"), 250*1024),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := bytes.NewReader(tt.input)
			var dst bytes.Buffer
			n, err := netutil.CopyBuffer(&dst, src)
			assert.NoError(t, err)
			assert.Equal(t, int64(len(tt.input)), n)
			assert.Equal(t, string(tt.expected), dst.String())
		})
	}
}
