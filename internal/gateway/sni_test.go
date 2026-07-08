package gateway

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

type dummyConn struct {
	io.Reader
	io.Writer
}

func (d *dummyConn) Close() error                     { return nil }
func (d *dummyConn) LocalAddr() net.Addr              { return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443} }
func (d *dummyConn) RemoteAddr() net.Addr             { return &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 54321} }
func (d *dummyConn) SetDeadline(t time.Time) error    { return nil }
func (d *dummyConn) SetReadDeadline(t time.Time) error { return nil }
func (d *dummyConn) SetWriteDeadline(t time.Time) error { return nil }

// helper to encode VarInt
func writeVarInt(buf *bytes.Buffer, val int) {
	u := uint32(val)
	for {
		if (u &^ 0x7F) == 0 {
			buf.WriteByte(byte(u))
			return
		}
		buf.WriteByte(byte((u & 0x7F) | 0x80))
		u >>= 7
	}
}

func buildMinecraftHandshake(pktID int, protoVer int, host string, port uint16, nextState int) []byte {
	var body bytes.Buffer
	writeVarInt(&body, pktID)
	writeVarInt(&body, protoVer)
	writeVarInt(&body, len(host))
	body.WriteString(host)
	body.WriteByte(byte(port >> 8))
	body.WriteByte(byte(port & 0xFF))
	writeVarInt(&body, nextState)

	var pkt bytes.Buffer
	writeVarInt(&pkt, body.Len())
	pkt.Write(body.Bytes())
	return pkt.Bytes()
}

func TestPeekMinecraft(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		wantHost string
		wantErr  bool
	}{
		{
			name:     "standard vanilla handshake",
			input:    buildMinecraftHandshake(0x00, 763, "mc.example.com", 25565, 2),
			wantHost: "mc.example.com",
			wantErr:  false,
		},
		{
			name:     "forge fml handshake with null terminator and port",
			input:    buildMinecraftHandshake(0x00, 763, "play.mc-server.id\x00FML\x00:443", 443, 2),
			wantHost: "play.mc-server.id",
			wantErr:  false,
		},
		{
			name:     "invalid packet ID (not handshake)",
			input:    buildMinecraftHandshake(0x01, 763, "mc.example.com", 25565, 2),
			wantHost: "",
			wantErr:  true,
		},
		{
			name:     "too short packet",
			input:    []byte{0x01, 0x00},
			wantHost: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &dummyConn{Reader: bytes.NewReader(tt.input), Writer: &bytes.Buffer{}}
			gotHost, bConn, err := peekMinecraft(conn)
			if (err != nil) != tt.wantErr {
				t.Fatalf("peekMinecraft() error = %v, wantErr %v", err, tt.wantErr)
			}
			if gotHost != tt.wantHost {
				t.Errorf("peekMinecraft() gotHost = %v, want %v", gotHost, tt.wantHost)
			}
			// Verify bufferedConn replays exact bytes
			readBack, _ := io.ReadAll(bConn)
			if !bytes.Equal(readBack, tt.input) {
				t.Errorf("bufferedConn didn't replay exact bytes: got %v, want %v", readBack, tt.input)
			}
		})
	}
}

func TestPeekMinecraft_AfterPeekSNI(t *testing.T) {
	pkt := buildMinecraftHandshake(0x00, 763, "mc.example.com", 25565, 2)
	conn := &dummyConn{Reader: bytes.NewReader(pkt), Writer: &bytes.Buffer{}}

	// First simulate what peekSNI does (reads 5 bytes and fails)
	_, bConnAfterSNI, errSNI := peekSNI(conn)
	if errSNI == nil {
		t.Fatalf("expected peekSNI to fail on Minecraft packet, but got nil error")
	}

	// Now peekMinecraft must correctly loop and read the rest of the Minecraft handshake packet from bConnAfterSNI
	gotHost, bConnMC, errMC := peekMinecraft(bConnAfterSNI)
	if errMC != nil {
		t.Fatalf("peekMinecraft after peekSNI failed: %v", errMC)
	}
	if gotHost != "mc.example.com" {
		t.Errorf("gotHost = %q, want %q", gotHost, "mc.example.com")
	}

	readBack, _ := io.ReadAll(bConnMC)
	if !bytes.Equal(readBack, pkt) {
		t.Errorf("bufferedConn didn't replay exact bytes after double peek: got %v, want %v", readBack, pkt)
	}
}
