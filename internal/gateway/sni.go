package gateway

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
)

// peekSNI reads from the connection just enough to extract the SNI hostname
// from the TLS ClientHello, without consuming the bytes from the returned connection.
func peekSNI(conn net.Conn) (string, net.Conn, error) {
	// We only peek, so we don't consume the actual connection data for the next handler
	// However, net.Conn doesn't have Peek. We must read and buffer.
	// Since we need to return a conn that replays these bytes, we use a wrapper.
	const recordHeaderLen = 5
	buf := make([]byte, recordHeaderLen)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		return "", &bufferedConn{Conn: conn, buf: buf}, err
	}

	// TLS Handshake record type is 22
	if buf[0] != 22 {
		return "", &bufferedConn{Conn: conn, buf: buf}, errors.New("not a TLS handshake")
	}

	recordLen := int(binary.BigEndian.Uint16(buf[3:5]))
	recordBuf := make([]byte, recordLen)
	_, err = io.ReadFull(conn, recordBuf)
	fullBuf := make([]byte, recordHeaderLen+recordLen)
	copy(fullBuf, buf)
	copy(fullBuf[recordHeaderLen:], recordBuf)
	if err != nil {
		return "", &bufferedConn{Conn: conn, buf: fullBuf}, err
	}

	// ClientHello is handshake type 1
	if recordBuf[0] != 1 {
		return "", &bufferedConn{Conn: conn, buf: fullBuf}, errors.New("not a ClientHello")
	}

	// Length of ClientHello
	helloLen := int(recordBuf[1])<<16 | int(recordBuf[2])<<8 | int(recordBuf[3])
	if helloLen > len(recordBuf)-4 {
		return "", &bufferedConn{Conn: conn, buf: fullBuf}, errors.New("ClientHello length mismatch")
	}

	// Skip ProtocolVersion (2) + Random (32) = 34 bytes
	pos := 4 + 34
	if pos >= len(recordBuf) {
		return "", &bufferedConn{Conn: conn, buf: fullBuf}, errors.New("buffer too small")
	}

	// SessionID
	sessionIDLen := int(recordBuf[pos])
	pos += 1 + sessionIDLen
	if pos >= len(recordBuf) {
		return "", &bufferedConn{Conn: conn, buf: fullBuf}, errors.New("buffer too small")
	}

	// CipherSuites
	cipherSuitesLen := int(binary.BigEndian.Uint16(recordBuf[pos : pos+2]))
	pos += 2 + cipherSuitesLen
	if pos >= len(recordBuf) {
		return "", &bufferedConn{Conn: conn, buf: fullBuf}, errors.New("buffer too small")
	}

	// CompressionMethods
	compressionMethodsLen := int(recordBuf[pos])
	pos += 1 + compressionMethodsLen
	if pos >= len(recordBuf) {
		return "", &bufferedConn{Conn: conn, buf: fullBuf}, errors.New("buffer too small")
	}

	// Extensions
	if pos == len(recordBuf) {
		return "", &bufferedConn{Conn: conn, buf: fullBuf}, nil // no extensions
	}

	extensionsLen := int(binary.BigEndian.Uint16(recordBuf[pos : pos+2]))
	pos += 2
	end := pos + extensionsLen
	if end > len(recordBuf) {
		end = len(recordBuf)
	}

	for pos+4 <= end {
		extType := binary.BigEndian.Uint16(recordBuf[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(recordBuf[pos+2 : pos+4]))
		pos += 4
		if extType == 0 { // ServerName extension
			if pos+2 > end {
				break
			}
			_ = int(binary.BigEndian.Uint16(recordBuf[pos : pos+2]))
			snPos := pos + 2
			for snPos+3 <= pos+extLen && snPos+3 <= end {
				nameType := recordBuf[snPos]
				nameLen := int(binary.BigEndian.Uint16(recordBuf[snPos+1 : snPos+3]))
				snPos += 3
				if nameType == 0 { // host_name
					if snPos+nameLen > end {
						break
					}
					return string(recordBuf[snPos : snPos+nameLen]), &bufferedConn{Conn: conn, buf: fullBuf}, nil
				}
				snPos += nameLen
			}
		}
		pos += extLen
	}

	return "", &bufferedConn{Conn: conn, buf: fullBuf}, errors.New("SNI not found")
}

// peekMinecraft reads from the connection just enough to check if it's a Minecraft
// Java Edition Handshake packet (Packet ID 0x00) and extracts the target hostname.
func peekMinecraft(conn net.Conn) (string, net.Conn, error) {
	const maxHeaderLen = 512
	buf := make([]byte, maxHeaderLen)
	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		return "", &bufferedConn{Conn: conn, buf: buf[:n]}, err
	}

	// Helper to decode VarInt from buffer
	readVarInt := func(data []byte) (int, int, error) {
		var num int
		var shift uint
		for i, b := range data {
			if shift >= 35 {
				return 0, 0, errors.New("varint too big")
			}
			num |= int(b&0x7F) << shift
			if b&0x80 == 0 {
				return num, i + 1, nil
			}
			shift += 7
		}
		return 0, 0, errors.New("incomplete varint")
	}

	for n < 5 && err == nil {
		var more int
		more, err = conn.Read(buf[n:])
		if more > 0 {
			n += more
		}
		if err != nil && n < 3 {
			return "", &bufferedConn{Conn: conn, buf: buf[:n]}, errors.New("packet too short for Minecraft handshake")
		}
	}

	pktLen, posLen, err := readVarInt(buf[:n])
	if err != nil || pktLen < 3 || pktLen > maxHeaderLen*2 {
		return "", &bufferedConn{Conn: conn, buf: buf[:n]}, errors.New("not a valid Minecraft packet length")
	}

	totalNeeded := posLen + pktLen
	if totalNeeded > maxHeaderLen {
		totalNeeded = maxHeaderLen
	}

	for n < totalNeeded && err == nil {
		var more int
		more, err = conn.Read(buf[n:totalNeeded])
		if more > 0 {
			n += more
		}
	}
	if n < totalNeeded {
		return "", &bufferedConn{Conn: conn, buf: buf[:n]}, errors.New("truncated Minecraft packet buffer")
	}

	// Read Packet ID (must be 0x00 for Handshake)
	pktID, posID, err := readVarInt(buf[posLen:n])
	if err != nil || pktID != 0x00 {
		return "", &bufferedConn{Conn: conn, buf: buf[:n]}, errors.New("not a Minecraft Handshake packet (ID != 0x00)")
	}

	// Read Protocol Version (e.g., 47 to 767+)
	_, posProto, err := readVarInt(buf[posLen+posID : n])
	if err != nil {
		return "", &bufferedConn{Conn: conn, buf: buf[:n]}, errors.New("invalid Minecraft protocol version")
	}

	// Read Server Address String (VarInt length + string bytes)
	offset := posLen + posID + posProto
	if offset >= n {
		return "", &bufferedConn{Conn: conn, buf: buf[:n]}, errors.New("buffer truncated before Server Address")
	}

	strLen, posStr, err := readVarInt(buf[offset:n])
	if err != nil || strLen <= 0 || offset+posStr+strLen > n {
		return "", &bufferedConn{Conn: conn, buf: buf[:n]}, errors.New("invalid Minecraft Server Address string")
	}

	rawHost := string(buf[offset+posStr : offset+posStr+strLen])
	// Clean rawHost: remove FML/Forge null terminators and trailing port if present
	host := strings.Split(rawHost, "\x00")[0]
	host = strings.TrimSpace(host)
	if strings.Contains(host, ":") {
		host = strings.Split(host, ":")[0]
	}
	host = strings.ToLower(host)

	// Validate basic domain format
	if host == "" || !strings.Contains(host, ".") {
		return "", &bufferedConn{Conn: conn, buf: buf[:n]}, errors.New("extracted Minecraft Server Address is not a valid hostname")
	}

	return host, &bufferedConn{Conn: conn, buf: buf[:n]}, nil
}

// bufferedConn wraps a net.Conn and replays buffered data first.
type bufferedConn struct {
	net.Conn
	buf []byte
}

func (b *bufferedConn) Read(p []byte) (n int, err error) {
	if len(b.buf) > 0 {
		n = copy(p, b.buf)
		b.buf = b.buf[n:]
		return n, nil
	}
	return b.Conn.Read(p)
}

// ChanListener allows passing accepted connections via a channel.
type ChanListener struct {
	conns chan net.Conn
	addr  net.Addr
	done  chan struct{}
}

func NewChanListener(addr net.Addr) *ChanListener {
	return &ChanListener{
		conns: make(chan net.Conn),
		addr:  addr,
		done:  make(chan struct{}),
	}
}

func (l *ChanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, errors.New("listener closed")
	}
}

func (l *ChanListener) Close() error {
	select {
	case <-l.done:
	default:
		close(l.done)
	}
	return nil
}

func (l *ChanListener) Addr() net.Addr {
	return l.addr
}

func (l *ChanListener) SendConn(conn net.Conn) {
	select {
	case l.conns <- conn:
	case <-l.done:
		_ = conn.Close()
	}
}
