package gateway

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
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
	fullBuf := append(buf, recordBuf...)
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
			 _ =  int(binary.BigEndian.Uint16(recordBuf[pos : pos+2]))
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

// ChanListener allows passing accepted connections via a channel
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
	close(l.done)
	return nil
}

func (l *ChanListener) Addr() net.Addr {
	return l.addr
}

func (l *ChanListener) SendConn(conn net.Conn) {
	select {
	case l.conns <- conn:
	case <-l.done:
		conn.Close()
	}
}
