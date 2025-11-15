package protocol

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

const (
	MsgTypeRegister = "register" // client -> server
	MsgTypeAck      = "ack"      // server -> client
	MsgTypePing     = "ping"     // server -> client
	MsgTypePong     = "pong"     // client -> server

	// Versi header data stream biner
	DataHeaderVersion byte = 1
)

type RegisterMessage struct {
	Type   string            `json:"type"`
	Token  string            `json:"token"`  // JWT
	Routes map[string]string `json:"routes"` // hostname -> target
	Modes  map[string]string `json:"modes,omitempty"`
}

type AckMessage struct {
	Type  string `json:"type"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

type PingMessage struct {
	Type string `json:"type"`
	Ts   int64  `json:"ts"`
}

type PongMessage struct {
	Type string `json:"type"`
	Ts   int64  `json:"ts"`
}

func SendJSON(w io.Writer, v any) error {
	return json.NewEncoder(w).Encode(v)
}

func ReadJSON(r io.Reader) (map[string]any, error) {
	var m map[string]any
	err := json.NewDecoder(r).Decode(&m)
	return m, err
}

func GetString(m map[string]any, k string) (string, error) {
	v, ok := m[k]
	if !ok {
		return "", fmt.Errorf("missing field %q", k)
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("field %q not string", k)
	}
	return s, nil
}

// ------------------------
// Data stream header biner
// [1 byte version][2 byte hostname_len][hostname...]
// Setelah itu langsung raw HTTP request/response.
// ------------------------

func WriteDataHeader(w io.Writer, hostname string) error {
	if len(hostname) == 0 || len(hostname) > 65535 {
		return fmt.Errorf("invalid hostname length")
	}
	h := []byte{DataHeaderVersion, 0, 0}
	binary.BigEndian.PutUint16(h[1:], uint16(len(hostname)))
	if _, err := w.Write(h); err != nil {
		return err
	}
	_, err := io.WriteString(w, hostname)
	return err
}

func ReadDataHeader(r io.Reader) (string, error) {
	h := make([]byte, 3)
	if _, err := io.ReadFull(r, h); err != nil {
		return "", err
	}
	if h[0] != DataHeaderVersion {
		return "", fmt.Errorf("unsupported version %d", h[0])
	}
	n := int(binary.BigEndian.Uint16(h[1:3]))
	if n <= 0 {
		return "", fmt.Errorf("empty hostname")
	}
	hn := make([]byte, n)
	if _, err := io.ReadFull(r, hn); err != nil {
		return "", err
	}
	return string(hn), nil
}

func NowMillis() int64 { return time.Now().UnixMilli() }
