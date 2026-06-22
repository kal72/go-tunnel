package tunnel

import (
	"time"
)

// TunnelInfo represents an active tunnel session's metadata.
type TunnelInfo struct {
	Name        string    `json:"name"`
	ClientName  string    `json:"client_name"`
	Hosts       []string  `json:"hosts"`
	ConnectedAt time.Time `json:"connected_at"`
	LastPing    time.Time `json:"last_ping"`
}
