package tunnel

import (
	"time"
)

// TunnelInfo represents an active tunnel session's metadata.
type TunnelInfo struct {
	ClientID    string    `json:"client_id"`
	Client      string    `json:"client"`
	Hosts       []string  `json:"hosts"`
	ConnectedAt time.Time `json:"connected_at"`
	LastPing    time.Time `json:"last_ping"`
}
