package tunnel

import (
	"time"

	"github.com/google/uuid"
)

// TunnelInfo represents an active tunnel session's metadata.
type TunnelInfo struct {
	ConnectedAt time.Time `json:"connected_at"`
	LastPing    time.Time `json:"last_ping"`
	Name        string    `json:"name"`
	ClientName  string    `json:"client_name"`
	Hosts       []string  `json:"hosts"`
}

type Domain struct {
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	Domain    string    `json:"domain" db:"domain"`
	UserID    uuid.UUID `json:"user_id" db:"user_id"`
}
