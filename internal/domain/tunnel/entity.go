package tunnel

import (
	"time"

	"github.com/google/uuid"
)

// TunnelInfo represents an active tunnel session's metadata.
type TunnelInfo struct {
	Name        string    `json:"name"`
	ClientName  string    `json:"client_name"`
	Hosts       []string  `json:"hosts"`
	ConnectedAt time.Time `json:"connected_at"`
	LastPing    time.Time `json:"last_ping"`
}

type Domain struct {
	Domain    string    `json:"domain" db:"domain"`
	UserID    uuid.UUID `json:"user_id" db:"user_id"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}
