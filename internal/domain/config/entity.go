package config

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type TunnelEntry struct {
	Hostname string `json:"hostname"`
	Target   string `json:"target"`
	Mode     string `json:"mode"`
}

type TunnelsJSONB []TunnelEntry

func (t *TunnelsJSONB) Scan(val interface{}) error {
	switch v := val.(type) {
	case []byte:
		return json.Unmarshal(v, t)
	case string:
		return json.Unmarshal([]byte(v), t)
	default:
		return fmt.Errorf("unsupported type: %T", v)
	}
}

func (t TunnelsJSONB) Value() (driver.Value, error) {
	if t == nil {
		return []byte("[]"), nil
	}
	return json.Marshal(t)
}

type ClientConfig struct {
	CreatedAt time.Time    `db:"created_at" json:"created_at"`
	UpdatedAt time.Time    `db:"updated_at" json:"updated_at"`
	Name      string       `db:"name" json:"name"`
	Tunnels   TunnelsJSONB `db:"tunnels" json:"tunnels"`
	ID        uuid.UUID    `db:"id" json:"id"`
	UserID    uuid.UUID    `db:"user_id" json:"user_id"`
}
