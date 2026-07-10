package apikey

import (
	"time"

	"github.com/google/uuid"
)

// APIKeyStatus represents the status of an API key.
type APIKeyStatus int16

const (
	// StatusActive indicates the key is active and can be used for authentication.
	StatusActive APIKeyStatus = 1
	// StatusRevoked indicates the key has been revoked and cannot be used.
	StatusRevoked APIKeyStatus = 0
)

// APIKey represents a long-lived authentication token for CLI access.
type APIKey struct {
	CreatedAt  time.Time    `db:"created_at" json:"created_at"`
	ExpiresAt  *time.Time   `db:"expires_at" json:"expires_at"` // nil = no expiration
	LastUsedAt *time.Time   `db:"last_used_at" json:"last_used_at"`
	Name       string       `db:"name" json:"name"`
	KeyHash    string       `db:"key_hash" json:"-"` // SHA-256 hash, never exposed
	ID         uuid.UUID    `db:"id" json:"id"`
	UserID     uuid.UUID    `db:"user_id" json:"user_id"`
	Status     APIKeyStatus `db:"status" json:"status"`
}

// APIKeyWithOwner includes owner username for admin listing.
type APIKeyWithOwner struct {
	Username string `db:"username" json:"username"`
	APIKey
}

// IsExpired checks if the key has passed its expiration date.
func (k *APIKey) IsExpired() bool {
	if k.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*k.ExpiresAt)
}

// IsValid checks if the key is active and not expired.
func (k *APIKey) IsValid() bool {
	return k.Status == StatusActive && !k.IsExpired()
}
