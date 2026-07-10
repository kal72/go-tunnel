package apikey

import (
	"context"

	"github.com/google/uuid"
)

// APIKeyRepository defines the persistence contract for API keys.
//
//mockery:generate: true
type APIKeyRepository interface {
	// Create stores a new API key record.
	Create(ctx context.Context, key *APIKey) error

	// GetByHash retrieves an API key by its SHA-256 hash.
	// Returns nil, nil if not found.
	GetByHash(ctx context.Context, keyHash string) (*APIKey, error)

	// GetByID retrieves an API key by its UUID.
	GetByID(ctx context.Context, id uuid.UUID) (*APIKey, error)

	// ListByUserID returns all API keys owned by a user (excluding hash).
	// Results are sorted by created_at DESC.
	ListByUserID(ctx context.Context, userID uuid.UUID, limit, offset int) ([]APIKey, int, error)

	// ListAll returns all API keys with owner info (admin only).
	// Results are sorted by created_at DESC.
	ListAll(ctx context.Context, limit, offset int, usernameFilter string) ([]APIKeyWithOwner, int, error)

	// CountActiveByUserID returns the number of active (non-revoked, non-expired) keys for a user.
	CountActiveByUserID(ctx context.Context, userID uuid.UUID) (int, error)

	// ExistsActiveByName checks if an active key with the given name exists for a user.
	ExistsActiveByName(ctx context.Context, userID uuid.UUID, name string) (bool, error)

	// Revoke sets the key status to revoked.
	Revoke(ctx context.Context, id uuid.UUID) error

	// UpdateLastUsedAt updates the last_used_at timestamp.
	UpdateLastUsedAt(ctx context.Context, id uuid.UUID) error

	// RevokeAllByUserID revokes all keys belonging to a user.
	RevokeAllByUserID(ctx context.Context, userID uuid.UUID) error
}
