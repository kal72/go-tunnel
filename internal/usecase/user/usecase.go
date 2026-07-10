package user

import (
	"context"
	"time"

	domainAPIKey "gotunnel/internal/domain/apikey"
	domainUser "gotunnel/internal/domain/user"

	"github.com/google/uuid"
)

//mockery:generate: true
type AuthUsecase interface {
	Login(ctx context.Context, username, password string) (token string, err error)
	LoginCLI(ctx context.Context, username, password string) (token string, err error)
	GetWebExpireDuration() time.Duration
	VerifyToken(ctx context.Context, token string) (*domainUser.User, error)
	Logout(ctx context.Context, token string) error
	CreateUser(ctx context.Context, username, password string, role int16) error
	ListUsers(ctx context.Context) ([]domainUser.User, error)
	UpdateUserStatus(ctx context.Context, id uuid.UUID, status int16) error
	UpdateUserPassword(ctx context.Context, id uuid.UUID, password string) error
	DeleteUser(ctx context.Context, id uuid.UUID) error
	RevokeUserTokens(ctx context.Context, targetUserID uuid.UUID) error

	// CreateAPIKey creates a new API key for a user.
	// Returns the plaintext key (shown once), the key metadata, and any error.
	CreateAPIKey(ctx context.Context, userID uuid.UUID, name string, expiresAt *time.Time) (plaintext string, key *domainAPIKey.APIKey, err error)

	// ListAPIKeys lists API keys. For regular users, lists own keys.
	// For admin (role=1), lists all keys with optional username filter.
	ListAPIKeys(ctx context.Context, userID uuid.UUID, role int16, limit, offset int, usernameFilter string) ([]domainAPIKey.APIKeyWithOwner, int, error)

	// RevokeAPIKey revokes an API key by ID.
	// Requires ownership or admin role.
	RevokeAPIKey(ctx context.Context, keyID, requesterID uuid.UUID, requesterRole int16) error

	// DeleteAPIKey permanently deletes an API key by ID from the database.
	// Requires ownership or admin role.
	DeleteAPIKey(ctx context.Context, keyID, requesterID uuid.UUID, requesterRole int16) error

	// GetAPIKeyByID retrieves an API key by ID.
	GetAPIKeyByID(ctx context.Context, keyID uuid.UUID) (*domainAPIKey.APIKey, error)
}
