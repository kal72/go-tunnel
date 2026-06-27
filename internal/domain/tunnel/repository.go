package tunnel

import (
	"context"
	"time"

	"github.com/google/uuid"
)

//mockery:generate: true
type TunnelStore interface {
	Ping(ctx context.Context)
	SetTunnel(ctx context.Context, sessionID string, info TunnelInfo) error
	DeleteTunnel(ctx context.Context, sessionID string) error
	ListTunnels(ctx context.Context) ([]TunnelInfo, error)

	// Token management
	SetToken(ctx context.Context, token string, expiration time.Duration) error
	IsTokenRevoked(ctx context.Context, token string) (bool, error)
	RevokeToken(ctx context.Context, token string) error

	// Active tunnel global lock
	SetActiveDomain(ctx context.Context, domain string, sessionID string) error
	RemoveActiveDomain(ctx context.Context, domain string) error
}

//mockery:generate: true
type DomainStore interface {
	Ping(ctx context.Context)
	AddDomain(ctx context.Context, domain string, userID uuid.UUID) error
	RemoveDomain(ctx context.Context, domain string, userID uuid.UUID, role int16) error
	ListDomains(ctx context.Context, userID uuid.UUID, role int16) ([]Domain, error)
	IsDomainAllowed(ctx context.Context, domain string, userID uuid.UUID, role int16) (bool, error)
}
