package tunnel

import (
	"context"

	domainTunnel "gotunnel/internal/domain/tunnel"

	"github.com/google/uuid"
)

//mockery:generate: true
type TunnelUsecase interface {
	RegisterTunnel(ctx context.Context, sessionID string, info domainTunnel.TunnelInfo) error
	UnregisterTunnel(ctx context.Context, sessionID string) error
	ListTunnels(ctx context.Context) ([]domainTunnel.TunnelInfo, error)
	IsDomainAllowed(ctx context.Context, domain string, userID uuid.UUID, role int16) (bool, error)
	ListDomains(ctx context.Context, userID uuid.UUID, role int16) ([]domainTunnel.Domain, error)
	AddDomain(ctx context.Context, domain string, userID uuid.UUID) error
	RemoveDomain(ctx context.Context, domain string, userID uuid.UUID, role int16) error

	// Active Domain Tracking
	SetActiveDomain(ctx context.Context, domain, sessionID string) error
	RemoveActiveDomain(ctx context.Context, domain string) error

	// Realtime pub/sub events
	PublishTunnelEvent(ctx context.Context, eventType string) error
	SubscribeTunnelEvents(ctx context.Context) (<-chan string, error)
}
