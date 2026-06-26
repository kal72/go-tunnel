package tunnel

import (
	"context"

	domainTunnel "gotunnel/internal/domain/tunnel"

	"github.com/google/uuid"
)

//go:generate mockery --name=TunnelUsecase --case=underscore --output=mocks --outpkg=mocks
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
}
