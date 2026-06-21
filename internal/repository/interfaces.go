package repository

import (
	"context"
	"time"

	"gotunnel/internal/model"
)

//go:generate mockery --name=TunnelStore --case=underscore --output=mocks --outpkg=mocks
type TunnelStore interface {
	Ping(ctx context.Context)
	SetTunnel(ctx context.Context, sessionID string, info model.TunnelInfo) error
	DeleteTunnel(ctx context.Context, sessionID string) error
	ListTunnels(ctx context.Context) ([]model.TunnelInfo, error)

	// Token management
	SetToken(ctx context.Context, token string, expiration time.Duration) error
	IsTokenRevoked(ctx context.Context, token string) (bool, error)
	RevokeToken(ctx context.Context, token string) error
}

//go:generate mockery --name=DomainStore --case=underscore --output=mocks --outpkg=mocks
type DomainStore interface {
	Ping(ctx context.Context)
	AddDomain(ctx context.Context, domain string) error
	RemoveDomain(ctx context.Context, domain string) error
	ListDomains(ctx context.Context) ([]string, error)
	IsDomainAllowed(ctx context.Context, domain string) (bool, error)
}
