package tunnel

import (
	"context"

	domainTunnel "gotunnel/internal/domain/tunnel"

	"github.com/google/uuid"
)

type tunnelUsecase struct {
	tunnelStore domainTunnel.TunnelStore
	domainStore domainTunnel.DomainStore
}

func NewTunnelUsecase(tunnelStore domainTunnel.TunnelStore, domainStore domainTunnel.DomainStore) TunnelUsecase {
	return &tunnelUsecase{
		tunnelStore: tunnelStore,
		domainStore: domainStore,
	}
}

func (u *tunnelUsecase) RegisterTunnel(ctx context.Context, sessionID string, info domainTunnel.TunnelInfo) error {
	return u.tunnelStore.SetTunnel(ctx, sessionID, info)
}

func (u *tunnelUsecase) UnregisterTunnel(ctx context.Context, sessionID string) error {
	return u.tunnelStore.DeleteTunnel(ctx, sessionID)
}

func (u *tunnelUsecase) ListTunnels(ctx context.Context) ([]domainTunnel.TunnelInfo, error) {
	return u.tunnelStore.ListTunnels(ctx)
}

func (u *tunnelUsecase) IsDomainAllowed(ctx context.Context, domain string, userID uuid.UUID, role int16) (bool, error) {
	if u.domainStore == nil {
		return false, nil
	}
	return u.domainStore.IsDomainAllowed(ctx, domain, userID, role)
}

func (u *tunnelUsecase) ListDomains(ctx context.Context, userID uuid.UUID, role int16) ([]domainTunnel.Domain, error) {
	if u.domainStore == nil {
		return []domainTunnel.Domain{}, nil
	}
	return u.domainStore.ListDomains(ctx, userID, role)
}

func (u *tunnelUsecase) AddDomain(ctx context.Context, domain string, userID uuid.UUID) error {
	if u.domainStore == nil {
		return nil
	}
	return u.domainStore.AddDomain(ctx, domain, userID)
}

func (u *tunnelUsecase) RemoveDomain(ctx context.Context, domain string, userID uuid.UUID, role int16) error {
	if u.domainStore == nil {
		return nil
	}
	return u.domainStore.RemoveDomain(ctx, domain, userID, role)
}

func (u *tunnelUsecase) SetActiveDomain(ctx context.Context, domain, sessionID string) error {
	return u.tunnelStore.SetActiveDomain(ctx, domain, sessionID)
}

func (u *tunnelUsecase) RemoveActiveDomain(ctx context.Context, domain string) error {
	return u.tunnelStore.RemoveActiveDomain(ctx, domain)
}

func (u *tunnelUsecase) SetRateLimitSetting(ctx context.Context, username, value string) error {
	return u.tunnelStore.SetRateLimitSetting(ctx, username, value)
}

func (u *tunnelUsecase) GetRateLimitSetting(ctx context.Context, username string) (string, error) {
	return u.tunnelStore.GetRateLimitSetting(ctx, username)
}

func (u *tunnelUsecase) DeleteRateLimitSetting(ctx context.Context, username string) error {
	return u.tunnelStore.DeleteRateLimitSetting(ctx, username)
}

func (u *tunnelUsecase) PublishTunnelEvent(ctx context.Context, eventType string) error {
	return u.tunnelStore.PublishTunnelEvent(ctx, eventType)
}

func (u *tunnelUsecase) SubscribeTunnelEvents(ctx context.Context) (<-chan string, error) {
	return u.tunnelStore.SubscribeTunnelEvents(ctx)
}

func (u *tunnelUsecase) PublishInspectEvent(ctx context.Context, host, payload string) error {
	return u.tunnelStore.PublishInspectEvent(ctx, host, payload)
}

func (u *tunnelUsecase) SubscribeInspectEvents(ctx context.Context, hosts ...string) (<-chan string, error) {
	return u.tunnelStore.SubscribeInspectEvents(ctx, hosts...)
}
