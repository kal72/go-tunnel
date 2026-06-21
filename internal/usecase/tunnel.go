package usecase

import (
	"context"

	"gotunnel/internal/model"
	"gotunnel/internal/repository"
)

type tunnelUsecase struct {
	tunnelStore repository.TunnelStore
	domainStore repository.DomainStore
}

func NewTunnelUsecase(tunnelStore repository.TunnelStore, domainStore repository.DomainStore) TunnelUsecase {
	return &tunnelUsecase{
		tunnelStore: tunnelStore,
		domainStore: domainStore,
	}
}

func (u *tunnelUsecase) RegisterTunnel(ctx context.Context, sessionID string, info model.TunnelInfo) error {
	return u.tunnelStore.SetTunnel(ctx, sessionID, info)
}

func (u *tunnelUsecase) UnregisterTunnel(ctx context.Context, sessionID string) error {
	return u.tunnelStore.DeleteTunnel(ctx, sessionID)
}

func (u *tunnelUsecase) ListTunnels(ctx context.Context) ([]model.TunnelInfo, error) {
	return u.tunnelStore.ListTunnels(ctx)
}

func (u *tunnelUsecase) IsDomainAllowed(ctx context.Context, domain string) (bool, error) {
	if u.domainStore == nil {
		return false, nil
	}
	return u.domainStore.IsDomainAllowed(ctx, domain)
}

func (u *tunnelUsecase) ListDomains(ctx context.Context) ([]string, error) {
	if u.domainStore == nil {
		return []string{}, nil
	}
	return u.domainStore.ListDomains(ctx)
}

func (u *tunnelUsecase) AddDomain(ctx context.Context, domain string) error {
	if u.domainStore == nil {
		return nil
	}
	return u.domainStore.AddDomain(ctx, domain)
}

func (u *tunnelUsecase) RemoveDomain(ctx context.Context, domain string) error {
	if u.domainStore == nil {
		return nil
	}
	return u.domainStore.RemoveDomain(ctx, domain)
}
