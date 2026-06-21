package usecase

import (
	"context"

	"gotunnel/internal/model"

	"github.com/google/uuid"
)

//go:generate mockery --name=AuthUsecase --case=underscore --output=mocks --outpkg=mocks
type AuthUsecase interface {
	Login(ctx context.Context, username, password string) (token string, err error)
	VerifyToken(ctx context.Context, token string) (*model.User, error)
	Logout(ctx context.Context, token string) error
	CreateUser(ctx context.Context, username, password string, role int16) error
	ListUsers(ctx context.Context) ([]model.User, error)
	UpdateUserStatus(ctx context.Context, id uuid.UUID, status int16) error
	UpdateUserPassword(ctx context.Context, id uuid.UUID, password string) error
	DeleteUser(ctx context.Context, id uuid.UUID) error
}

//go:generate mockery --name=ConfigUsecase --case=underscore --output=mocks --outpkg=mocks
type ConfigUsecase interface {
	GetConfigByName(ctx context.Context, userID uuid.UUID, name string) (*model.ClientConfig, error)
	GetConfigByID(ctx context.Context, id uuid.UUID) (*model.ClientConfig, error)
	GetConfigsByUserID(ctx context.Context, userID uuid.UUID) ([]model.ClientConfig, error)
	GetAllConfigs(ctx context.Context) ([]model.ClientConfig, error)
	CreateConfig(ctx context.Context, userID uuid.UUID, name string, tunnels model.TunnelsJSONB) error
	UpdateConfig(ctx context.Context, id uuid.UUID, name string, tunnels model.TunnelsJSONB) error
	DeleteConfig(ctx context.Context, id uuid.UUID) error
}

//go:generate mockery --name=TunnelUsecase --case=underscore --output=mocks --outpkg=mocks
type TunnelUsecase interface {
	RegisterTunnel(ctx context.Context, sessionID string, info model.TunnelInfo) error
	UnregisterTunnel(ctx context.Context, sessionID string) error
	ListTunnels(ctx context.Context) ([]model.TunnelInfo, error)
	IsDomainAllowed(ctx context.Context, domain string) (bool, error)
	ListDomains(ctx context.Context) ([]string, error)
	AddDomain(ctx context.Context, domain string) error
	RemoveDomain(ctx context.Context, domain string) error
}
