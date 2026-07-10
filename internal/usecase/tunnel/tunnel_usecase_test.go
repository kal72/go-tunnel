package tunnel

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	domainTunnel "gotunnel/internal/domain/tunnel"
	tunnelMocks "gotunnel/internal/domain/tunnel/mocks"
)

func TestTunnelUsecase_RegisterTunnel(t *testing.T) {
	t.Parallel()

	sessionID := "sess-123"
	info := domainTunnel.TunnelInfo{Name: "sub"}

	tests := []struct {
		name      string
		mockSetup func(tunnelStore *tunnelMocks.MockTunnelStore)
		wantErr   bool
	}{
		{
			name: "success register",
			mockSetup: func(tunnelStore *tunnelMocks.MockTunnelStore) {
				tunnelStore.On("SetTunnel", mock.Anything, sessionID, info).Return(nil).Once()
			},
			wantErr: false,
		},
		{
			name: "store error",
			mockSetup: func(tunnelStore *tunnelMocks.MockTunnelStore) {
				tunnelStore.On("SetTunnel", mock.Anything, sessionID, info).Return(errors.New("store err")).Once()
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tunnelStore := tunnelMocks.NewMockTunnelStore(t)
			domainStore := tunnelMocks.NewMockDomainStore(t)
			tt.mockSetup(tunnelStore)

			uc := NewTunnelUsecase(tunnelStore, domainStore)
			err := uc.RegisterTunnel(context.Background(), sessionID, info)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestTunnelUsecase_UnregisterTunnel(t *testing.T) {
	t.Parallel()

	sessionID := "sess-123"

	tests := []struct {
		name      string
		mockSetup func(tunnelStore *tunnelMocks.MockTunnelStore)
		wantErr   bool
	}{
		{
			name: "success unregister",
			mockSetup: func(tunnelStore *tunnelMocks.MockTunnelStore) {
				tunnelStore.On("DeleteTunnel", mock.Anything, sessionID).Return(nil).Once()
			},
			wantErr: false,
		},
		{
			name: "store error",
			mockSetup: func(tunnelStore *tunnelMocks.MockTunnelStore) {
				tunnelStore.On("DeleteTunnel", mock.Anything, sessionID).Return(errors.New("store err")).Once()
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tunnelStore := tunnelMocks.NewMockTunnelStore(t)
			domainStore := tunnelMocks.NewMockDomainStore(t)
			tt.mockSetup(tunnelStore)

			uc := NewTunnelUsecase(tunnelStore, domainStore)
			err := uc.UnregisterTunnel(context.Background(), sessionID)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestTunnelUsecase_ListTunnels(t *testing.T) {
	t.Parallel()

	expectedList := []domainTunnel.TunnelInfo{{Name: "sub1"}}

	tests := []struct {
		name      string
		mockSetup func(tunnelStore *tunnelMocks.MockTunnelStore)
		wantErr   bool
	}{
		{
			name: "success list",
			mockSetup: func(tunnelStore *tunnelMocks.MockTunnelStore) {
				tunnelStore.On("ListTunnels", mock.Anything).Return(expectedList, nil).Once()
			},
			wantErr: false,
		},
		{
			name: "store error",
			mockSetup: func(tunnelStore *tunnelMocks.MockTunnelStore) {
				tunnelStore.On("ListTunnels", mock.Anything).Return(nil, errors.New("store err")).Once()
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tunnelStore := tunnelMocks.NewMockTunnelStore(t)
			domainStore := tunnelMocks.NewMockDomainStore(t)
			tt.mockSetup(tunnelStore)

			uc := NewTunnelUsecase(tunnelStore, domainStore)
			res, err := uc.ListTunnels(context.Background())

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, expectedList, res)
			}
		})
	}
}

func TestTunnelUsecase_IsDomainAllowed(t *testing.T) {
	t.Parallel()

	domain := "example.com"
	userID := uuid.New()
	role := int16(1)

	tests := []struct {
		name         string
		nilDomain    bool
		mockSetup    func(domainStore *tunnelMocks.MockDomainStore)
		expectedBool bool
		wantErr      bool
	}{
		{
			name:         "nil domain store returns false nil",
			nilDomain:    true,
			mockSetup:    func(domainStore *tunnelMocks.MockDomainStore) {},
			expectedBool: false,
			wantErr:      false,
		},
		{
			name:      "domain allowed success",
			nilDomain: false,
			mockSetup: func(domainStore *tunnelMocks.MockDomainStore) {
				domainStore.On("IsDomainAllowed", mock.Anything, domain, userID, role).Return(true, nil).Once()
			},
			expectedBool: true,
			wantErr:      false,
		},
		{
			name:      "domain store error",
			nilDomain: false,
			mockSetup: func(domainStore *tunnelMocks.MockDomainStore) {
				domainStore.On("IsDomainAllowed", mock.Anything, domain, userID, role).Return(false, errors.New("err")).Once()
			},
			expectedBool: false,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tunnelStore := tunnelMocks.NewMockTunnelStore(t)
			var domainStore domainTunnel.DomainStore
			if !tt.nilDomain {
				mockDS := tunnelMocks.NewMockDomainStore(t)
				tt.mockSetup(mockDS)
				domainStore = mockDS
			}

			uc := NewTunnelUsecase(tunnelStore, domainStore)
			res, err := uc.IsDomainAllowed(context.Background(), domain, userID, role)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedBool, res)
			}
		})
	}
}

func TestTunnelUsecase_ListDomains(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	role := int16(1)
	expectedList := []domainTunnel.Domain{{Domain: "d1.com"}}

	tests := []struct {
		name         string
		nilDomain    bool
		mockSetup    func(domainStore *tunnelMocks.MockDomainStore)
		expectedList []domainTunnel.Domain
		wantErr      bool
	}{
		{
			name:         "nil domain store returns empty list",
			nilDomain:    true,
			mockSetup:    func(domainStore *tunnelMocks.MockDomainStore) {},
			expectedList: []domainTunnel.Domain{},
			wantErr:      false,
		},
		{
			name:      "list domains success",
			nilDomain: false,
			mockSetup: func(domainStore *tunnelMocks.MockDomainStore) {
				domainStore.On("ListDomains", mock.Anything, userID, role).Return(expectedList, nil).Once()
			},
			expectedList: expectedList,
			wantErr:      false,
		},
		{
			name:      "domain store error",
			nilDomain: false,
			mockSetup: func(domainStore *tunnelMocks.MockDomainStore) {
				domainStore.On("ListDomains", mock.Anything, userID, role).Return(nil, errors.New("err")).Once()
			},
			expectedList: nil,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tunnelStore := tunnelMocks.NewMockTunnelStore(t)
			var domainStore domainTunnel.DomainStore
			if !tt.nilDomain {
				mockDS := tunnelMocks.NewMockDomainStore(t)
				tt.mockSetup(mockDS)
				domainStore = mockDS
			}

			uc := NewTunnelUsecase(tunnelStore, domainStore)
			res, err := uc.ListDomains(context.Background(), userID, role)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedList, res)
			}
		})
	}
}

func TestTunnelUsecase_AddDomain(t *testing.T) {
	t.Parallel()

	domain := "new.com"
	userID := uuid.New()

	tests := []struct {
		name      string
		nilDomain bool
		mockSetup func(domainStore *tunnelMocks.MockDomainStore)
		wantErr   bool
	}{
		{
			name:      "nil domain store returns nil",
			nilDomain: true,
			mockSetup: func(domainStore *tunnelMocks.MockDomainStore) {},
			wantErr:   false,
		},
		{
			name:      "add domain success",
			nilDomain: false,
			mockSetup: func(domainStore *tunnelMocks.MockDomainStore) {
				domainStore.On("AddDomain", mock.Anything, domain, userID).Return(nil).Once()
			},
			wantErr: false,
		},
		{
			name:      "domain store error",
			nilDomain: false,
			mockSetup: func(domainStore *tunnelMocks.MockDomainStore) {
				domainStore.On("AddDomain", mock.Anything, domain, userID).Return(errors.New("err")).Once()
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tunnelStore := tunnelMocks.NewMockTunnelStore(t)
			var domainStore domainTunnel.DomainStore
			if !tt.nilDomain {
				mockDS := tunnelMocks.NewMockDomainStore(t)
				tt.mockSetup(mockDS)
				domainStore = mockDS
			}

			uc := NewTunnelUsecase(tunnelStore, domainStore)
			err := uc.AddDomain(context.Background(), domain, userID)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestTunnelUsecase_RemoveDomain(t *testing.T) {
	t.Parallel()

	domain := "old.com"
	userID := uuid.New()
	role := int16(1)

	tests := []struct {
		name      string
		nilDomain bool
		mockSetup func(domainStore *tunnelMocks.MockDomainStore)
		wantErr   bool
	}{
		{
			name:      "nil domain store returns nil",
			nilDomain: true,
			mockSetup: func(domainStore *tunnelMocks.MockDomainStore) {},
			wantErr:   false,
		},
		{
			name:      "remove domain success",
			nilDomain: false,
			mockSetup: func(domainStore *tunnelMocks.MockDomainStore) {
				domainStore.On("RemoveDomain", mock.Anything, domain, userID, role).Return(nil).Once()
			},
			wantErr: false,
		},
		{
			name:      "domain store error",
			nilDomain: false,
			mockSetup: func(domainStore *tunnelMocks.MockDomainStore) {
				domainStore.On("RemoveDomain", mock.Anything, domain, userID, role).Return(errors.New("err")).Once()
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tunnelStore := tunnelMocks.NewMockTunnelStore(t)
			var domainStore domainTunnel.DomainStore
			if !tt.nilDomain {
				mockDS := tunnelMocks.NewMockDomainStore(t)
				tt.mockSetup(mockDS)
				domainStore = mockDS
			}

			uc := NewTunnelUsecase(tunnelStore, domainStore)
			err := uc.RemoveDomain(context.Background(), domain, userID, role)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestTunnelUsecase_SetActiveDomain(t *testing.T) {
	t.Parallel()

	domain := "active.com"
	sessionID := "sess-1"

	tests := []struct {
		name      string
		mockSetup func(tunnelStore *tunnelMocks.MockTunnelStore)
		wantErr   bool
	}{
		{
			name: "success set active",
			mockSetup: func(tunnelStore *tunnelMocks.MockTunnelStore) {
				tunnelStore.On("SetActiveDomain", mock.Anything, domain, sessionID).Return(nil).Once()
			},
			wantErr: false,
		},
		{
			name: "store error",
			mockSetup: func(tunnelStore *tunnelMocks.MockTunnelStore) {
				tunnelStore.On("SetActiveDomain", mock.Anything, domain, sessionID).Return(errors.New("err")).Once()
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tunnelStore := tunnelMocks.NewMockTunnelStore(t)
			domainStore := tunnelMocks.NewMockDomainStore(t)
			tt.mockSetup(tunnelStore)

			uc := NewTunnelUsecase(tunnelStore, domainStore)
			err := uc.SetActiveDomain(context.Background(), domain, sessionID)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestTunnelUsecase_RemoveActiveDomain(t *testing.T) {
	t.Parallel()

	domain := "active.com"

	tests := []struct {
		name      string
		mockSetup func(tunnelStore *tunnelMocks.MockTunnelStore)
		wantErr   bool
	}{
		{
			name: "success remove active",
			mockSetup: func(tunnelStore *tunnelMocks.MockTunnelStore) {
				tunnelStore.On("RemoveActiveDomain", mock.Anything, domain).Return(nil).Once()
			},
			wantErr: false,
		},
		{
			name: "store error",
			mockSetup: func(tunnelStore *tunnelMocks.MockTunnelStore) {
				tunnelStore.On("RemoveActiveDomain", mock.Anything, domain).Return(errors.New("err")).Once()
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tunnelStore := tunnelMocks.NewMockTunnelStore(t)
			domainStore := tunnelMocks.NewMockDomainStore(t)
			tt.mockSetup(tunnelStore)

			uc := NewTunnelUsecase(tunnelStore, domainStore)
			err := uc.RemoveActiveDomain(context.Background(), domain)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestTunnelUsecase_RefreshActiveDomains(t *testing.T) {
	t.Parallel()

	domains := []string{"app.com", "api.com"}
	sessionID := "sess-1"
	ttl := 3 * time.Minute

	tests := []struct {
		name      string
		mockSetup func(tunnelStore *tunnelMocks.MockTunnelStore)
		wantErr   bool
	}{
		{
			name: "success refresh",
			mockSetup: func(tunnelStore *tunnelMocks.MockTunnelStore) {
				tunnelStore.On("RefreshActiveDomains", mock.Anything, domains, sessionID, ttl).Return(nil).Once()
			},
			wantErr: false,
		},
		{
			name: "store error",
			mockSetup: func(tunnelStore *tunnelMocks.MockTunnelStore) {
				tunnelStore.On("RefreshActiveDomains", mock.Anything, domains, sessionID, ttl).Return(errors.New("store err")).Once()
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tunnelStore := tunnelMocks.NewMockTunnelStore(t)
			domainStore := tunnelMocks.NewMockDomainStore(t)
			tt.mockSetup(tunnelStore)

			uc := NewTunnelUsecase(tunnelStore, domainStore)
			err := uc.RefreshActiveDomains(context.Background(), domains, sessionID, ttl)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestTunnelUsecase_FlushAllTunnelsAndDomains(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		mockSetup func(tunnelStore *tunnelMocks.MockTunnelStore)
		wantErr   bool
	}{
		{
			name: "success flush",
			mockSetup: func(tunnelStore *tunnelMocks.MockTunnelStore) {
				tunnelStore.On("FlushAllTunnelsAndDomains", mock.Anything).Return(nil).Once()
			},
			wantErr: false,
		},
		{
			name: "store error",
			mockSetup: func(tunnelStore *tunnelMocks.MockTunnelStore) {
				tunnelStore.On("FlushAllTunnelsAndDomains", mock.Anything).Return(errors.New("store err")).Once()
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tunnelStore := tunnelMocks.NewMockTunnelStore(t)
			domainStore := tunnelMocks.NewMockDomainStore(t)
			tt.mockSetup(tunnelStore)

			uc := NewTunnelUsecase(tunnelStore, domainStore)
			err := uc.FlushAllTunnelsAndDomains(context.Background())

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
