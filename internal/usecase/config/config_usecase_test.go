package config

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	domainConfig "gotunnel/internal/domain/config"
	"gotunnel/internal/domain/config/mocks"
	domainErrors "gotunnel/internal/domain/errors"
)

func TestConfigUsecase_GetConfigByName(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	name := "test-config"
	expectedCfg := &domainConfig.ClientConfig{ID: uuid.New(), UserID: userID, Name: name}

	tests := []struct {
		name      string
		mockSetup func(mockRepo *mocks.MockConfigRepository)
		wantNil   bool
		wantErr   bool
	}{
		{
			name: "success get config by name",
			mockSetup: func(mockRepo *mocks.MockConfigRepository) {
				mockRepo.On("GetConfigByName", mock.Anything, userID, name).Return(expectedCfg, nil).Once()
			},
			wantNil: false,
			wantErr: false,
		},
		{
			name: "repo error returns error",
			mockSetup: func(mockRepo *mocks.MockConfigRepository) {
				mockRepo.On("GetConfigByName", mock.Anything, userID, name).Return(nil, errors.New("db error")).Once()
			},
			wantNil: true,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mockRepo := mocks.NewMockConfigRepository(t)
			tt.mockSetup(mockRepo)

			uc := NewConfigUsecase(mockRepo)
			res, err := uc.GetConfigByName(context.Background(), userID, name)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			if tt.wantNil {
				assert.Nil(t, res)
			} else {
				require.NotNil(t, res)
				assert.Equal(t, expectedCfg.Name, res.Name)
			}
		})
	}
}

func TestConfigUsecase_GetConfigByID(t *testing.T) {
	t.Parallel()

	configID := uuid.New()
	expectedCfg := &domainConfig.ClientConfig{ID: configID, Name: "cfg1"}

	tests := []struct {
		name      string
		mockSetup func(mockRepo *mocks.MockConfigRepository)
		wantNil   bool
		wantErr   bool
	}{
		{
			name: "success get config by id",
			mockSetup: func(mockRepo *mocks.MockConfigRepository) {
				mockRepo.On("GetConfigByID", mock.Anything, configID).Return(expectedCfg, nil).Once()
			},
			wantNil: false,
			wantErr: false,
		},
		{
			name: "repo error returns error",
			mockSetup: func(mockRepo *mocks.MockConfigRepository) {
				mockRepo.On("GetConfigByID", mock.Anything, configID).Return(nil, errors.New("not found")).Once()
			},
			wantNil: true,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mockRepo := mocks.NewMockConfigRepository(t)
			tt.mockSetup(mockRepo)

			uc := NewConfigUsecase(mockRepo)
			res, err := uc.GetConfigByID(context.Background(), configID)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			if tt.wantNil {
				assert.Nil(t, res)
			} else {
				require.NotNil(t, res)
				assert.Equal(t, configID, res.ID)
			}
		})
	}
}

func TestConfigUsecase_GetConfigsByUserID(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	expectedConfigs := []domainConfig.ClientConfig{
		{ID: uuid.New(), UserID: userID, Name: "cfg1"},
		{ID: uuid.New(), UserID: userID, Name: "cfg2"},
	}

	tests := []struct {
		name      string
		mockSetup func(mockRepo *mocks.MockConfigRepository)
		wantLen   int
		wantErr   bool
	}{
		{
			name: "success returns configs",
			mockSetup: func(mockRepo *mocks.MockConfigRepository) {
				mockRepo.On("GetConfigsByUserID", mock.Anything, userID).Return(expectedConfigs, nil).Once()
			},
			wantLen: 2,
			wantErr: false,
		},
		{
			name: "repo error returns error",
			mockSetup: func(mockRepo *mocks.MockConfigRepository) {
				mockRepo.On("GetConfigsByUserID", mock.Anything, userID).Return(nil, errors.New("db error")).Once()
			},
			wantLen: 0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mockRepo := mocks.NewMockConfigRepository(t)
			tt.mockSetup(mockRepo)

			uc := NewConfigUsecase(mockRepo)
			res, err := uc.GetConfigsByUserID(context.Background(), userID)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Len(t, res, tt.wantLen)
			}
		})
	}
}

func TestConfigUsecase_GetAllConfigs(t *testing.T) {
	t.Parallel()

	expectedConfigs := []domainConfig.ClientConfig{
		{ID: uuid.New(), Name: "cfg1"},
	}

	tests := []struct {
		name      string
		mockSetup func(mockRepo *mocks.MockConfigRepository)
		wantLen   int
		wantErr   bool
	}{
		{
			name: "success returns all configs",
			mockSetup: func(mockRepo *mocks.MockConfigRepository) {
				mockRepo.On("GetAllConfigs", mock.Anything).Return(expectedConfigs, nil).Once()
			},
			wantLen: 1,
			wantErr: false,
		},
		{
			name: "repo error returns error",
			mockSetup: func(mockRepo *mocks.MockConfigRepository) {
				mockRepo.On("GetAllConfigs", mock.Anything).Return(nil, errors.New("db error")).Once()
			},
			wantLen: 0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mockRepo := mocks.NewMockConfigRepository(t)
			tt.mockSetup(mockRepo)

			uc := NewConfigUsecase(mockRepo)
			res, err := uc.GetAllConfigs(context.Background())

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Len(t, res, tt.wantLen)
			}
		})
	}
}

func TestConfigUsecase_CreateConfig(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	name := "new-cfg"
	tunnels := domainConfig.TunnelsJSONB{
		{Hostname: "test.example.com", Target: "localhost:80", Mode: "http"},
	}

	tests := []struct {
		name      string
		mockSetup func(mockRepo *mocks.MockConfigRepository)
		wantErr   error
	}{
		{
			name: "success create config",
			mockSetup: func(mockRepo *mocks.MockConfigRepository) {
				mockRepo.On("GetConfigByName", mock.Anything, userID, name).Return(nil, nil).Once()
				mockRepo.On("CreateConfig", mock.Anything, mock.MatchedBy(func(cfg *domainConfig.ClientConfig) bool {
					return cfg.UserID == userID && cfg.Name == name && reflect.DeepEqual(cfg.Tunnels, tunnels)
				})).Return(nil).Once()
			},
			wantErr: nil,
		},
		{
			name: "error check existing config",
			mockSetup: func(mockRepo *mocks.MockConfigRepository) {
				mockRepo.On("GetConfigByName", mock.Anything, userID, name).Return(nil, errors.New("check error")).Once()
			},
			wantErr: errors.New("check error"),
		},
		{
			name: "already exists returns ErrAlreadyExists",
			mockSetup: func(mockRepo *mocks.MockConfigRepository) {
				mockRepo.On("GetConfigByName", mock.Anything, userID, name).Return(&domainConfig.ClientConfig{ID: uuid.New()}, nil).Once()
			},
			wantErr: domainErrors.ErrAlreadyExists,
		},
		{
			name: "create repo error returns error",
			mockSetup: func(mockRepo *mocks.MockConfigRepository) {
				mockRepo.On("GetConfigByName", mock.Anything, userID, name).Return(nil, nil).Once()
				mockRepo.On("CreateConfig", mock.Anything, mock.Anything).Return(errors.New("insert error")).Once()
			},
			wantErr: errors.New("insert error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mockRepo := mocks.NewMockConfigRepository(t)
			tt.mockSetup(mockRepo)

			uc := NewConfigUsecase(mockRepo)
			err := uc.CreateConfig(context.Background(), userID, name, tunnels)

			if tt.wantErr != nil {
				assert.Error(t, err)
				if errors.Is(tt.wantErr, domainErrors.ErrAlreadyExists) {
					assert.ErrorIs(t, err, domainErrors.ErrAlreadyExists)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestConfigUsecase_UpdateConfig(t *testing.T) {
	t.Parallel()

	configID := uuid.New()
	userID := uuid.New()
	oldName := "old-cfg"
	newName := "new-cfg"
	tunnels := domainConfig.TunnelsJSONB{
		{Hostname: "update.example.com", Target: "localhost:8080", Mode: "http"},
	}

	tests := []struct {
		name      string
		mockSetup func(mockRepo *mocks.MockConfigRepository)
		wantErr   error
	}{
		{
			name: "success update config without name change",
			mockSetup: func(mockRepo *mocks.MockConfigRepository) {
				existing := &domainConfig.ClientConfig{ID: configID, UserID: userID, Name: oldName}
				mockRepo.On("GetConfigByID", mock.Anything, configID).Return(existing, nil).Once()
				mockRepo.On("UpdateConfig", mock.Anything, mock.MatchedBy(func(cfg *domainConfig.ClientConfig) bool {
					return cfg.ID == configID && cfg.Name == oldName && reflect.DeepEqual(cfg.Tunnels, tunnels)
				})).Return(nil).Once()
			},
			wantErr: nil,
		},
		{
			name: "success update config with name change",
			mockSetup: func(mockRepo *mocks.MockConfigRepository) {
				existing := &domainConfig.ClientConfig{ID: configID, UserID: userID, Name: oldName}
				mockRepo.On("GetConfigByID", mock.Anything, configID).Return(existing, nil).Once()
				mockRepo.On("GetConfigByName", mock.Anything, userID, newName).Return(nil, nil).Once()
				mockRepo.On("UpdateConfig", mock.Anything, mock.MatchedBy(func(cfg *domainConfig.ClientConfig) bool {
					return cfg.ID == configID && cfg.Name == newName && reflect.DeepEqual(cfg.Tunnels, tunnels)
				})).Return(nil).Once()
			},
			wantErr: nil,
		},
		{
			name: "success update config when get by name returns self",
			mockSetup: func(mockRepo *mocks.MockConfigRepository) {
				existing := &domainConfig.ClientConfig{ID: configID, UserID: userID, Name: oldName}
				mockRepo.On("GetConfigByID", mock.Anything, configID).Return(existing, nil).Once()
				mockRepo.On("GetConfigByName", mock.Anything, userID, newName).Return(&domainConfig.ClientConfig{ID: configID, UserID: userID, Name: newName}, nil).Once()
				mockRepo.On("UpdateConfig", mock.Anything, mock.Anything).Return(nil).Once()
			},
			wantErr: nil,
		},
		{
			name: "get by id error returns error",
			mockSetup: func(mockRepo *mocks.MockConfigRepository) {
				mockRepo.On("GetConfigByID", mock.Anything, configID).Return(nil, errors.New("db error")).Once()
			},
			wantErr: errors.New("db error"),
		},
		{
			name: "not found returns ErrNotFound",
			mockSetup: func(mockRepo *mocks.MockConfigRepository) {
				mockRepo.On("GetConfigByID", mock.Anything, configID).Return(nil, nil).Once()
			},
			wantErr: domainErrors.ErrNotFound,
		},
		{
			name: "get by new name error returns error",
			mockSetup: func(mockRepo *mocks.MockConfigRepository) {
				existing := &domainConfig.ClientConfig{ID: configID, UserID: userID, Name: oldName}
				mockRepo.On("GetConfigByID", mock.Anything, configID).Return(existing, nil).Once()
				mockRepo.On("GetConfigByName", mock.Anything, userID, newName).Return(nil, errors.New("check error")).Once()
			},
			wantErr: errors.New("check error"),
		},
		{
			name: "new name already exists on different id returns ErrAlreadyExists",
			mockSetup: func(mockRepo *mocks.MockConfigRepository) {
				existing := &domainConfig.ClientConfig{ID: configID, UserID: userID, Name: oldName}
				other := &domainConfig.ClientConfig{ID: uuid.New(), UserID: userID, Name: newName}
				mockRepo.On("GetConfigByID", mock.Anything, configID).Return(existing, nil).Once()
				mockRepo.On("GetConfigByName", mock.Anything, userID, newName).Return(other, nil).Once()
			},
			wantErr: domainErrors.ErrAlreadyExists,
		},
		{
			name: "update repo error returns error",
			mockSetup: func(mockRepo *mocks.MockConfigRepository) {
				existing := &domainConfig.ClientConfig{ID: configID, UserID: userID, Name: oldName}
				mockRepo.On("GetConfigByID", mock.Anything, configID).Return(existing, nil).Once()
				mockRepo.On("GetConfigByName", mock.Anything, userID, newName).Return(nil, nil).Once()
				mockRepo.On("UpdateConfig", mock.Anything, mock.Anything).Return(errors.New("update error")).Once()
			},
			wantErr: errors.New("update error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mockRepo := mocks.NewMockConfigRepository(t)
			tt.mockSetup(mockRepo)

			uc := NewConfigUsecase(mockRepo)
			targetName := oldName
			if tt.name != "success update config without name change" {
				targetName = newName
			}
			err := uc.UpdateConfig(context.Background(), configID, targetName, tunnels)

			if tt.wantErr != nil {
				assert.Error(t, err)
				if errors.Is(tt.wantErr, domainErrors.ErrNotFound) {
					assert.ErrorIs(t, err, domainErrors.ErrNotFound)
				}
				if errors.Is(tt.wantErr, domainErrors.ErrAlreadyExists) {
					assert.ErrorIs(t, err, domainErrors.ErrAlreadyExists)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestConfigUsecase_DeleteConfig(t *testing.T) {
	t.Parallel()

	configID := uuid.New()

	tests := []struct {
		name      string
		mockSetup func(mockRepo *mocks.MockConfigRepository)
		wantErr   bool
	}{
		{
			name: "success delete config",
			mockSetup: func(mockRepo *mocks.MockConfigRepository) {
				mockRepo.On("DeleteConfig", mock.Anything, configID).Return(nil).Once()
			},
			wantErr: false,
		},
		{
			name: "repo error returns error",
			mockSetup: func(mockRepo *mocks.MockConfigRepository) {
				mockRepo.On("DeleteConfig", mock.Anything, configID).Return(errors.New("delete error")).Once()
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mockRepo := mocks.NewMockConfigRepository(t)
			tt.mockSetup(mockRepo)

			uc := NewConfigUsecase(mockRepo)
			err := uc.DeleteConfig(context.Background(), configID)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
