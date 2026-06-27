package setting

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"gotunnel/internal/domain/setting/mocks"
)

func TestSettingUsecase_GetSetting(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		key       string
		mockSetup func(mockStore *mocks.MockSettingStore)
		expected  string
		wantErr   bool
	}{
		{
			name: "success get setting",
			key:  "theme",
			mockSetup: func(mockStore *mocks.MockSettingStore) {
				mockStore.On("GetSetting", mock.Anything, "theme").Return("dark", nil).Once()
			},
			expected: "dark",
			wantErr:  false,
		},
		{
			name: "store error returns error",
			key:  "theme",
			mockSetup: func(mockStore *mocks.MockSettingStore) {
				mockStore.On("GetSetting", mock.Anything, "theme").Return("", errors.New("db error")).Once()
			},
			expected: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mockStore := mocks.NewMockSettingStore(t)
			tt.mockSetup(mockStore)

			uc := NewSettingUsecase(mockStore)
			res, err := uc.GetSetting(context.Background(), tt.key)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, res)
			}
		})
	}
}

func TestSettingUsecase_SetSetting(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		key       string
		val       string
		mockSetup func(mockStore *mocks.MockSettingStore)
		wantErr   bool
	}{
		{
			name: "success set setting",
			key:  "theme",
			val:  "light",
			mockSetup: func(mockStore *mocks.MockSettingStore) {
				mockStore.On("SetSetting", mock.Anything, "theme", "light").Return(nil).Once()
			},
			wantErr: false,
		},
		{
			name: "store error returns error",
			key:  "theme",
			val:  "light",
			mockSetup: func(mockStore *mocks.MockSettingStore) {
				mockStore.On("SetSetting", mock.Anything, "theme", "light").Return(errors.New("save error")).Once()
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mockStore := mocks.NewMockSettingStore(t)
			tt.mockSetup(mockStore)

			uc := NewSettingUsecase(mockStore)
			err := uc.SetSetting(context.Background(), tt.key, tt.val)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSettingUsecase_GetAllSettings(t *testing.T) {
	t.Parallel()

	expectedMap := map[string]string{"theme": "dark", "lang": "en"}

	tests := []struct {
		name      string
		mockSetup func(mockStore *mocks.MockSettingStore)
		wantMap   map[string]string
		wantErr   bool
	}{
		{
			name: "success get all settings",
			mockSetup: func(mockStore *mocks.MockSettingStore) {
				mockStore.On("GetAllSettings", mock.Anything).Return(expectedMap, nil).Once()
			},
			wantMap: expectedMap,
			wantErr: false,
		},
		{
			name: "store error returns error",
			mockSetup: func(mockStore *mocks.MockSettingStore) {
				mockStore.On("GetAllSettings", mock.Anything).Return(nil, errors.New("db error")).Once()
			},
			wantMap: nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mockStore := mocks.NewMockSettingStore(t)
			tt.mockSetup(mockStore)

			uc := NewSettingUsecase(mockStore)
			res, err := uc.GetAllSettings(context.Background())

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantMap, res)
			}
		})
	}
}

func TestSettingUsecase_GetMaxFreeDomains(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		fallback  int
		mockSetup func(mockStore *mocks.MockSettingStore)
		expected  int
	}{
		{
			name:     "store returns error yields fallback",
			fallback: 3,
			mockSetup: func(mockStore *mocks.MockSettingStore) {
				mockStore.On("GetSetting", mock.Anything, "max_free_domains").Return("", errors.New("err")).Once()
			},
			expected: 3,
		},
		{
			name:     "store returns empty string yields fallback",
			fallback: 3,
			mockSetup: func(mockStore *mocks.MockSettingStore) {
				mockStore.On("GetSetting", mock.Anything, "max_free_domains").Return("", nil).Once()
			},
			expected: 3,
		},
		{
			name:     "store returns invalid int yields fallback",
			fallback: 3,
			mockSetup: func(mockStore *mocks.MockSettingStore) {
				mockStore.On("GetSetting", mock.Anything, "max_free_domains").Return("invalid", nil).Once()
			},
			expected: 3,
		},
		{
			name:     "store returns valid int yields parsed value",
			fallback: 3,
			mockSetup: func(mockStore *mocks.MockSettingStore) {
				mockStore.On("GetSetting", mock.Anything, "max_free_domains").Return("10", nil).Once()
			},
			expected: 10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mockStore := mocks.NewMockSettingStore(t)
			tt.mockSetup(mockStore)

			uc := NewSettingUsecase(mockStore)
			res := uc.GetMaxFreeDomains(context.Background(), tt.fallback)
			assert.Equal(t, tt.expected, res)
		})
	}
}

func TestSettingUsecase_GetMaxTunnelsPerUser(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		fallback  int
		mockSetup func(mockStore *mocks.MockSettingStore)
		expected  int
	}{
		{
			name:     "store returns error yields fallback",
			fallback: 5,
			mockSetup: func(mockStore *mocks.MockSettingStore) {
				mockStore.On("GetSetting", mock.Anything, "max_tunnels_per_user").Return("", errors.New("err")).Once()
			},
			expected: 5,
		},
		{
			name:     "store returns empty string yields fallback",
			fallback: 5,
			mockSetup: func(mockStore *mocks.MockSettingStore) {
				mockStore.On("GetSetting", mock.Anything, "max_tunnels_per_user").Return("", nil).Once()
			},
			expected: 5,
		},
		{
			name:     "store returns invalid int yields fallback",
			fallback: 5,
			mockSetup: func(mockStore *mocks.MockSettingStore) {
				mockStore.On("GetSetting", mock.Anything, "max_tunnels_per_user").Return("notanumber", nil).Once()
			},
			expected: 5,
		},
		{
			name:     "store returns valid int yields parsed value",
			fallback: 5,
			mockSetup: func(mockStore *mocks.MockSettingStore) {
				mockStore.On("GetSetting", mock.Anything, "max_tunnels_per_user").Return("20", nil).Once()
			},
			expected: 20,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mockStore := mocks.NewMockSettingStore(t)
			tt.mockSetup(mockStore)

			uc := NewSettingUsecase(mockStore)
			res := uc.GetMaxTunnelsPerUser(context.Background(), tt.fallback)
			assert.Equal(t, tt.expected, res)
		})
	}
}

func TestSettingUsecase_GetAllowRegistration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		fallback  bool
		mockSetup func(mockStore *mocks.MockSettingStore)
		expected  bool
	}{
		{
			name:     "store returns error yields fallback",
			fallback: true,
			mockSetup: func(mockStore *mocks.MockSettingStore) {
				mockStore.On("GetSetting", mock.Anything, "allow_registration").Return("", errors.New("err")).Once()
			},
			expected: true,
		},
		{
			name:     "store returns empty string yields fallback",
			fallback: true,
			mockSetup: func(mockStore *mocks.MockSettingStore) {
				mockStore.On("GetSetting", mock.Anything, "allow_registration").Return("", nil).Once()
			},
			expected: true,
		},
		{
			name:     "store returns invalid bool yields fallback",
			fallback: true,
			mockSetup: func(mockStore *mocks.MockSettingStore) {
				mockStore.On("GetSetting", mock.Anything, "allow_registration").Return("notabool", nil).Once()
			},
			expected: true,
		},
		{
			name:     "store returns valid bool yields parsed value",
			fallback: true,
			mockSetup: func(mockStore *mocks.MockSettingStore) {
				mockStore.On("GetSetting", mock.Anything, "allow_registration").Return("false", nil).Once()
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mockStore := mocks.NewMockSettingStore(t)
			tt.mockSetup(mockStore)

			uc := NewSettingUsecase(mockStore)
			res := uc.GetAllowRegistration(context.Background(), tt.fallback)
			assert.Equal(t, tt.expected, res)
		})
	}
}
