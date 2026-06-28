package postgres

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	domainConfig "gotunnel/internal/domain/config"
)

func setupMockDB(t *testing.T) (*sqlx.DB, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = db.Close()
	})
	sqlx.BindDriver("sqlmock", sqlx.DOLLAR)
	sqlxDB := sqlx.NewDb(db, "sqlmock")
	return sqlxDB, mock
}

func TestSqlxConfigRepository_GetConfigByName(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	configID := uuid.New()
	now := time.Now()
	query := regexp.QuoteMeta("SELECT id, user_id, name, tunnels, created_at, updated_at FROM client_configs WHERE user_id = $1 AND name = $2")

	tests := []struct {
		name       string
		configName string
		mockSetup  func(mock sqlmock.Sqlmock)
		wantNil    bool
		wantErr    bool
	}{
		{
			name:       "success found config",
			configName: "test-config",
			mockSetup: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"id", "user_id", "name", "tunnels", "created_at", "updated_at"}).
					AddRow(configID, userID, "test-config", `[{"hostname":"web","target":"localhost:8080","mode":"http"}]`, now, now)
				mock.ExpectQuery(query).WithArgs(userID, "test-config").WillReturnRows(rows)
			},
			wantNil: false,
			wantErr: false,
		},
		{
			name:       "not found returns nil without error",
			configName: "missing-config",
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(query).WithArgs(userID, "missing-config").WillReturnError(sql.ErrNoRows)
			},
			wantNil: true,
			wantErr: false,
		},
		{
			name:       "database error returns error",
			configName: "error-config",
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(query).WithArgs(userID, "error-config").WillReturnError(errors.New("db error"))
			},
			wantNil: true,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			db, mock := setupMockDB(t)
			repo := NewConfigRepository(db)

			tt.mockSetup(mock)

			res, err := repo.GetConfigByName(context.Background(), userID, tt.configName)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			if tt.wantNil {
				assert.Nil(t, res)
			} else {
				require.NotNil(t, res)
				assert.Equal(t, tt.configName, res.Name)
				assert.Equal(t, userID, res.UserID)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestSqlxConfigRepository_GetConfigByID(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	configID := uuid.New()
	now := time.Now()
	query := regexp.QuoteMeta("SELECT id, user_id, name, tunnels, created_at, updated_at FROM client_configs WHERE id = $1")

	tests := []struct {
		name      string
		id        uuid.UUID
		mockSetup func(mock sqlmock.Sqlmock)
		wantNil   bool
		wantErr   bool
	}{
		{
			name: "success found config by id",
			id:   configID,
			mockSetup: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"id", "user_id", "name", "tunnels", "created_at", "updated_at"}).
					AddRow(configID, userID, "test-config", `[]`, now, now)
				mock.ExpectQuery(query).WithArgs(configID).WillReturnRows(rows)
			},
			wantNil: false,
			wantErr: false,
		},
		{
			name: "not found returns nil without error",
			id:   configID,
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(query).WithArgs(configID).WillReturnError(sql.ErrNoRows)
			},
			wantNil: true,
			wantErr: false,
		},
		{
			name: "database error returns error",
			id:   configID,
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(query).WithArgs(configID).WillReturnError(errors.New("db error"))
			},
			wantNil: true,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			db, mock := setupMockDB(t)
			repo := NewConfigRepository(db)

			tt.mockSetup(mock)

			res, err := repo.GetConfigByID(context.Background(), tt.id)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			if tt.wantNil {
				assert.Nil(t, res)
			} else {
				require.NotNil(t, res)
				assert.Equal(t, tt.id, res.ID)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestSqlxConfigRepository_GetConfigsByUserID(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	configID := uuid.New()
	now := time.Now()
	query := regexp.QuoteMeta("SELECT id, user_id, name, tunnels, created_at, updated_at FROM client_configs WHERE user_id = $1 ORDER BY created_at DESC")

	tests := []struct {
		name      string
		mockSetup func(mock sqlmock.Sqlmock)
		wantCount int
		wantErr   bool
	}{
		{
			name: "success returns multiple configs",
			mockSetup: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"id", "user_id", "name", "tunnels", "created_at", "updated_at"}).
					AddRow(configID, userID, "cfg-1", `[]`, now, now).
					AddRow(uuid.New(), userID, "cfg-2", `[]`, now, now)
				mock.ExpectQuery(query).WithArgs(userID).WillReturnRows(rows)
			},
			wantCount: 2,
			wantErr:   false,
		},
		{
			name: "nil rows returns empty slice",
			mockSetup: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"id", "user_id", "name", "tunnels", "created_at", "updated_at"})
				mock.ExpectQuery(query).WithArgs(userID).WillReturnRows(rows)
			},
			wantCount: 0,
			wantErr:   false,
		},
		{
			name: "database error returns error",
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(query).WithArgs(userID).WillReturnError(errors.New("select error"))
			},
			wantCount: 0,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			db, mock := setupMockDB(t)
			repo := NewConfigRepository(db)

			tt.mockSetup(mock)

			res, err := repo.GetConfigsByUserID(context.Background(), userID)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, res)
				assert.Len(t, res, tt.wantCount)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestSqlxConfigRepository_GetAllConfigs(t *testing.T) {
	t.Parallel()

	configID := uuid.New()
	userID := uuid.New()
	now := time.Now()
	query := regexp.QuoteMeta("SELECT id, user_id, name, tunnels, created_at, updated_at FROM client_configs ORDER BY created_at DESC")

	tests := []struct {
		name      string
		mockSetup func(mock sqlmock.Sqlmock)
		wantCount int
		wantErr   bool
	}{
		{
			name: "success returns all configs",
			mockSetup: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"id", "user_id", "name", "tunnels", "created_at", "updated_at"}).
					AddRow(configID, userID, "cfg-1", `[]`, now, now)
				mock.ExpectQuery(query).WillReturnRows(rows)
			},
			wantCount: 1,
			wantErr:   false,
		},
		{
			name: "empty result returns non-nil empty slice",
			mockSetup: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"id", "user_id", "name", "tunnels", "created_at", "updated_at"})
				mock.ExpectQuery(query).WillReturnRows(rows)
			},
			wantCount: 0,
			wantErr:   false,
		},
		{
			name: "database error returns error",
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(query).WillReturnError(errors.New("db error"))
			},
			wantCount: 0,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			db, mock := setupMockDB(t)
			repo := NewConfigRepository(db)

			tt.mockSetup(mock)

			res, err := repo.GetAllConfigs(context.Background())
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, res)
				assert.Len(t, res, tt.wantCount)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestSqlxConfigRepository_CreateConfig(t *testing.T) {
	t.Parallel()

	cfg := &domainConfig.ClientConfig{
		UserID:  uuid.New(),
		Name:    "new-config",
		Tunnels: domainConfig.TunnelsJSONB{{Hostname: "web", Target: "localhost:8080", Mode: "http"}},
	}
	query := `INSERT INTO client_configs`

	tests := []struct {
		name      string
		mockSetup func(mock sqlmock.Sqlmock)
		wantErr   bool
	}{
		{
			name: "success create config",
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(query).
					WithArgs(cfg.UserID, cfg.Name, cfg.Tunnels).
					WillReturnResult(sqlmock.NewResult(1, 1))
			},
			wantErr: false,
		},
		{
			name: "exec error returns error",
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(query).
					WithArgs(cfg.UserID, cfg.Name, cfg.Tunnels).
					WillReturnError(errors.New("insert failed"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			db, mock := setupMockDB(t)
			repo := NewConfigRepository(db)

			tt.mockSetup(mock)

			err := repo.CreateConfig(context.Background(), cfg)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestSqlxConfigRepository_UpdateConfig(t *testing.T) {
	t.Parallel()

	cfg := &domainConfig.ClientConfig{
		ID:      uuid.New(),
		Name:    "updated-config",
		Tunnels: domainConfig.TunnelsJSONB{{Hostname: "web", Target: "localhost:9090", Mode: "http"}},
	}
	query := `UPDATE client_configs SET name`

	tests := []struct {
		name      string
		mockSetup func(mock sqlmock.Sqlmock)
		wantErr   bool
	}{
		{
			name: "success update config",
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(query).
					WithArgs(cfg.Name, cfg.Tunnels, cfg.ID).
					WillReturnResult(sqlmock.NewResult(1, 1))
			},
			wantErr: false,
		},
		{
			name: "exec error returns error",
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(query).
					WithArgs(cfg.Name, cfg.Tunnels, cfg.ID).
					WillReturnError(errors.New("update failed"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			db, mock := setupMockDB(t)
			repo := NewConfigRepository(db)

			tt.mockSetup(mock)

			err := repo.UpdateConfig(context.Background(), cfg)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestSqlxConfigRepository_DeleteConfig(t *testing.T) {
	t.Parallel()

	configID := uuid.New()
	query := regexp.QuoteMeta("DELETE FROM client_configs WHERE id = $1")

	tests := []struct {
		name      string
		mockSetup func(mock sqlmock.Sqlmock)
		wantErr   bool
	}{
		{
			name: "success delete config",
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(query).WithArgs(configID).WillReturnResult(sqlmock.NewResult(1, 1))
			},
			wantErr: false,
		},
		{
			name: "exec error returns error",
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(query).WithArgs(configID).WillReturnError(errors.New("delete failed"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			db, mock := setupMockDB(t)
			repo := NewConfigRepository(db)

			tt.mockSetup(mock)

			err := repo.DeleteConfig(context.Background(), configID)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}
