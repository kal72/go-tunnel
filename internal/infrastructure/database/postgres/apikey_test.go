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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	domainAPIKey "gotunnel/internal/domain/apikey"
)

func TestSqlxAPIKeyRepository_Create(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	keyID := uuid.New()
	now := time.Now()
	expiresAt := now.Add(24 * time.Hour)

	key := &domainAPIKey.APIKey{
		ID:        keyID,
		UserID:    userID,
		Name:      "my-key",
		KeyHash:   "abc123hash",
		Status:    domainAPIKey.StatusActive,
		CreatedAt: now,
		ExpiresAt: &expiresAt,
	}

	query := regexp.QuoteMeta("INSERT INTO api_keys (id, user_id, name, key_hash, status, created_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7)")

	tests := []struct {
		name      string
		mockSetup func(mock sqlmock.Sqlmock)
		wantErr   bool
	}{
		{
			name: "success create API key",
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(query).
					WithArgs(key.ID, key.UserID, key.Name, key.KeyHash, key.Status, key.CreatedAt, key.ExpiresAt).
					WillReturnResult(sqlmock.NewResult(1, 1))
			},
			wantErr: false,
		},
		{
			name: "exec error returns error",
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(query).
					WithArgs(key.ID, key.UserID, key.Name, key.KeyHash, key.Status, key.CreatedAt, key.ExpiresAt).
					WillReturnError(errors.New("insert failed"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			db, mock := setupMockDB(t)
			repo := NewAPIKeyRepository(db)

			tt.mockSetup(mock)

			err := repo.Create(context.Background(), key)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestSqlxAPIKeyRepository_GetByHash(t *testing.T) {
	t.Parallel()

	keyID := uuid.New()
	userID := uuid.New()
	now := time.Now()
	expiresAt := now.Add(24 * time.Hour)
	lastUsedAt := now.Add(-1 * time.Hour)

	query := regexp.QuoteMeta("SELECT id, user_id, name, key_hash, status, created_at, expires_at, last_used_at FROM api_keys WHERE key_hash = $1")

	tests := []struct {
		name      string
		keyHash   string
		mockSetup func(mock sqlmock.Sqlmock)
		wantNil   bool
		wantErr   bool
	}{
		{
			name:    "success found key by hash",
			keyHash: "abc123hash",
			mockSetup: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"id", "user_id", "name", "key_hash", "status", "created_at", "expires_at", "last_used_at"}).
					AddRow(keyID, userID, "my-key", "abc123hash", domainAPIKey.StatusActive, now, expiresAt, lastUsedAt)
				mock.ExpectQuery(query).WithArgs("abc123hash").WillReturnRows(rows)
			},
			wantNil: false,
			wantErr: false,
		},
		{
			name:    "not found returns nil without error",
			keyHash: "nonexistent",
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(query).WithArgs("nonexistent").WillReturnError(sql.ErrNoRows)
			},
			wantNil: true,
			wantErr: false,
		},
		{
			name:    "database error returns error",
			keyHash: "abc123hash",
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(query).WithArgs("abc123hash").WillReturnError(errors.New("db error"))
			},
			wantNil: true,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			db, mock := setupMockDB(t)
			repo := NewAPIKeyRepository(db)

			tt.mockSetup(mock)

			res, err := repo.GetByHash(context.Background(), tt.keyHash)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			if tt.wantNil {
				assert.Nil(t, res)
			} else {
				require.NotNil(t, res)
				assert.Equal(t, keyID, res.ID)
				assert.Equal(t, userID, res.UserID)
				assert.Equal(t, "my-key", res.Name)
				assert.Equal(t, domainAPIKey.StatusActive, res.Status)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestSqlxAPIKeyRepository_ListByUserID(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	keyID1 := uuid.New()
	keyID2 := uuid.New()
	now := time.Now()

	query := regexp.QuoteMeta(`SELECT id, user_id, name, status, created_at, expires_at, last_used_at,
		       COUNT(*) OVER() AS total_count
		FROM api_keys
		WHERE user_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3`)

	tests := []struct {
		name      string
		limit     int
		offset    int
		mockSetup func(mock sqlmock.Sqlmock)
		wantCount int
		wantTotal int
		wantErr   bool
	}{
		{
			name:   "success returns paginated keys",
			limit:  10,
			offset: 0,
			mockSetup: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"id", "user_id", "name", "status", "created_at", "expires_at", "last_used_at", "total_count"}).
					AddRow(keyID1, userID, "key-1", domainAPIKey.StatusActive, now, nil, nil, 2).
					AddRow(keyID2, userID, "key-2", domainAPIKey.StatusActive, now.Add(-1*time.Hour), nil, nil, 2)
				mock.ExpectQuery(query).WithArgs(userID, 10, 0).WillReturnRows(rows)
			},
			wantCount: 2,
			wantTotal: 2,
			wantErr:   false,
		},
		{
			name:   "success with offset pagination",
			limit:  1,
			offset: 1,
			mockSetup: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"id", "user_id", "name", "status", "created_at", "expires_at", "last_used_at", "total_count"}).
					AddRow(keyID2, userID, "key-2", domainAPIKey.StatusActive, now.Add(-1*time.Hour), nil, nil, 2)
				mock.ExpectQuery(query).WithArgs(userID, 1, 1).WillReturnRows(rows)
			},
			wantCount: 1,
			wantTotal: 2,
			wantErr:   false,
		},
		{
			name:   "empty result returns zero keys",
			limit:  10,
			offset: 0,
			mockSetup: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"id", "user_id", "name", "status", "created_at", "expires_at", "last_used_at", "total_count"})
				mock.ExpectQuery(query).WithArgs(userID, 10, 0).WillReturnRows(rows)
			},
			wantCount: 0,
			wantTotal: 0,
			wantErr:   false,
		},
		{
			name:   "database error returns error",
			limit:  10,
			offset: 0,
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(query).WithArgs(userID, 10, 0).WillReturnError(errors.New("query failed"))
			},
			wantCount: 0,
			wantTotal: 0,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			db, mock := setupMockDB(t)
			repo := NewAPIKeyRepository(db)

			tt.mockSetup(mock)

			keys, total, err := repo.ListByUserID(context.Background(), userID, tt.limit, tt.offset)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Len(t, keys, tt.wantCount)
				assert.Equal(t, tt.wantTotal, total)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestSqlxAPIKeyRepository_CountActiveByUserID(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	query := regexp.QuoteMeta("SELECT COUNT(*) FROM api_keys WHERE user_id = $1 AND status = $2 AND (expires_at IS NULL OR expires_at > NOW())")

	tests := []struct {
		name      string
		mockSetup func(mock sqlmock.Sqlmock)
		wantCount int
		wantErr   bool
	}{
		{
			name: "success returns count of active keys",
			mockSetup: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"count"}).AddRow(5)
				mock.ExpectQuery(query).WithArgs(userID, domainAPIKey.StatusActive).WillReturnRows(rows)
			},
			wantCount: 5,
			wantErr:   false,
		},
		{
			name: "success returns zero when no active keys",
			mockSetup: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"count"}).AddRow(0)
				mock.ExpectQuery(query).WithArgs(userID, domainAPIKey.StatusActive).WillReturnRows(rows)
			},
			wantCount: 0,
			wantErr:   false,
		},
		{
			name: "database error returns error",
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(query).WithArgs(userID, domainAPIKey.StatusActive).WillReturnError(errors.New("count failed"))
			},
			wantCount: 0,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			db, mock := setupMockDB(t)
			repo := NewAPIKeyRepository(db)

			tt.mockSetup(mock)

			count, err := repo.CountActiveByUserID(context.Background(), userID)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantCount, count)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestSqlxAPIKeyRepository_Revoke(t *testing.T) {
	t.Parallel()

	keyID := uuid.New()
	query := regexp.QuoteMeta("UPDATE api_keys SET status = $1 WHERE id = $2")

	tests := []struct {
		name      string
		mockSetup func(mock sqlmock.Sqlmock)
		wantErr   bool
	}{
		{
			name: "success revoke key",
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(query).
					WithArgs(domainAPIKey.StatusRevoked, keyID).
					WillReturnResult(sqlmock.NewResult(1, 1))
			},
			wantErr: false,
		},
		{
			name: "exec error returns error",
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(query).
					WithArgs(domainAPIKey.StatusRevoked, keyID).
					WillReturnError(errors.New("update failed"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			db, mock := setupMockDB(t)
			repo := NewAPIKeyRepository(db)

			tt.mockSetup(mock)

			err := repo.Revoke(context.Background(), keyID)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestSqlxAPIKeyRepository_RevokeAllByUserID(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	query := regexp.QuoteMeta("UPDATE api_keys SET status = $1 WHERE user_id = $2 AND status = $3")

	tests := []struct {
		name      string
		mockSetup func(mock sqlmock.Sqlmock)
		wantErr   bool
	}{
		{
			name: "success revoke all keys for user",
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(query).
					WithArgs(domainAPIKey.StatusRevoked, userID, domainAPIKey.StatusActive).
					WillReturnResult(sqlmock.NewResult(1, 3))
			},
			wantErr: false,
		},
		{
			name: "exec error returns error",
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(query).
					WithArgs(domainAPIKey.StatusRevoked, userID, domainAPIKey.StatusActive).
					WillReturnError(errors.New("revoke all failed"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			db, mock := setupMockDB(t)
			repo := NewAPIKeyRepository(db)

			tt.mockSetup(mock)

			err := repo.RevokeAllByUserID(context.Background(), userID)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestSqlxAPIKeyRepository_UpdateLastUsedAt(t *testing.T) {
	t.Parallel()

	keyID := uuid.New()
	query := regexp.QuoteMeta("UPDATE api_keys SET last_used_at = NOW() WHERE id = $1")

	tests := []struct {
		name      string
		mockSetup func(mock sqlmock.Sqlmock)
		wantErr   bool
	}{
		{
			name: "success update last used at",
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(query).
					WithArgs(keyID).
					WillReturnResult(sqlmock.NewResult(1, 1))
			},
			wantErr: false,
		},
		{
			name: "exec error returns error",
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(query).
					WithArgs(keyID).
					WillReturnError(errors.New("update failed"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			db, mock := setupMockDB(t)
			repo := NewAPIKeyRepository(db)

			tt.mockSetup(mock)

			err := repo.UpdateLastUsedAt(context.Background(), keyID)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestSqlxAPIKeyRepository_GetByID(t *testing.T) {
	t.Parallel()

	keyID := uuid.New()
	userID := uuid.New()
	now := time.Now()

	query := regexp.QuoteMeta("SELECT id, user_id, name, key_hash, status, created_at, expires_at, last_used_at FROM api_keys WHERE id = $1")

	tests := []struct {
		name      string
		mockSetup func(mock sqlmock.Sqlmock)
		wantNil   bool
		wantErr   bool
	}{
		{
			name: "success found key by ID",
			mockSetup: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"id", "user_id", "name", "key_hash", "status", "created_at", "expires_at", "last_used_at"}).
					AddRow(keyID, userID, "my-key", "abc123hash", domainAPIKey.StatusActive, now, nil, nil)
				mock.ExpectQuery(query).WithArgs(keyID).WillReturnRows(rows)
			},
			wantNil: false,
			wantErr: false,
		},
		{
			name: "not found returns nil without error",
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(query).WithArgs(keyID).WillReturnError(sql.ErrNoRows)
			},
			wantNil: true,
			wantErr: false,
		},
		{
			name: "database error returns error",
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(query).WithArgs(keyID).WillReturnError(errors.New("db error"))
			},
			wantNil: true,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			db, mock := setupMockDB(t)
			repo := NewAPIKeyRepository(db)

			tt.mockSetup(mock)

			res, err := repo.GetByID(context.Background(), keyID)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			if tt.wantNil {
				assert.Nil(t, res)
			} else {
				require.NotNil(t, res)
				assert.Equal(t, keyID, res.ID)
				assert.Equal(t, userID, res.UserID)
				assert.Equal(t, "my-key", res.Name)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestSqlxAPIKeyRepository_ExistsActiveByName(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	query := regexp.QuoteMeta("SELECT EXISTS(SELECT 1 FROM api_keys WHERE user_id = $1 AND name = $2 AND status = $3)")

	tests := []struct {
		name       string
		keyName    string
		mockSetup  func(mock sqlmock.Sqlmock)
		wantExists bool
		wantErr    bool
	}{
		{
			name:    "exists returns true",
			keyName: "my-key",
			mockSetup: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"exists"}).AddRow(true)
				mock.ExpectQuery(query).WithArgs(userID, "my-key", domainAPIKey.StatusActive).WillReturnRows(rows)
			},
			wantExists: true,
			wantErr:    false,
		},
		{
			name:    "not exists returns false",
			keyName: "other-key",
			mockSetup: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"exists"}).AddRow(false)
				mock.ExpectQuery(query).WithArgs(userID, "other-key", domainAPIKey.StatusActive).WillReturnRows(rows)
			},
			wantExists: false,
			wantErr:    false,
		},
		{
			name:    "database error returns error",
			keyName: "my-key",
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(query).WithArgs(userID, "my-key", domainAPIKey.StatusActive).WillReturnError(errors.New("db error"))
			},
			wantExists: false,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			db, mock := setupMockDB(t)
			repo := NewAPIKeyRepository(db)

			tt.mockSetup(mock)

			exists, err := repo.ExistsActiveByName(context.Background(), userID, tt.keyName)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantExists, exists)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}
