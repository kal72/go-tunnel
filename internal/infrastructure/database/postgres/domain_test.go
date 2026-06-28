package postgres

import (
	"context"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDomainRepository_Ping(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		mockSetup func(mock sqlmock.Sqlmock)
	}{
		{
			name: "ping success",
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectPing()
			},
		},
		{
			name: "ping failure logs error cleanly",
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectPing().WillReturnError(errors.New("ping failed"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			db, mock := setupMockDB(t)
			repo := NewDomainRepository(db)

			tt.mockSetup(mock)

			assert.NotPanics(t, func() {
				repo.Ping(context.Background())
			})

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestDomainRepository_AddDomain(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	domainName := "test.example.com"
	query := regexp.QuoteMeta("INSERT INTO domains (domain, user_id) VALUES ($1, $2)")

	tests := []struct {
		name      string
		mockSetup func(mock sqlmock.Sqlmock)
		wantErr   bool
	}{
		{
			name: "success add domain",
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(query).WithArgs(domainName, userID).WillReturnResult(sqlmock.NewResult(1, 1))
			},
			wantErr: false,
		},
		{
			name: "database error returns error",
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(query).WithArgs(domainName, userID).WillReturnError(errors.New("insert failed"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			db, mock := setupMockDB(t)
			repo := NewDomainRepository(db)

			tt.mockSetup(mock)

			err := repo.AddDomain(context.Background(), domainName, userID)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestDomainRepository_RemoveDomain(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	domainName := "test.example.com"
	adminQuery := regexp.QuoteMeta("DELETE FROM domains WHERE domain = $1")
	userQuery := regexp.QuoteMeta("DELETE FROM domains WHERE domain = $1 AND user_id = $2")

	tests := []struct {
		name      string
		role      int16
		mockSetup func(mock sqlmock.Sqlmock)
		wantErr   bool
		errMsg    string
	}{
		{
			name: "admin remove domain success",
			role: 1,
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(adminQuery).WithArgs(domainName).WillReturnResult(sqlmock.NewResult(1, 1))
			},
			wantErr: false,
		},
		{
			name: "user remove domain success",
			role: 2,
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(userQuery).WithArgs(domainName, userID).WillReturnResult(sqlmock.NewResult(1, 1))
			},
			wantErr: false,
		},
		{
			name: "exec error returns error",
			role: 2,
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(userQuery).WithArgs(domainName, userID).WillReturnError(errors.New("db error"))
			},
			wantErr: true,
		},
		{
			name: "rows affected error returns error",
			role: 1,
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(adminQuery).WithArgs(domainName).WillReturnResult(sqlmock.NewErrorResult(errors.New("rows affected error")))
			},
			wantErr: true,
		},
		{
			name: "0 rows affected returns unauthorized error",
			role: 2,
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(userQuery).WithArgs(domainName, userID).WillReturnResult(sqlmock.NewResult(1, 0))
			},
			wantErr: true,
			errMsg:  "domain not found or unauthorized to delete",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			db, mock := setupMockDB(t)
			repo := NewDomainRepository(db)

			tt.mockSetup(mock)

			err := repo.RemoveDomain(context.Background(), domainName, userID, tt.role)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestDomainRepository_ListDomains(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	now := time.Now()
	adminQuery := regexp.QuoteMeta("SELECT domain, user_id, created_at FROM domains ORDER BY created_at DESC")
	userQuery := regexp.QuoteMeta("SELECT domain, user_id, created_at FROM domains WHERE user_id = $1 ORDER BY created_at DESC")

	tests := []struct {
		name      string
		role      int16
		mockSetup func(mock sqlmock.Sqlmock)
		wantCount int
		wantErr   bool
	}{
		{
			name: "admin list domains returns all",
			role: 1,
			mockSetup: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"domain", "user_id", "created_at"}).
					AddRow("admin.example.com", userID, now).
					AddRow("other.example.com", uuid.New(), now)
				mock.ExpectQuery(adminQuery).WillReturnRows(rows)
			},
			wantCount: 2,
			wantErr:   false,
		},
		{
			name: "user list domains returns filtered by user id",
			role: 2,
			mockSetup: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"domain", "user_id", "created_at"}).
					AddRow("user.example.com", userID, now)
				mock.ExpectQuery(userQuery).WithArgs(userID).WillReturnRows(rows)
			},
			wantCount: 1,
			wantErr:   false,
		},
		{
			name: "database error returns error",
			role: 2,
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(userQuery).WithArgs(userID).WillReturnError(errors.New("select error"))
			},
			wantCount: 0,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			db, mock := setupMockDB(t)
			repo := NewDomainRepository(db)

			tt.mockSetup(mock)

			res, err := repo.ListDomains(context.Background(), userID, tt.role)
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

func TestDomainRepository_IsDomainAllowed(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	domainName := "test.example.com"
	adminQuery := regexp.QuoteMeta("SELECT COUNT(*) FROM domains WHERE domain = $1")
	userQuery := regexp.QuoteMeta("SELECT COUNT(*) FROM domains WHERE domain = $1 AND user_id = $2")

	tests := []struct {
		name      string
		role      int16
		mockSetup func(mock sqlmock.Sqlmock)
		want      bool
		wantErr   bool
	}{
		{
			name: "admin check domain allowed true",
			role: 1,
			mockSetup: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"count"}).AddRow(1)
				mock.ExpectQuery(adminQuery).WithArgs(domainName).WillReturnRows(rows)
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "user check domain allowed false when count is 0",
			role: 2,
			mockSetup: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"count"}).AddRow(0)
				mock.ExpectQuery(userQuery).WithArgs(domainName, userID).WillReturnRows(rows)
			},
			want:    false,
			wantErr: false,
		},
		{
			name: "database error returns error",
			role: 2,
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(userQuery).WithArgs(domainName, userID).WillReturnError(errors.New("db error"))
			},
			want:    false,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			db, mock := setupMockDB(t)
			repo := NewDomainRepository(db)

			tt.mockSetup(mock)

			allowed, err := repo.IsDomainAllowed(context.Background(), domainName, userID, tt.role)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, allowed)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}
