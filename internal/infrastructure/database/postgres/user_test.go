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

	domainUser "gotunnel/internal/domain/user"
)

func TestSqlxUserRepository_GetUserByUsername(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	now := time.Now()
	query := regexp.QuoteMeta("SELECT id, username, password, role, status, created_at, updated_at FROM users WHERE username = $1")

	tests := []struct {
		name      string
		username  string
		mockSetup func(mock sqlmock.Sqlmock)
		wantNil   bool
		wantErr   bool
	}{
		{
			name:     "success found user",
			username: "admin",
			mockSetup: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"id", "username", "password", "role", "status", "created_at", "updated_at"}).
					AddRow(userID, "admin", "hash", int16(1), int16(1), now, now)
				mock.ExpectQuery(query).WithArgs("admin").WillReturnRows(rows)
			},
			wantNil: false,
			wantErr: false,
		},
		{
			name:     "not found returns nil without error",
			username: "unknown",
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(query).WithArgs("unknown").WillReturnError(sql.ErrNoRows)
			},
			wantNil: true,
			wantErr: false,
		},
		{
			name:     "database error returns error",
			username: "admin",
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(query).WithArgs("admin").WillReturnError(errors.New("db error"))
			},
			wantNil: true,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			db, mock := setupMockDB(t)
			repo := NewUserRepository(db)

			tt.mockSetup(mock)

			res, err := repo.GetUserByUsername(context.Background(), tt.username)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			if tt.wantNil {
				assert.Nil(t, res)
			} else {
				require.NotNil(t, res)
				assert.Equal(t, tt.username, res.Username)
				assert.Equal(t, userID, res.ID)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestSqlxUserRepository_CreateUser(t *testing.T) {
	t.Parallel()

	user := &domainUser.User{
		Username: "newuser",
		Password: "hashedpassword",
		Role:     2,
		Status:   1,
	}
	query := `INSERT INTO users`

	tests := []struct {
		name      string
		mockSetup func(mock sqlmock.Sqlmock)
		wantErr   bool
	}{
		{
			name: "success create user",
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(query).
					WithArgs(user.Username, user.Password, user.Role, user.Status).
					WillReturnResult(sqlmock.NewResult(1, 1))
			},
			wantErr: false,
		},
		{
			name: "exec error returns error",
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(query).
					WithArgs(user.Username, user.Password, user.Role, user.Status).
					WillReturnError(errors.New("insert failed"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			db, mock := setupMockDB(t)
			repo := NewUserRepository(db)

			tt.mockSetup(mock)

			err := repo.CreateUser(context.Background(), user)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestSqlxUserRepository_UpdateUserStatus(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	status := int16(2)
	query := regexp.QuoteMeta("UPDATE users SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2")

	tests := []struct {
		name      string
		mockSetup func(mock sqlmock.Sqlmock)
		wantErr   bool
	}{
		{
			name: "success update user status",
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(query).WithArgs(status, userID).WillReturnResult(sqlmock.NewResult(1, 1))
			},
			wantErr: false,
		},
		{
			name: "exec error returns error",
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(query).WithArgs(status, userID).WillReturnError(errors.New("update status failed"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			db, mock := setupMockDB(t)
			repo := NewUserRepository(db)

			tt.mockSetup(mock)

			err := repo.UpdateUserStatus(context.Background(), userID, status)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestSqlxUserRepository_UpdateUserPassword(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	passwordHash := "newhashedpassword"
	query := regexp.QuoteMeta("UPDATE users SET password = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2")

	tests := []struct {
		name      string
		mockSetup func(mock sqlmock.Sqlmock)
		wantErr   bool
	}{
		{
			name: "success update user password",
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(query).WithArgs(passwordHash, userID).WillReturnResult(sqlmock.NewResult(1, 1))
			},
			wantErr: false,
		},
		{
			name: "exec error returns error",
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(query).WithArgs(passwordHash, userID).WillReturnError(errors.New("update password failed"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			db, mock := setupMockDB(t)
			repo := NewUserRepository(db)

			tt.mockSetup(mock)

			err := repo.UpdateUserPassword(context.Background(), userID, passwordHash)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestSqlxUserRepository_DeleteUser(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	query := regexp.QuoteMeta("DELETE FROM users WHERE id = $1")

	tests := []struct {
		name      string
		mockSetup func(mock sqlmock.Sqlmock)
		wantErr   bool
	}{
		{
			name: "success delete user",
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(query).WithArgs(userID).WillReturnResult(sqlmock.NewResult(1, 1))
			},
			wantErr: false,
		},
		{
			name: "exec error returns error",
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(query).WithArgs(userID).WillReturnError(errors.New("delete failed"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			db, mock := setupMockDB(t)
			repo := NewUserRepository(db)

			tt.mockSetup(mock)

			err := repo.DeleteUser(context.Background(), userID)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestSqlxUserRepository_GetUsers(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	now := time.Now()
	query := regexp.QuoteMeta("SELECT id, username, password, role, status, created_at, updated_at FROM users ORDER BY created_at DESC")

	tests := []struct {
		name      string
		mockSetup func(mock sqlmock.Sqlmock)
		wantCount int
		wantErr   bool
	}{
		{
			name: "success get all users",
			mockSetup: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"id", "username", "password", "role", "status", "created_at", "updated_at"}).
					AddRow(userID, "admin", "hash", int16(1), int16(1), now, now).
					AddRow(uuid.New(), "user1", "hash", int16(2), int16(1), now, now)
				mock.ExpectQuery(query).WillReturnRows(rows)
			},
			wantCount: 2,
			wantErr:   false,
		},
		{
			name: "empty result returns zero length slice",
			mockSetup: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"id", "username", "password", "role", "status", "created_at", "updated_at"})
				mock.ExpectQuery(query).WillReturnRows(rows)
			},
			wantCount: 0,
			wantErr:   false,
		},
		{
			name: "database error returns error",
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(query).WillReturnError(errors.New("select error"))
			},
			wantCount: 0,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			db, mock := setupMockDB(t)
			repo := NewUserRepository(db)

			tt.mockSetup(mock)

			res, err := repo.GetUsers(context.Background())
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tt.wantCount > 0 {
					require.NotNil(t, res)
				}
				assert.Len(t, res, tt.wantCount)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}
