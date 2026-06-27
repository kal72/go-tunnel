package postgres

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSettingRepository_GetSetting(t *testing.T) {
	t.Parallel()

	query := regexp.QuoteMeta("SELECT value FROM system_settings WHERE key = $1")

	tests := []struct {
		name      string
		key       string
		mockSetup func(mock sqlmock.Sqlmock)
		wantVal   string
		wantErr   bool
	}{
		{
			name: "success returns unmarshaled json string",
			key:  "app_name",
			mockSetup: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"value"}).AddRow([]byte(`"GoTunnel"`))
				mock.ExpectQuery(query).WithArgs("app_name").WillReturnRows(rows)
			},
			wantVal: "GoTunnel",
			wantErr: false,
		},
		{
			name: "success returns raw string fallback if unmarshal fails",
			key:  "raw_key",
			mockSetup: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"value"}).AddRow([]byte(`raw-unquoted-value`))
				mock.ExpectQuery(query).WithArgs("raw_key").WillReturnRows(rows)
			},
			wantVal: "raw-unquoted-value",
			wantErr: false,
		},
		{
			name: "not found returns empty string without error",
			key:  "missing_key",
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(query).WithArgs("missing_key").WillReturnError(sql.ErrNoRows)
			},
			wantVal: "",
			wantErr: false,
		},
		{
			name: "database error returns error",
			key:  "err_key",
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(query).WithArgs("err_key").WillReturnError(errors.New("db error"))
			},
			wantVal: "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			db, mock := setupMockDB(t)
			repo := NewSettingRepository(db)

			tt.mockSetup(mock)

			res, err := repo.GetSetting(context.Background(), tt.key)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantVal, res)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestSettingRepository_SetSetting(t *testing.T) {
	t.Parallel()

	query := regexp.QuoteMeta("INSERT INTO system_settings (key, value, updated_at)")

	tests := []struct {
		name      string
		key       string
		val       string
		mockSetup func(mock sqlmock.Sqlmock)
		wantErr   bool
	}{
		{
			name: "success set setting",
			key:  "theme",
			val:  "dark",
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(query).
					WithArgs("theme", []byte(`"dark"`)).
					WillReturnResult(sqlmock.NewResult(1, 1))
			},
			wantErr: false,
		},
		{
			name: "database error returns error",
			key:  "theme",
			val:  "dark",
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(query).
					WithArgs("theme", []byte(`"dark"`)).
					WillReturnError(errors.New("insert or update failed"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			db, mock := setupMockDB(t)
			repo := NewSettingRepository(db)

			tt.mockSetup(mock)

			err := repo.SetSetting(context.Background(), tt.key, tt.val)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestSettingRepository_GetAllSettings(t *testing.T) {
	t.Parallel()

	query := regexp.QuoteMeta("SELECT key, value FROM system_settings")

	tests := []struct {
		name      string
		mockSetup func(mock sqlmock.Sqlmock)
		wantLen   int
		wantErr   bool
	}{
		{
			name: "success returns map of settings",
			mockSetup: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"key", "value"}).
					AddRow("app_name", []byte(`"GoTunnel"`)).
					AddRow("raw_val", []byte(`raw-string`))
				mock.ExpectQuery(query).WillReturnRows(rows)
			},
			wantLen: 2,
			wantErr: false,
		},
		{
			name: "empty rows returns non-nil empty map",
			mockSetup: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"key", "value"})
				mock.ExpectQuery(query).WillReturnRows(rows)
			},
			wantLen: 0,
			wantErr: false,
		},
		{
			name: "query error returns error",
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(query).WillReturnError(errors.New("query failed"))
			},
			wantLen: 0,
			wantErr: true,
		},
		{
			name: "scan error during row iteration returns error",
			mockSetup: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"key", "value"}).
					AddRow(nil, []byte(`"GoTunnel"`))
				mock.ExpectQuery(query).WillReturnRows(rows)
			},
			wantLen: 0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			db, mock := setupMockDB(t)
			repo := NewSettingRepository(db)

			tt.mockSetup(mock)

			res, err := repo.GetAllSettings(context.Background())
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, res)
				assert.Len(t, res, tt.wantLen)
				if tt.wantLen == 2 {
					assert.Equal(t, "GoTunnel", res["app_name"])
					assert.Equal(t, "raw-string", res["raw_val"])
				}
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}
