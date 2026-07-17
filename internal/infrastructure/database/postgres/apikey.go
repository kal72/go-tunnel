package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	domainAPIKey "gotunnel/internal/domain/apikey"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

type sqlxAPIKeyRepository struct {
	db *sqlx.DB
}

// NewAPIKeyRepository creates a new PostgreSQL-backed API key repository.
func NewAPIKeyRepository(db *sqlx.DB) domainAPIKey.APIKeyRepository {
	return &sqlxAPIKeyRepository{db: db}
}

func (r *sqlxAPIKeyRepository) Create(ctx context.Context, key *domainAPIKey.APIKey) error {
	query := `INSERT INTO api_keys (id, user_id, name, key_hash, status, created_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7)`
	_, err := r.db.ExecContext(ctx, query, key.ID, key.UserID, key.Name, key.KeyHash, key.Status, key.CreatedAt, key.ExpiresAt)
	if err != nil {
		return fmt.Errorf("Create API key error: %w", err)
	}
	return nil
}

func (r *sqlxAPIKeyRepository) GetByHash(ctx context.Context, keyHash string) (*domainAPIKey.APIKey, error) {
	var key domainAPIKey.APIKey
	query := `SELECT id, user_id, name, key_hash, status, created_at, expires_at, last_used_at FROM api_keys WHERE key_hash = $1`
	err := r.db.GetContext(ctx, &key, query, keyHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil //nolint:nilnil // Return nil if not found
		}
		return nil, fmt.Errorf("GetByHash error: %w", err)
	}
	return &key, nil
}

func (r *sqlxAPIKeyRepository) GetByID(ctx context.Context, id uuid.UUID) (*domainAPIKey.APIKey, error) {
	var key domainAPIKey.APIKey
	query := `SELECT id, user_id, name, key_hash, status, created_at, expires_at, last_used_at FROM api_keys WHERE id = $1`
	err := r.db.GetContext(ctx, &key, query, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil //nolint:nilnil // Return nil if not found
		}
		return nil, fmt.Errorf("GetByID error: %w", err)
	}
	return &key, nil
}

func (r *sqlxAPIKeyRepository) ListByUserID(ctx context.Context, userID uuid.UUID, limit, offset int) ([]domainAPIKey.APIKey, int, error) {
	var keys []domainAPIKey.APIKey
	query := `
		SELECT id, user_id, name, status, created_at, expires_at, last_used_at,
		       COUNT(*) OVER() AS total_count
		FROM api_keys
		WHERE user_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`

	rows, err := r.db.QueryxContext(ctx, query, userID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("ListByUserID error: %w", err)
	}
	defer rows.Close()

	var totalCount int
	for rows.Next() {
		var key domainAPIKey.APIKey
		var count int
		err := rows.Scan(&key.ID, &key.UserID, &key.Name, &key.Status, &key.CreatedAt, &key.ExpiresAt, &key.LastUsedAt, &count)
		if err != nil {
			return nil, 0, fmt.Errorf("ListByUserID scan error: %w", err)
		}
		totalCount = count
		keys = append(keys, key)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("ListByUserID rows error: %w", err)
	}

	return keys, totalCount, nil
}

func (r *sqlxAPIKeyRepository) ListAll(ctx context.Context, limit, offset int, usernameFilter string) ([]domainAPIKey.APIKeyWithOwner, int, error) {
	var keys []domainAPIKey.APIKeyWithOwner
	var query string
	var args []interface{}

	if usernameFilter != "" {
		query = `
			SELECT ak.id, ak.user_id, ak.name, ak.status, ak.created_at, ak.expires_at, ak.last_used_at,
			       u.username,
			       COUNT(*) OVER() AS total_count
			FROM api_keys ak
			JOIN users u ON u.id = ak.user_id
			WHERE u.username ILIKE $1
			ORDER BY ak.created_at DESC
			LIMIT $2 OFFSET $3
		`
		args = []interface{}{"%" + usernameFilter + "%", limit, offset}
	} else {
		query = `
			SELECT ak.id, ak.user_id, ak.name, ak.status, ak.created_at, ak.expires_at, ak.last_used_at,
			       u.username,
			       COUNT(*) OVER() AS total_count
			FROM api_keys ak
			JOIN users u ON u.id = ak.user_id
			ORDER BY ak.created_at DESC
			LIMIT $1 OFFSET $2
		`
		args = []interface{}{limit, offset}
	}

	rows, err := r.db.QueryxContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("ListAll error: %w", err)
	}
	defer rows.Close()

	var totalCount int
	for rows.Next() {
		var key domainAPIKey.APIKeyWithOwner
		var count int
		err := rows.Scan(
			&key.ID, &key.UserID, &key.Name, &key.Status,
			&key.CreatedAt, &key.ExpiresAt, &key.LastUsedAt,
			&key.Username, &count,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("ListAll scan error: %w", err)
		}
		totalCount = count
		keys = append(keys, key)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("ListAll rows error: %w", err)
	}

	return keys, totalCount, nil
}

func (r *sqlxAPIKeyRepository) CountActiveByUserID(ctx context.Context, userID uuid.UUID) (int, error) {
	var count int
	query := `SELECT COUNT(*) FROM api_keys WHERE user_id = $1 AND status = $2 AND (expires_at IS NULL OR expires_at > NOW())`
	err := r.db.GetContext(ctx, &count, query, userID, domainAPIKey.StatusActive)
	if err != nil {
		return 0, fmt.Errorf("CountActiveByUserID error: %w", err)
	}
	return count, nil
}

func (r *sqlxAPIKeyRepository) ExistsActiveByName(ctx context.Context, userID uuid.UUID, name string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM api_keys WHERE user_id = $1 AND name = $2 AND status = $3)`
	err := r.db.GetContext(ctx, &exists, query, userID, name, domainAPIKey.StatusActive)
	if err != nil {
		return false, fmt.Errorf("ExistsActiveByName error: %w", err)
	}
	return exists, nil
}

func (r *sqlxAPIKeyRepository) Revoke(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE api_keys SET status = $1 WHERE id = $2`
	_, err := r.db.ExecContext(ctx, query, domainAPIKey.StatusRevoked, id)
	if err != nil {
		return fmt.Errorf("Revoke error: %w", err)
	}
	return nil
}

func (r *sqlxAPIKeyRepository) UpdateLastUsedAt(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE api_keys SET last_used_at = NOW() WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("UpdateLastUsedAt error: %w", err)
	}
	return nil
}

func (r *sqlxAPIKeyRepository) RevokeAllByUserID(ctx context.Context, userID uuid.UUID) error {
	query := `UPDATE api_keys SET status = $1 WHERE user_id = $2 AND status = $3`
	_, err := r.db.ExecContext(ctx, query, domainAPIKey.StatusRevoked, userID, domainAPIKey.StatusActive)
	if err != nil {
		return fmt.Errorf("RevokeAllByUserID error: %w", err)
	}
	return nil
}

func (r *sqlxAPIKeyRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM api_keys WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("Delete error: %w", err)
	}
	return nil
}
