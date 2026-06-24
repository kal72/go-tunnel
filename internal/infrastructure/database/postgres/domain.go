package postgres

import (
	"context"
	"fmt"
	"log"

	domainTunnel "gotunnel/internal/domain/tunnel"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

type DomainRepository struct {
	db *sqlx.DB
}

func NewDomainRepository(db *sqlx.DB) *DomainRepository {
	return &DomainRepository{db: db}
}

func (r *DomainRepository) Ping(ctx context.Context) {
	err := r.db.PingContext(ctx)
	if err != nil {
		log.Println("Postgres domain store connection failed:", err)
		return
	}
	log.Println("Postgres domain store connected")
}

func (r *DomainRepository) AddDomain(ctx context.Context, domain string, userID uuid.UUID) error {
	query := `INSERT INTO domains (domain, user_id) VALUES ($1, $2)`
	_, err := r.db.ExecContext(ctx, query, domain, userID)
	if err != nil {
		return fmt.Errorf("failed to add domain: %w", err)
	}
	return nil
}

func (r *DomainRepository) RemoveDomain(ctx context.Context, domain string, userID uuid.UUID, role int16) error {
	var query string
	var args []interface{}

	if role == 1 { // Admin
		query = `DELETE FROM domains WHERE domain = $1`
		args = []interface{}{domain}
	} else { // User
		query = `DELETE FROM domains WHERE domain = $1 AND user_id = $2`
		args = []interface{}{domain, userID}
	}

	result, err := r.db.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to remove domain: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return fmt.Errorf("domain not found or unauthorized to delete")
	}

	return nil
}

func (r *DomainRepository) ListDomains(ctx context.Context, userID uuid.UUID, role int16) ([]domainTunnel.Domain, error) {
	var domains []domainTunnel.Domain
	var query string
	var args []interface{}

	if role == 1 { // Admin
		query = `SELECT domain, user_id, created_at FROM domains ORDER BY created_at DESC`
	} else { // User
		query = `SELECT domain, user_id, created_at FROM domains WHERE user_id = $1 ORDER BY created_at DESC`
		args = []interface{}{userID}
	}

	err := r.db.SelectContext(ctx, &domains, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list domains: %w", err)
	}

	return domains, nil
}

func (r *DomainRepository) IsDomainAllowed(ctx context.Context, domain string, userID uuid.UUID, role int16) (bool, error) {
	var count int
	var query string
	var args []interface{}

	if role == 1 { // Admin
		query = `SELECT COUNT(*) FROM domains WHERE domain = $1`
		args = []interface{}{domain}
	} else { // User
		query = `SELECT COUNT(*) FROM domains WHERE domain = $1 AND user_id = $2`
		args = []interface{}{domain, userID}
	}

	err := r.db.GetContext(ctx, &count, query, args...)
	if err != nil {
		return false, fmt.Errorf("failed to check domain: %w", err)
	}

	return count > 0, nil
}
