package postgres

import (
	"fmt"
	"log"

	"gotunnel/internal/config"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

//coverage:ignore file
func InitDB(env *config.ServerConfig) (*sqlx.DB, error) {
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		env.DBHost, env.DBPort, env.DBUser, env.DBPass, env.DBName, env.DBSSLMode)

	db, err := sqlx.Connect("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to db: %w", err)
	}

	log.Println("Database connection successful")
	return db, nil
}
