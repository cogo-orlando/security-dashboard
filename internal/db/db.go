package db

import (
	"database/sql"
	"fmt"
	"os"

	_ "github.com/lib/pq"
)

// Connect ouvre la connexion à Supabase via DATABASE_URL
func Connect() (*sql.DB, error) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return nil, fmt.Errorf("DATABASE_URL non définie")
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("sql.Open: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("db.Ping: %w", err)
	}

	// Pool de connexions
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)

	return db, nil
}

// Migrate crée les tables si elles n'existent pas
func Migrate(db *sql.DB) error {
	queries := []string{
		// Table des événements de sécurité
		`CREATE TABLE IF NOT EXISTS security_events (
			id         BIGSERIAL PRIMARY KEY,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			ip         TEXT NOT NULL,
			method     TEXT NOT NULL,
			path       TEXT NOT NULL,
			status     INT NOT NULL,
			user_agent TEXT,
			country    TEXT,
			event_type TEXT NOT NULL DEFAULT 'request'
		)`,

		// Table des IPs blacklistées
		`CREATE TABLE IF NOT EXISTS blacklisted_ips (
			id         BIGSERIAL PRIMARY KEY,
			ip         TEXT NOT NULL UNIQUE,
			reason     TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			expires_at TIMESTAMPTZ NOT NULL
		)`,

		// Table des métriques journalières
		`CREATE TABLE IF NOT EXISTS daily_stats (
			id           BIGSERIAL PRIMARY KEY,
			date         DATE NOT NULL UNIQUE,
			total_req    INT NOT NULL DEFAULT 0,
			unique_ips   INT NOT NULL DEFAULT 0,
			errors_4xx   INT NOT NULL DEFAULT 0,
			errors_5xx   INT NOT NULL DEFAULT 0,
			honeypot_hit INT NOT NULL DEFAULT 0
		)`,

		// Index pour les requêtes fréquentes
		`CREATE INDEX IF NOT EXISTS idx_events_created_at ON security_events(created_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_events_ip ON security_events(ip)`,
		`CREATE INDEX IF NOT EXISTS idx_events_type ON security_events(event_type)`,
		`CREATE INDEX IF NOT EXISTS idx_blacklist_expires ON blacklisted_ips(expires_at)`,
	}

	for _, q := range queries {
		if _, err := db.Exec(q); err != nil {
			return fmt.Errorf("migration failed: %w\nquery: %s", err, q)
		}
	}

	return nil
}
