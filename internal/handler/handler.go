package handler

import (
	"database/sql"
	"encoding/json"
	"html/template"
	"net/http"
	"security/internal/auth"
	"security/internal/models"
	"time"
)

// ── LOGIN ──

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if auth.ValidSession(r) {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	errMsg := ""
	if r.URL.Query().Get("error") == "invalid" {
		errMsg = "Mot de passe incorrect."
	} else if r.URL.Query().Get("error") == "unauthorized" {
		errMsg = "Session expirée. Reconnectez-vous."
	}

	tmpl, err := template.ParseFiles("web/html/login.html")
	if err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.Execute(w, map[string]string{"Error": errMsg}) //nolint:errcheck
}

func APILoginHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		password := r.FormValue("password")
		if password == "" {
			http.Redirect(w, r, "/login?error=invalid", http.StatusSeeOther)
			return
		}

		if !auth.CheckPassword(password) {
			// Log tentative échouée
			go logFailedLogin(db, r)
			http.Redirect(w, r, "/login?error=invalid", http.StatusSeeOther)
			return
		}

		auth.CreateSession(w)
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
	}
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	auth.DestroySession(w, r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ── DASHBOARD ──

func DashboardHandler(db *sql.DB) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tmpl, err := template.ParseFiles("web/html/dashboard.html")
		if err != nil {
			http.Error(w, "Template error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		tmpl.Execute(w, nil) //nolint:errcheck
	})
}

// ── API STATS ──

func APIStatsHandler(db *sql.DB) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stats, err := getStats(db)
		if err != nil {
			http.Error(w, `{"error":"db error"}`, http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(stats) //nolint:errcheck
	})
}

// ── API EVENTS ──

func APIEventsHandler(db *sql.DB) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limit := 50
		eventType := r.URL.Query().Get("type") // "honeypot", "error", "ratelimit", ""

		events, err := getEvents(db, limit, eventType)
		if err != nil {
			http.Error(w, `{"error":"db error"}`, http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(events) //nolint:errcheck
	})
}

// ── API BLACKLIST ──

func APIBlacklistHandler(db *sql.DB) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		blacklist, err := getBlacklist(db)
		if err != nil {
			http.Error(w, `{"error":"db error"}`, http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(blacklist) //nolint:errcheck
	})
}

// ══════════════════════════════════════════
//  QUERIES
// ══════════════════════════════════════════

func getStats(db *sql.DB) (*models.DashboardStats, error) {
	stats := &models.DashboardStats{}

	// Total événements
	db.QueryRow(`SELECT COUNT(*) FROM security_events`).Scan(&stats.TotalEvents) //nolint:errcheck

	// Total blacklist active
	db.QueryRow(`SELECT COUNT(*) FROM blacklisted_ips WHERE expires_at > NOW()`).Scan(&stats.TotalBlacklist) //nolint:errcheck

	// Événements 24h
	db.QueryRow(`SELECT COUNT(*) FROM security_events WHERE created_at > NOW() - INTERVAL '24 hours'`).Scan(&stats.Events24h) //nolint:errcheck

	// Honeypots 24h
	db.QueryRow(`SELECT COUNT(*) FROM security_events WHERE event_type = 'honeypot' AND created_at > NOW() - INTERVAL '24 hours'`).Scan(&stats.Honeypots24h) //nolint:errcheck

	// Erreurs 24h
	db.QueryRow(`SELECT COUNT(*) FROM security_events WHERE event_type = 'error' AND created_at > NOW() - INTERVAL '24 hours'`).Scan(&stats.Errors24h) //nolint:errcheck

	// Top IPs
	rows, err := db.Query(`
		SELECT ip, COUNT(*) as count
		FROM security_events
		WHERE created_at > NOW() - INTERVAL '24 hours'
		GROUP BY ip
		ORDER BY count DESC
		LIMIT 10
	`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var ip models.IPCount
			rows.Scan(&ip.IP, &ip.Count) //nolint:errcheck
			stats.TopIPs = append(stats.TopIPs, ip)
		}
	}

	// Top paths
	rows2, err := db.Query(`
		SELECT path, COUNT(*) as count
		FROM security_events
		WHERE created_at > NOW() - INTERVAL '24 hours'
		GROUP BY path
		ORDER BY count DESC
		LIMIT 10
	`)
	if err == nil {
		defer rows2.Close()
		for rows2.Next() {
			var p models.PathCount
			rows2.Scan(&p.Path, &p.Count) //nolint:errcheck
			stats.TopPaths = append(stats.TopPaths, p)
		}
	}

	// Événements par heure (24h)
	rows3, err := db.Query(`
		SELECT EXTRACT(HOUR FROM created_at)::INT as hour, COUNT(*) as count
		FROM security_events
		WHERE created_at > NOW() - INTERVAL '24 hours'
		GROUP BY hour
		ORDER BY hour
	`)
	if err == nil {
		defer rows3.Close()
		for rows3.Next() {
			var h models.HourCount
			rows3.Scan(&h.Hour, &h.Count) //nolint:errcheck
			stats.EventsByHour = append(stats.EventsByHour, h)
		}
	}

	// Événements récents
	rows4, err := db.Query(`
		SELECT id, created_at, ip, method, path, status, COALESCE(user_agent,''), COALESCE(country,''), event_type
		FROM security_events
		ORDER BY created_at DESC
		LIMIT 20
	`)
	if err == nil {
		defer rows4.Close()
		for rows4.Next() {
			var e models.SecurityEvent
			rows4.Scan(&e.ID, &e.CreatedAt, &e.IP, &e.Method, &e.Path, &e.Status, &e.UserAgent, &e.Country, &e.EventType) //nolint:errcheck
			stats.RecentEvents = append(stats.RecentEvents, e)
		}
	}

	return stats, nil
}

func getEvents(db *sql.DB, limit int, eventType string) ([]models.SecurityEvent, error) {
	var rows *sql.Rows
	var err error

	if eventType != "" {
		rows, err = db.Query(`
			SELECT id, created_at, ip, method, path, status, COALESCE(user_agent,''), COALESCE(country,''), event_type
			FROM security_events
			WHERE event_type = $1
			ORDER BY created_at DESC
			LIMIT $2
		`, eventType, limit)
	} else {
		rows, err = db.Query(`
			SELECT id, created_at, ip, method, path, status, COALESCE(user_agent,''), COALESCE(country,''), event_type
			FROM security_events
			ORDER BY created_at DESC
			LIMIT $1
		`, limit)
	}

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []models.SecurityEvent
	for rows.Next() {
		var e models.SecurityEvent
		rows.Scan(&e.ID, &e.CreatedAt, &e.IP, &e.Method, &e.Path, &e.Status, &e.UserAgent, &e.Country, &e.EventType) //nolint:errcheck
		events = append(events, e)
	}

	return events, nil
}

func getBlacklist(db *sql.DB) ([]models.BlacklistedIP, error) {
	rows, err := db.Query(`
		SELECT id, ip, reason, created_at, expires_at
		FROM blacklisted_ips
		WHERE expires_at > NOW()
		ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []models.BlacklistedIP
	for rows.Next() {
		var b models.BlacklistedIP
		rows.Scan(&b.ID, &b.IP, &b.Reason, &b.CreatedAt, &b.ExpiresAt) //nolint:errcheck
		list = append(list, b)
	}

	return list, nil
}

func logFailedLogin(db *sql.DB, r *http.Request) {
	ip := r.Header.Get("CF-Connecting-IP")
	if ip == "" {
		ip = r.RemoteAddr
	}

	db.Exec(`
		INSERT INTO security_events (ip, method, path, status, user_agent, event_type)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, ip, r.Method, "/api/login", 401, r.UserAgent(), "brute_force") //nolint:errcheck

	// Blackliste après 5 tentatives en 10 minutes
	var count int
	db.QueryRow(`
		SELECT COUNT(*) FROM security_events
		WHERE ip = $1 AND event_type = 'brute_force'
		AND created_at > NOW() - INTERVAL '10 minutes'
	`, ip).Scan(&count) //nolint:errcheck

	if count >= 5 {
		db.Exec(`
			INSERT INTO blacklisted_ips (ip, reason, expires_at)
			VALUES ($1, $2, $3)
			ON CONFLICT (ip) DO UPDATE SET expires_at = $3
		`, ip, "brute_force_login", time.Now().Add(24*time.Hour)) //nolint:errcheck
	}
}
