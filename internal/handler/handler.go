package handler

import (
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"security/internal/auth"
	"security/internal/models"
	"strconv"
	"strings"
	"time"
)

// ══════════════════════════════════════════
//  LOGIN
// ══════════════════════════════════════════

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

// ══════════════════════════════════════════
//  DASHBOARD
// ══════════════════════════════════════════

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

// ══════════════════════════════════════════
//  API STATS
// ══════════════════════════════════════════

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

// ══════════════════════════════════════════
//  API EVENTS — avec recherche et pagination
// ══════════════════════════════════════════

func APIEventsHandler(db *sql.DB) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limit := 50
		if l := r.URL.Query().Get("limit"); l != "" {
			if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 200 {
				limit = n
			}
		}

		eventType := r.URL.Query().Get("type")
		search := r.URL.Query().Get("q") // recherche par IP ou path

		events, err := getEvents(db, limit, eventType, search)
		if err != nil {
			http.Error(w, `{"error":"db error"}`, http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(events) //nolint:errcheck
	})
}

// ══════════════════════════════════════════
//  API BLACKLIST
// ══════════════════════════════════════════

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
//  API USER AGENTS — top navigateurs/bots
// ══════════════════════════════════════════

func APIAgentsHandler(db *sql.DB) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rows, err := db.Query(`
			SELECT
				CASE
					WHEN user_agent ILIKE '%bot%' OR user_agent ILIKE '%crawler%' OR user_agent ILIKE '%spider%' THEN 'Bot'
					WHEN user_agent ILIKE '%chrome%' THEN 'Chrome'
					WHEN user_agent ILIKE '%firefox%' THEN 'Firefox'
					WHEN user_agent ILIKE '%safari%' AND user_agent NOT ILIKE '%chrome%' THEN 'Safari'
					WHEN user_agent ILIKE '%curl%' THEN 'curl'
					WHEN user_agent ILIKE '%python%' THEN 'Python'
					WHEN user_agent ILIKE '%go-http%' OR user_agent ILIKE '%go http%' THEN 'Go HTTP'
					WHEN user_agent = '' THEN 'Unknown'
					ELSE 'Other'
				END AS agent_type,
				COUNT(*) as count
			FROM security_events
			WHERE created_at > NOW() - INTERVAL '24 hours'
			GROUP BY agent_type
			ORDER BY count DESC
		`)
		if err != nil {
			http.Error(w, `{"error":"db error"}`, http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		type AgentCount struct {
			Agent string `json:"agent"`
			Count int    `json:"count"`
		}

		var agents []AgentCount
		for rows.Next() {
			var a AgentCount
			rows.Scan(&a.Agent, &a.Count) //nolint:errcheck
			agents = append(agents, a)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(agents) //nolint:errcheck
	})
}

// ══════════════════════════════════════════
//  API ERREURS GROUPÉES — top 404/500 par path
// ══════════════════════════════════════════

func APIErrorsHandler(db *sql.DB) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rows, err := db.Query(`
			SELECT path, status, COUNT(*) as count
			FROM security_events
			WHERE status >= 400
			AND created_at > NOW() - INTERVAL '24 hours'
			GROUP BY path, status
			ORDER BY count DESC
			LIMIT 20
		`)
		if err != nil {
			http.Error(w, `{"error":"db error"}`, http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		type ErrorCount struct {
			Path   string `json:"path"`
			Status int    `json:"status"`
			Count  int    `json:"count"`
		}

		var errors []ErrorCount
		for rows.Next() {
			var e ErrorCount
			rows.Scan(&e.Path, &e.Status, &e.Count) //nolint:errcheck
			errors = append(errors, e)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(errors) //nolint:errcheck
	})
}

// ══════════════════════════════════════════
//  API TENDANCES — comparaison 24h vs 48h
// ══════════════════════════════════════════

func APITrendsHandler(db *sql.DB) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		type Period struct {
			Total    int `json:"total"`
			Honeypot int `json:"honeypot"`
			Errors   int `json:"errors"`
		}

		type Trends struct {
			Current  Period  `json:"current"`
			Previous Period  `json:"previous"`
			DeltaReq float64 `json:"delta_req"`
			DeltaHp  float64 `json:"delta_hp"`
			DeltaErr float64 `json:"delta_err"`
		}

		var curr, prev Period

		// Période actuelle — 0 à 24h
		db.QueryRow(`SELECT COUNT(*) FROM security_events WHERE created_at > NOW() - INTERVAL '24 hours'`).Scan(&curr.Total)                                //nolint:errcheck
		db.QueryRow(`SELECT COUNT(*) FROM security_events WHERE event_type = 'honeypot' AND created_at > NOW() - INTERVAL '24 hours'`).Scan(&curr.Honeypot) //nolint:errcheck
		db.QueryRow(`SELECT COUNT(*) FROM security_events WHERE status >= 400 AND created_at > NOW() - INTERVAL '24 hours'`).Scan(&curr.Errors)             //nolint:errcheck

		// Période précédente — 24h à 48h
		db.QueryRow(`SELECT COUNT(*) FROM security_events WHERE created_at BETWEEN NOW() - INTERVAL '48 hours' AND NOW() - INTERVAL '24 hours'`).Scan(&prev.Total)                                //nolint:errcheck
		db.QueryRow(`SELECT COUNT(*) FROM security_events WHERE event_type = 'honeypot' AND created_at BETWEEN NOW() - INTERVAL '48 hours' AND NOW() - INTERVAL '24 hours'`).Scan(&prev.Honeypot) //nolint:errcheck
		db.QueryRow(`SELECT COUNT(*) FROM security_events WHERE status >= 400 AND created_at BETWEEN NOW() - INTERVAL '48 hours' AND NOW() - INTERVAL '24 hours'`).Scan(&prev.Errors)             //nolint:errcheck

		delta := func(curr, prev int) float64 {
			if prev == 0 {
				return 0
			}
			return float64(curr-prev) / float64(prev) * 100
		}

		trends := Trends{
			Current:  curr,
			Previous: prev,
			DeltaReq: delta(curr.Total, prev.Total),
			DeltaHp:  delta(curr.Honeypot, prev.Honeypot),
			DeltaErr: delta(curr.Errors, prev.Errors),
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(trends) //nolint:errcheck
	})
}

// ══════════════════════════════════════════
//  API EXPORT CSV
// ══════════════════════════════════════════

func APIExportHandler(db *sql.DB) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		days := 7
		if d := r.URL.Query().Get("days"); d != "" {
			if n, err := strconv.Atoi(d); err == nil && n > 0 && n <= 30 {
				days = n
			}
		}

		rows, err := db.Query(fmt.Sprintf(`
			SELECT created_at, ip, method, path, status, COALESCE(user_agent,''), event_type
			FROM security_events
			WHERE created_at > NOW() - INTERVAL '%d days'
			ORDER BY created_at DESC
		`, days))
		if err != nil {
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		filename := fmt.Sprintf("security-events-%s.csv", time.Now().Format("2006-01-02"))
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))

		cw := csv.NewWriter(w)
		cw.Write([]string{"created_at", "ip", "method", "path", "status", "user_agent", "event_type"}) //nolint:errcheck

		for rows.Next() {
			var createdAt time.Time
			var ip, method, path, userAgent, eventType string
			var status int
			rows.Scan(&createdAt, &ip, &method, &path, &status, &userAgent, &eventType) //nolint:errcheck
			cw.Write([]string{                                                          //nolint:errcheck
				createdAt.Format(time.RFC3339),
				ip, method, path,
				strconv.Itoa(status),
				userAgent, eventType,
			})
		}

		cw.Flush()
	})
}

// ══════════════════════════════════════════
//  API CLEANUP — supprime les vieux événements
// ══════════════════════════════════════════

func APICleanupHandler(db *sql.DB) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		result, err := db.Exec(`
			DELETE FROM security_events
			WHERE created_at < NOW() - INTERVAL '30 days'
		`)
		if err != nil {
			http.Error(w, `{"error":"db error"}`, http.StatusInternalServerError)
			return
		}

		deleted, _ := result.RowsAffected()
		slog.Info("cleanup effectué", "deleted", deleted)

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"deleted":%d,"message":"Événements > 30 jours supprimés"}`, deleted)
	})
}

// ══════════════════════════════════════════
//  QUERIES
// ══════════════════════════════════════════

func getStats(db *sql.DB) (*models.DashboardStats, error) {
	stats := &models.DashboardStats{}

	db.QueryRow(`SELECT COUNT(*) FROM security_events`).Scan(&stats.TotalEvents)                                                                             //nolint:errcheck
	db.QueryRow(`SELECT COUNT(*) FROM blacklisted_ips WHERE expires_at > NOW()`).Scan(&stats.TotalBlacklist)                                                 //nolint:errcheck
	db.QueryRow(`SELECT COUNT(*) FROM security_events WHERE created_at > NOW() - INTERVAL '24 hours'`).Scan(&stats.Events24h)                                //nolint:errcheck
	db.QueryRow(`SELECT COUNT(*) FROM security_events WHERE event_type = 'honeypot' AND created_at > NOW() - INTERVAL '24 hours'`).Scan(&stats.Honeypots24h) //nolint:errcheck
	db.QueryRow(`SELECT COUNT(*) FROM security_events WHERE event_type = 'error' AND created_at > NOW() - INTERVAL '24 hours'`).Scan(&stats.Errors24h)       //nolint:errcheck

	// Top IPs
	rows, err := db.Query(`
		SELECT ip, COUNT(*) as count FROM security_events
		WHERE created_at > NOW() - INTERVAL '24 hours'
		GROUP BY ip ORDER BY count DESC LIMIT 10
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
		SELECT path, COUNT(*) as count FROM security_events
		WHERE created_at > NOW() - INTERVAL '24 hours'
		GROUP BY path ORDER BY count DESC LIMIT 10
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
		GROUP BY hour ORDER BY hour
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
		SELECT id, created_at, ip, method, path, status,
		       COALESCE(user_agent,''), COALESCE(country,''), event_type
		FROM security_events
		ORDER BY created_at DESC LIMIT 20
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

func getEvents(db *sql.DB, limit int, eventType, search string) ([]models.SecurityEvent, error) {
	var args []interface{}
	query := `
		SELECT id, created_at, ip, method, path, status,
		       COALESCE(user_agent,''), COALESCE(country,''), event_type
		FROM security_events
		WHERE 1=1
	`

	if eventType != "" {
		args = append(args, eventType)
		query += fmt.Sprintf(" AND event_type = $%d", len(args))
	}

	if search != "" {
		args = append(args, "%"+strings.ToLower(search)+"%")
		query += fmt.Sprintf(" AND (LOWER(ip) LIKE $%d OR LOWER(path) LIKE $%d)", len(args), len(args))
	}

	query += " ORDER BY created_at DESC"
	args = append(args, limit)
	query += fmt.Sprintf(" LIMIT $%d", len(args))

	rows, err := db.Query(query, args...)
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

	db.Exec(` //nolint:errcheck
		INSERT INTO security_events (ip, method, path, status, user_agent, event_type)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, ip, r.Method, "/api/login", 401, r.UserAgent(), "brute_force")

	var count int
	db.QueryRow(`
		SELECT COUNT(*) FROM security_events
		WHERE ip = $1 AND event_type = 'brute_force'
		AND created_at > NOW() - INTERVAL '10 minutes'
	`, ip).Scan(&count) //nolint:errcheck

	if count >= 5 {
		db.Exec(` //nolint:errcheck
			INSERT INTO blacklisted_ips (ip, reason, expires_at)
			VALUES ($1, $2, $3)
			ON CONFLICT (ip) DO UPDATE SET expires_at = $3
		`, ip, "brute_force_login", time.Now().Add(24*time.Hour))
	}
}
