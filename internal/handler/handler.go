package handler

import (
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"runtime"
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
	_ = tmpl.Execute(w, map[string]string{"Error": errMsg}) // #nosec G104
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
		_ = tmpl.Execute(w, nil) // #nosec G104
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
		_ = json.NewEncoder(w).Encode(stats) // #nosec G104
	})
}

// ══════════════════════════════════════════
//  API EVENTS
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
		search := r.URL.Query().Get("q")

		events, err := getEvents(db, limit, eventType, search)
		if err != nil {
			http.Error(w, `{"error":"db error"}`, http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(events) // #nosec G104
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
		_ = json.NewEncoder(w).Encode(blacklist) // #nosec G104
	})
}

// ══════════════════════════════════════════
//  API USER AGENTS
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
			_ = rows.Scan(&a.Agent, &a.Count) // #nosec G104
			agents = append(agents, a)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(agents) // #nosec G104
	})
}

// ══════════════════════════════════════════
//  API ERREURS GROUPÉES
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
			_ = rows.Scan(&e.Path, &e.Status, &e.Count) // #nosec G104
			errors = append(errors, e)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(errors) // #nosec G104
	})
}

// ══════════════════════════════════════════
//  API TENDANCES
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

		_ = db.QueryRow(`SELECT COUNT(*) FROM security_events WHERE created_at > NOW() - INTERVAL '24 hours'`).Scan(&curr.Total)                                // #nosec G104
		_ = db.QueryRow(`SELECT COUNT(*) FROM security_events WHERE event_type = 'honeypot' AND created_at > NOW() - INTERVAL '24 hours'`).Scan(&curr.Honeypot) // #nosec G104
		_ = db.QueryRow(`SELECT COUNT(*) FROM security_events WHERE status >= 400 AND created_at > NOW() - INTERVAL '24 hours'`).Scan(&curr.Errors)             // #nosec G104

		_ = db.QueryRow(`SELECT COUNT(*) FROM security_events WHERE created_at BETWEEN NOW() - INTERVAL '48 hours' AND NOW() - INTERVAL '24 hours'`).Scan(&prev.Total)                                // #nosec G104
		_ = db.QueryRow(`SELECT COUNT(*) FROM security_events WHERE event_type = 'honeypot' AND created_at BETWEEN NOW() - INTERVAL '48 hours' AND NOW() - INTERVAL '24 hours'`).Scan(&prev.Honeypot) // #nosec G104
		_ = db.QueryRow(`SELECT COUNT(*) FROM security_events WHERE status >= 400 AND created_at BETWEEN NOW() - INTERVAL '48 hours' AND NOW() - INTERVAL '24 hours'`).Scan(&prev.Errors)             // #nosec G104

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
		_ = json.NewEncoder(w).Encode(trends) // #nosec G104
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

		rows, err := db.Query(`
			SELECT created_at, ip, method, path, status, COALESCE(user_agent,''), event_type
			FROM security_events
			WHERE created_at > NOW() - ($1 * INTERVAL '1 day')
			ORDER BY created_at DESC
		`, days)
		if err != nil {
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		filename := fmt.Sprintf("security-events-%s.csv", time.Now().Format("2006-01-02"))
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))

		cw := csv.NewWriter(w)
		_ = cw.Write([]string{"created_at", "ip", "method", "path", "status", "user_agent", "event_type"}) // #nosec G104

		for rows.Next() {
			var createdAt time.Time
			var ip, method, path, userAgent, eventType string
			var status int
			_ = rows.Scan(&createdAt, &ip, &method, &path, &status, &userAgent, &eventType) // #nosec G104
			_ = cw.Write([]string{                                                          // #nosec G104
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
//  API CLEANUP
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
		fmt.Fprintf(w, `{"deleted":%d,"message":"Événements > 30 jours supprimés"}`, deleted) // #nosec G104
	})
}

// ══════════════════════════════════════════
//  QUERIES
// ══════════════════════════════════════════

func getStats(db *sql.DB) (*models.DashboardStats, error) {
	stats := &models.DashboardStats{}

	_ = db.QueryRow(`SELECT COUNT(*) FROM security_events`).Scan(&stats.TotalEvents)                                                                             // #nosec G104
	_ = db.QueryRow(`SELECT COUNT(*) FROM blacklisted_ips WHERE expires_at > NOW()`).Scan(&stats.TotalBlacklist)                                                 // #nosec G104
	_ = db.QueryRow(`SELECT COUNT(*) FROM security_events WHERE created_at > NOW() - INTERVAL '24 hours'`).Scan(&stats.Events24h)                                // #nosec G104
	_ = db.QueryRow(`SELECT COUNT(*) FROM security_events WHERE event_type = 'honeypot' AND created_at > NOW() - INTERVAL '24 hours'`).Scan(&stats.Honeypots24h) // #nosec G104
	_ = db.QueryRow(`SELECT COUNT(*) FROM security_events WHERE event_type = 'error' AND created_at > NOW() - INTERVAL '24 hours'`).Scan(&stats.Errors24h)       // #nosec G104

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
			_ = rows.Scan(&ip.IP, &ip.Count) // #nosec G104
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
			_ = rows2.Scan(&p.Path, &p.Count) // #nosec G104
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
			_ = rows3.Scan(&h.Hour, &h.Count) // #nosec G104
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
			_ = rows4.Scan(&e.ID, &e.CreatedAt, &e.IP, &e.Method, &e.Path, &e.Status, &e.UserAgent, &e.Country, &e.EventType) // #nosec G104
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
		query += fmt.Sprintf(" AND event_type = $%d", len(args)) // #nosec G201
	}

	if search != "" {
		args = append(args, "%"+strings.ToLower(search)+"%")
		query += fmt.Sprintf(" AND (LOWER(ip) LIKE $%d OR LOWER(path) LIKE $%d)", len(args), len(args)) // #nosec G201
	}

	query += " ORDER BY created_at DESC"
	args = append(args, limit)
	query += fmt.Sprintf(" LIMIT $%d", len(args)) // #nosec G201 G202

	rows, err := db.Query(query, args...) // #nosec G701
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []models.SecurityEvent
	for rows.Next() {
		var e models.SecurityEvent
		_ = rows.Scan(&e.ID, &e.CreatedAt, &e.IP, &e.Method, &e.Path, &e.Status, &e.UserAgent, &e.Country, &e.EventType) // #nosec G104
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
		_ = rows.Scan(&b.ID, &b.IP, &b.Reason, &b.CreatedAt, &b.ExpiresAt) // #nosec G104
		list = append(list, b)
	}

	return list, nil
}

func logFailedLogin(db *sql.DB, r *http.Request) {
	ip := r.Header.Get("CF-Connecting-IP")
	if ip == "" {
		ip = r.RemoteAddr
	}

	_, _ = db.Exec(` // #nosec G104
		INSERT INTO security_events (ip, method, path, status, user_agent, event_type)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, ip, r.Method, "/api/login", 401, r.UserAgent(), "brute_force")

	var count int
	_ = db.QueryRow(` // #nosec G104
		SELECT COUNT(*) FROM security_events
		WHERE ip = $1 AND event_type = 'brute_force'
		AND created_at > NOW() - INTERVAL '10 minutes'
	`, ip).Scan(&count)

	if count >= 5 {
		_, _ = db.Exec(` // #nosec G104
			INSERT INTO blacklisted_ips (ip, reason, expires_at)
			VALUES ($1, $2, $3)
			ON CONFLICT (ip) DO UPDATE SET expires_at = $3
		`, ip, "brute_force_login", time.Now().Add(24*time.Hour))
	}
}

// ══════════════════════════════════════════
//  API METRICS — métriques système Go
// ══════════════════════════════════════════

func APIMetricsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var mem runtime.MemStats
		runtime.ReadMemStats(&mem)

		type Metrics struct {
			Goroutines   int     `json:"goroutines"`
			AllocMB      float64 `json:"alloc_mb"`
			TotalAllocMB float64 `json:"total_alloc_mb"`
			SysMB        float64 `json:"sys_mb"`
			GCCycles     uint32  `json:"gc_cycles"`
			Uptime       string  `json:"uptime"`
			GoVersion    string  `json:"go_version"`
			GOOS         string  `json:"goos"`
			GOARCH       string  `json:"goarch"`
		}

		metrics := Metrics{
			Goroutines:   runtime.NumGoroutine(),
			AllocMB:      float64(mem.Alloc) / 1024 / 1024,
			TotalAllocMB: float64(mem.TotalAlloc) / 1024 / 1024,
			SysMB:        float64(mem.Sys) / 1024 / 1024,
			GCCycles:     mem.NumGC,
			Uptime:       time.Since(startTime).Round(time.Second).String(),
			GoVersion:    runtime.Version(),
			GOOS:         runtime.GOOS,
			GOARCH:       runtime.GOARCH,
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(metrics) // #nosec G104
	})
}

// startTime enregistre le démarrage du serveur
var startTime = time.Now()
