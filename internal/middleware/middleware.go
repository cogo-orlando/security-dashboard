package middleware

import (
	"database/sql"
	"log/slog"
	"net/http"
	"security/internal/auth"
	"time"
)

// Chain applique tous les middlewares
func Chain(next http.Handler, db *sql.DB) http.Handler {
	h := next
	h = LoggerMiddleware(h, db)
	h = RecoveryMiddleware(h)
	return h
}

// RequireAuth protège les routes admin
func RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !auth.ValidSession(r) {
			http.Redirect(w, r, "/login?error=unauthorized", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// LoggerMiddleware logue chaque requête et la sauvegarde en DB
func LoggerMiddleware(next http.Handler, db *sql.DB) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, status: 200}

		next.ServeHTTP(rw, r)

		duration := time.Since(start)
		ip := getIP(r)

		slog.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rw.status,
			"ip", ip,
			"duration_ms", duration.Milliseconds(),
			"user_agent", r.UserAgent(),
		)

		// Sauvegarde en DB de manière asynchrone
		if db != nil {
			go saveEvent(db, ip, r.Method, r.URL.Path, rw.status, r.UserAgent())
		}
	})
}

// RecoveryMiddleware récupère les panics
func RecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				slog.Error("panic récupéré", "error", rec)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// saveEvent sauvegarde un événement en base de données
func saveEvent(db *sql.DB, ip, method, path string, status int, userAgent string) {
	eventType := "request"
	if status == http.StatusNotFound {
		eventType = "error"
	} else if status == http.StatusTooManyRequests {
		eventType = "ratelimit"
	} else if status >= 500 {
		eventType = "error"
	}

	_, err := db.Exec(`
		INSERT INTO security_events (ip, method, path, status, user_agent, event_type)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, ip, method, path, status, userAgent, eventType)

	if err != nil {
		slog.Error("saveEvent failed", "error", err)
	}
}

// getIP extrait l'IP réelle de la requête
func getIP(r *http.Request) string {
	if ip := r.Header.Get("CF-Connecting-IP"); ip != "" {
		return ip
	}
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return ip
	}
	return r.RemoteAddr
}

// responseWriter wrappé pour capturer le status code
type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(status int) {
	rw.status = status
	rw.ResponseWriter.WriteHeader(status)
}
