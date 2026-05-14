package middleware

import (
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"security/internal/auth"
	"sync"
	"time"
)

// ══════════════════════════════════════════
//  CHAIN
// ══════════════════════════════════════════

func Chain(next http.Handler, db *sql.DB) http.Handler {
	h := next
	h = LoggerMiddleware(h, db)
	h = SecurityMiddleware(h)
	h = MaxBytesMiddleware(h)
	h = RecoveryMiddleware(h)
	return h
}

// ══════════════════════════════════════════
//  REQUIRE AUTH
// ══════════════════════════════════════════

func RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !auth.ValidSession(r) {
			http.Redirect(w, r, "/login?error=unauthorized", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ══════════════════════════════════════════
//  SECURITY HEADERS
// ══════════════════════════════════════════

func SecurityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		h.Set("Content-Security-Policy",
			"default-src 'self'; "+
				"style-src 'self' https://fonts.googleapis.com 'unsafe-inline'; "+
				"font-src 'self' https://fonts.gstatic.com; "+
				"script-src 'self'; "+
				"img-src 'self' data:; "+
				"connect-src 'self'",
		)
		h.Del("X-Powered-By")
		h.Set("Server", "")
		next.ServeHTTP(w, r)
	})
}

// ══════════════════════════════════════════
//  MAX BYTES — protection contre gros payloads
// ══════════════════════════════════════════

func MaxBytesMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB max
		next.ServeHTTP(w, r)
	})
}

// ══════════════════════════════════════════
//  RATE LIMIT LOGIN
//  Bloque après 10 tentatives en 5 minutes par IP
// ══════════════════════════════════════════

type loginLimiter struct {
	mu      sync.Mutex
	records map[string][]time.Time
}

var loginRL = &loginLimiter{records: make(map[string][]time.Time)}

func init() {
	go func() {
		for range time.Tick(10 * time.Minute) {
			loginRL.mu.Lock()
			now := time.Now()
			for ip, times := range loginRL.records {
				var recent []time.Time
				for _, t := range times {
					if now.Sub(t) < 5*time.Minute {
						recent = append(recent, t)
					}
				}
				if len(recent) == 0 {
					delete(loginRL.records, ip)
				} else {
					loginRL.records[ip] = recent
				}
			}
			loginRL.mu.Unlock()
		}
	}()
}

func (ll *loginLimiter) allow(ip string) bool {
	ll.mu.Lock()
	defer ll.mu.Unlock()
	now := time.Now()
	var recent []time.Time
	for _, t := range ll.records[ip] {
		if now.Sub(t) < 5*time.Minute {
			recent = append(recent, t)
		}
	}
	if len(recent) >= 10 {
		return false
	}
	ll.records[ip] = append(recent, now)
	return true
}

// RateLimitLogin protège uniquement la route /api/login
func RateLimitLogin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/login" && r.Method == http.MethodPost {
			ip := getIP(r)
			if !loginRL.allow(ip) {
				slog.Warn("login rate limit dépassé", "ip", ip)
				w.Header().Set("Retry-After", "300")
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// ══════════════════════════════════════════
//  LOGGER
// ══════════════════════════════════════════

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

		if db != nil {
			go saveEvent(db, ip, r.Method, r.URL.Path, rw.status, r.UserAgent())
		}
	})
}

// ══════════════════════════════════════════
//  RECOVERY
// ══════════════════════════════════════════

func RecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				slog.Error("panic récupéré", "error", fmt.Sprintf("%v", rec))
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// ══════════════════════════════════════════
//  SAVE EVENT
// ══════════════════════════════════════════

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

// ══════════════════════════════════════════
//  HELPERS
// ══════════════════════════════════════════

func getIP(r *http.Request) string {
	if ip := r.Header.Get("CF-Connecting-IP"); ip != "" {
		return ip
	}
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return ip
	}
	return r.RemoteAddr
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(status int) {
	rw.status = status
	rw.ResponseWriter.WriteHeader(status)
}
