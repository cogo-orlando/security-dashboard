package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ══════════════════════════════════════════
//  HELPER
// ══════════════════════════════════════════

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

// ══════════════════════════════════════════
//  TESTS — getIP
// ══════════════════════════════════════════

func TestGetIP_CloudflareHeader(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("CF-Connecting-IP", "1.2.3.4")
	r.Header.Set("X-Forwarded-For", "9.9.9.9")

	ip := getIP(r)
	if ip != "1.2.3.4" {
		t.Errorf("attendu 1.2.3.4, obtenu %s", ip)
	}
}

func TestGetIP_XForwardedFor(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Forwarded-For", "5.6.7.8")

	ip := getIP(r)
	if ip != "5.6.7.8" {
		t.Errorf("attendu 5.6.7.8, obtenu %s", ip)
	}
}

func TestGetIP_RemoteAddr(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "192.168.1.1:1234"

	ip := getIP(r)
	if ip != "192.168.1.1:1234" {
		t.Errorf("attendu 192.168.1.1:1234, obtenu %s", ip)
	}
}

// ══════════════════════════════════════════
//  TESTS — SecurityMiddleware
// ══════════════════════════════════════════

func TestSecurity_XFrameOptions(t *testing.T) {
	handler := SecurityMiddleware(okHandler())
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	handler.ServeHTTP(w, r)

	if w.Header().Get("X-Frame-Options") != "DENY" {
		t.Errorf("X-Frame-Options devrait être DENY, obtenu %s", w.Header().Get("X-Frame-Options"))
	}
}

func TestSecurity_XContentTypeOptions(t *testing.T) {
	handler := SecurityMiddleware(okHandler())
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	handler.ServeHTTP(w, r)

	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("X-Content-Type-Options devrait être nosniff")
	}
}

func TestSecurity_CSPPresent(t *testing.T) {
	handler := SecurityMiddleware(okHandler())
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	handler.ServeHTTP(w, r)

	csp := w.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Error("Content-Security-Policy devrait être présent")
	}
	if !strings.Contains(csp, "default-src 'self'") {
		t.Errorf("CSP devrait contenir default-src 'self', obtenu: %s", csp)
	}
}

func TestSecurity_ReferrerPolicy(t *testing.T) {
	handler := SecurityMiddleware(okHandler())
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	handler.ServeHTTP(w, r)

	if w.Header().Get("Referrer-Policy") != "strict-origin-when-cross-origin" {
		t.Error("Referrer-Policy incorrect")
	}
}

func TestSecurity_Returns200(t *testing.T) {
	handler := SecurityMiddleware(okHandler())
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("attendu 200, obtenu %d", w.Code)
	}
}

// ══════════════════════════════════════════
//  TESTS — RateLimitLogin
// ══════════════════════════════════════════

func TestRateLimitLogin_AllowsNormalLogin(t *testing.T) {
	loginRL = &loginLimiter{records: make(map[string][]time.Time)}

	handler := RateLimitLogin(okHandler())
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/login", nil)
	r.Header.Set("CF-Connecting-IP", "10.0.0.1")
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("première tentative devrait être autorisée, obtenu %d", w.Code)
	}
}

func TestRateLimitLogin_BlocksAfterLimit(t *testing.T) {
	loginRL = &loginLimiter{records: make(map[string][]time.Time)}

	ip := "10.0.0.2"
	now := time.Now()
	times := make([]time.Time, 10)
	for i := range times {
		times[i] = now
	}
	loginRL.mu.Lock()
	loginRL.records[ip] = times
	loginRL.mu.Unlock()

	handler := RateLimitLogin(okHandler())
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/login", nil)
	r.Header.Set("CF-Connecting-IP", ip)
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("après 10 tentatives devrait retourner 429, obtenu %d", w.Code)
	}
}

func TestRateLimitLogin_OnlyBlocksLoginRoute(t *testing.T) {
	loginRL = &loginLimiter{records: make(map[string][]time.Time)}

	ip := "10.0.0.3"
	now := time.Now()
	times := make([]time.Time, 10)
	for i := range times {
		times[i] = now
	}
	loginRL.mu.Lock()
	loginRL.records[ip] = times
	loginRL.mu.Unlock()

	handler := RateLimitLogin(okHandler())
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	r.Header.Set("CF-Connecting-IP", ip)
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("/dashboard ne devrait pas être bloqué, obtenu %d", w.Code)
	}
}

func TestRateLimitLogin_DifferentIPsIndependent(t *testing.T) {
	loginRL = &loginLimiter{records: make(map[string][]time.Time)}

	ipA := "10.0.1.1"
	now := time.Now()
	times := make([]time.Time, 10)
	for i := range times {
		times[i] = now
	}
	loginRL.mu.Lock()
	loginRL.records[ipA] = times
	loginRL.mu.Unlock()

	handler := RateLimitLogin(okHandler())
	ipB := "10.0.1.2"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/login", nil)
	r.Header.Set("CF-Connecting-IP", ipB)
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("IP B ne devrait pas être bloquée, obtenu %d", w.Code)
	}
}

// ══════════════════════════════════════════
//  TESTS — RecoveryMiddleware
// ══════════════════════════════════════════

func TestRecovery_NormalHandler(t *testing.T) {
	handler := RecoveryMiddleware(okHandler())
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("attendu 200, obtenu %d", w.Code)
	}
}

func TestRecovery_CatchesPanic(t *testing.T) {
	panicHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("test panic")
	})

	handler := RecoveryMiddleware(panicHandler)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("panic devrait retourner 500, obtenu %d", w.Code)
	}
}

// ══════════════════════════════════════════
//  TESTS — MaxBytesMiddleware
// ══════════════════════════════════════════

func TestMaxBytes_AllowsSmallBody(t *testing.T) {
	handler := MaxBytesMiddleware(okHandler())
	w := httptest.NewRecorder()
	body := strings.NewReader("small body")
	r := httptest.NewRequest(http.MethodPost, "/", body)
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("petit body devrait être autorisé, obtenu %d", w.Code)
	}
}
