package auth

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// ── Sessions en mémoire ──
var (
	sessions   = make(map[string]time.Time)
	sessionsMu sync.RWMutex
)

const (
	sessionCookie = "sd_session"
	sessionTTL    = 8 * time.Hour
	cookieName    = "sd_session"
)

// CheckPassword vérifie le mot de passe admin
func CheckPassword(password string) bool {
	adminHash := os.Getenv("ADMIN_PASSWORD_HASH")
	if adminHash == "" {
		// Fallback pour le dev — mot de passe par défaut "admin"
		return password == os.Getenv("ADMIN_PASSWORD")
	}
	return bcrypt.CompareHashAndPassword([]byte(adminHash), []byte(password)) == nil
}

// CreateSession crée une nouvelle session et pose le cookie
func CreateSession(w http.ResponseWriter) {
	token := generateToken()

	sessionsMu.Lock()
	sessions[token] = time.Now().Add(sessionTTL)
	sessionsMu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(sessionTTL.Seconds()),
		HttpOnly: true,
		Secure:   os.Getenv("ENV") == "production",
		SameSite: http.SameSiteStrictMode,
	})
}

// ValidSession vérifie si la session est valide
func ValidSession(r *http.Request) bool {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return false
	}

	sessionsMu.RLock()
	expiry, ok := sessions[cookie.Value]
	sessionsMu.RUnlock()

	if !ok {
		return false
	}

	if time.Now().After(expiry) {
		sessionsMu.Lock()
		delete(sessions, cookie.Value)
		sessionsMu.Unlock()
		return false
	}

	return true
}

// DestroySession supprime la session
func DestroySession(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(cookieName)
	if err == nil {
		sessionsMu.Lock()
		delete(sessions, cookie.Value)
		sessionsMu.Unlock()
	}

	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

// CleanupSessions supprime les sessions expirées
func CleanupSessions() {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	now := time.Now()
	for token, expiry := range sessions {
		if now.After(expiry) {
			delete(sessions, token)
		}
	}
}

func generateToken() string {
	b := make([]byte, 32)
	rand.Read(b) //nolint:errcheck
	return hex.EncodeToString(b)
}

// HashPassword génère un hash bcrypt — utilitaire pour créer le hash admin
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash), err
}
