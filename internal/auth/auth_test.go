package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ══════════════════════════════════════════
//  TESTS — CheckPassword
// ══════════════════════════════════════════

func TestCheckPassword_WithPlainPassword(t *testing.T) {
	t.Setenv("ADMIN_PASSWORD", "testpassword")
	t.Setenv("ADMIN_PASSWORD_HASH", "")

	if !CheckPassword("testpassword") {
		t.Error("mot de passe correct devrait retourner true")
	}
}

func TestCheckPassword_WrongPlainPassword(t *testing.T) {
	t.Setenv("ADMIN_PASSWORD", "testpassword")
	t.Setenv("ADMIN_PASSWORD_HASH", "")

	if CheckPassword("wrongpassword") {
		t.Error("mot de passe incorrect devrait retourner false")
	}
}

func TestCheckPassword_WithBcryptHash(t *testing.T) {
	// Hash bcrypt de "testpassword" généré avec DefaultCost
	hash, err := HashPassword("testpassword")
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	t.Setenv("ADMIN_PASSWORD_HASH", hash)

	if !CheckPassword("testpassword") {
		t.Error("hash bcrypt correct devrait retourner true")
	}
}

func TestCheckPassword_WrongBcryptHash(t *testing.T) {
	hash, err := HashPassword("testpassword")
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	t.Setenv("ADMIN_PASSWORD_HASH", hash)

	if CheckPassword("wrongpassword") {
		t.Error("mauvais mot de passe avec hash bcrypt devrait retourner false")
	}
}

func TestCheckPassword_EmptyPassword(t *testing.T) {
	t.Setenv("ADMIN_PASSWORD", "testpassword")
	t.Setenv("ADMIN_PASSWORD_HASH", "")

	if CheckPassword("") {
		t.Error("mot de passe vide devrait retourner false")
	}
}

// ══════════════════════════════════════════
//  TESTS — Session
// ══════════════════════════════════════════

func TestCreateSession_SetsCookie(t *testing.T) {
	// Réinitialise les sessions
	sessionsMu.Lock()
	sessions = make(map[string]time.Time)
	sessionsMu.Unlock()

	w := httptest.NewRecorder()
	CreateSession(w)

	cookies := w.Result().Cookies()
	var found bool
	for _, c := range cookies {
		if c.Name == cookieName {
			found = true
			if c.Value == "" {
				t.Error("valeur du cookie ne devrait pas être vide")
			}
			if !c.HttpOnly {
				t.Error("cookie devrait être HttpOnly")
			}
		}
	}

	if !found {
		t.Errorf("cookie %s non trouvé dans la réponse", cookieName)
	}
}

func TestValidSession_ValidToken(t *testing.T) {
	sessionsMu.Lock()
	sessions = make(map[string]time.Time)
	sessionsMu.Unlock()

	w := httptest.NewRecorder()
	CreateSession(w)

	// Récupère le cookie créé
	var token string
	for _, c := range w.Result().Cookies() {
		if c.Name == cookieName {
			token = c.Value
		}
	}

	// Crée une requête avec ce cookie
	r := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	r.AddCookie(&http.Cookie{Name: cookieName, Value: token})

	if !ValidSession(r) {
		t.Error("session valide devrait retourner true")
	}
}

func TestValidSession_InvalidToken(t *testing.T) {
	sessionsMu.Lock()
	sessions = make(map[string]time.Time)
	sessionsMu.Unlock()

	r := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	r.AddCookie(&http.Cookie{Name: cookieName, Value: "token_inexistant"})

	if ValidSession(r) {
		t.Error("token inexistant devrait retourner false")
	}
}

func TestValidSession_NoCookie(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/dashboard", nil)

	if ValidSession(r) {
		t.Error("absence de cookie devrait retourner false")
	}
}

func TestValidSession_ExpiredSession(t *testing.T) {
	sessionsMu.Lock()
	sessions = make(map[string]time.Time)
	// Ajoute une session déjà expirée
	sessions["expired_token"] = time.Now().Add(-1 * time.Hour)
	sessionsMu.Unlock()

	r := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	r.AddCookie(&http.Cookie{Name: cookieName, Value: "expired_token"})

	if ValidSession(r) {
		t.Error("session expirée devrait retourner false")
	}

	// Vérifie que la session a été supprimée
	sessionsMu.RLock()
	_, exists := sessions["expired_token"]
	sessionsMu.RUnlock()

	if exists {
		t.Error("session expirée devrait être supprimée")
	}
}

func TestDestroySession_RemovesSession(t *testing.T) {
	sessionsMu.Lock()
	sessions = make(map[string]time.Time)
	sessions["test_token"] = time.Now().Add(sessionTTL)
	sessionsMu.Unlock()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/logout", nil)
	r.AddCookie(&http.Cookie{Name: cookieName, Value: "test_token"})

	DestroySession(w, r)

	// Vérifie que la session est supprimée
	sessionsMu.RLock()
	_, exists := sessions["test_token"]
	sessionsMu.RUnlock()

	if exists {
		t.Error("session devrait être supprimée après DestroySession")
	}

	// Vérifie que le cookie est invalidé
	for _, c := range w.Result().Cookies() {
		if c.Name == cookieName {
			if c.MaxAge != -1 {
				t.Error("cookie devrait être invalidé avec MaxAge=-1")
			}
		}
	}
}

func TestCleanupSessions_RemovesExpired(t *testing.T) {
	sessionsMu.Lock()
	sessions = map[string]time.Time{
		"valid_token":   time.Now().Add(sessionTTL),
		"expired_token": time.Now().Add(-1 * time.Hour),
	}
	sessionsMu.Unlock()

	CleanupSessions()

	sessionsMu.RLock()
	_, validExists := sessions["valid_token"]
	_, expiredExists := sessions["expired_token"]
	sessionsMu.RUnlock()

	if !validExists {
		t.Error("session valide ne devrait pas être supprimée")
	}
	if expiredExists {
		t.Error("session expirée devrait être supprimée")
	}
}

// ══════════════════════════════════════════
//  TESTS — HashPassword
// ══════════════════════════════════════════

func TestHashPassword_GeneratesValidHash(t *testing.T) {
	hash, err := HashPassword("testpassword")
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	if len(hash) == 0 {
		t.Error("hash ne devrait pas être vide")
	}

	if hash == "testpassword" {
		t.Error("hash ne devrait pas être identique au mot de passe")
	}
}

func TestHashPassword_DifferentHashesSamePassword(t *testing.T) {
	hash1, _ := HashPassword("testpassword")
	hash2, _ := HashPassword("testpassword")

	if hash1 == hash2 {
		t.Error("deux hash du même mot de passe devraient être différents (salt)")
	}
}
