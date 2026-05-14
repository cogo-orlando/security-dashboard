package internal

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"security/internal/db"
	"security/internal/handler"
	"security/internal/middleware"
	"syscall"
	"time"
)

func Start() {
	// ── Connexion base de données ──
	database, err := db.Connect()
	if err != nil {
		slog.Error("impossible de se connecter à la base de données", "error", err)
		os.Exit(1)
	}
	defer database.Close()
	slog.Info("connexion base de données établie")

	// ── Migrations ──
	if err := db.Migrate(database); err != nil {
		slog.Error("migration échouée", "error", err)
		os.Exit(1)
	}
	slog.Info("migrations appliquées")

	// ── Router ──
	mux := http.NewServeMux()

	// Fichiers statiques
	fs := http.FileServer(http.Dir("./web"))
	mux.Handle("/css/", fs)
	mux.Handle("/js/", fs)

	// Routes publiques
	mux.HandleFunc("/", handler.LoginHandler)
	mux.HandleFunc("/login", handler.LoginHandler)
	mux.HandleFunc("/api/login", handler.APILoginHandler(database))
	mux.HandleFunc("/logout", handler.LogoutHandler)

	// Routes protégées
	mux.Handle("/dashboard", middleware.RequireAuth(handler.DashboardHandler(database)))
	mux.Handle("/api/stats", middleware.RequireAuth(handler.APIStatsHandler(database)))
	mux.Handle("/api/events", middleware.RequireAuth(handler.APIEventsHandler(database)))
	mux.Handle("/api/blacklist", middleware.RequireAuth(handler.APIBlacklistHandler(database)))

	// Middleware chain
	h := middleware.Chain(mux, database)

	// ── Serveur ──
	port := os.Getenv("PORT")
	if port == "" {
		port = "8081"
	}

	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      h,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		slog.Info("serveur démarré", "port", port, "url", fmt.Sprintf("http://localhost:%s", port))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("erreur fatale serveur", "error", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit

	slog.Info("arrêt gracieux en cours", "signal", sig.String())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("arrêt forcé", "error", err)
	} else {
		slog.Info("arrêt propre")
	}
}
