package main

import (
	"log/slog"
	"os"
	"security/internal"

	"github.com/joho/godotenv"
)

func main() {
	_ = godotenv.Load()
	// Logger JSON structuré
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	slog.Info("démarrage security-dashboard")

	internal.Start()
}
