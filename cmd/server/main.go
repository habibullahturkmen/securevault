// SecureVault server: single binary containing the API, the content-addressed
// storage engine, the schema migrations, and (in production builds) the
// embedded web interface.
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"time"

	"securevault/internal/api"
	"securevault/internal/audit"
	"securevault/internal/auth"
	"securevault/internal/config"
	"securevault/internal/database"
	"securevault/internal/files"
	"securevault/internal/storage"
	webui "securevault/web"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	slog.SetDefault(logger)

	if err := run(logger); err != nil {
		logger.Error("fatal", "err", err.Error())
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	ctx := context.Background()

	pool, err := database.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	applied, err := database.Migrate(ctx, pool)
	if err != nil {
		return err
	}
	logger.Info("migrations up to date", "applied", applied)

	store, err := storage.New(cfg.DataDir, cfg.MasterKey)
	if err != nil {
		return err
	}

	auditLog := audit.New(pool, logger)
	authSvc := auth.NewService(pool, auditLog)
	mode, err := auth.ParseRegistrationMode(cfg.RegistrationMode)
	if err != nil {
		return err
	}
	authSvc.SetRegistrationPolicy(auth.RegistrationPolicy{Mode: mode, MaxUsers: cfg.MaxUsers})
	repo := files.NewRepo(pool, store, auditLog, cfg.MaxUploadBytes)

	ui := webui.FS()
	server := api.NewServer(authSvc, repo, auditLog, pool, logger,
		cfg.Dev, cfg.MaxUploadBytes, ui)

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           server.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       5 * time.Minute, // uploads stream within this window
		WriteTimeout:      5 * time.Minute,
		IdleTimeout:       2 * time.Minute,
	}

	logger.Info("listening", "addr", cfg.ListenAddr, "dev", cfg.Dev, "embedded_ui", ui != nil,
		"registration", mode, "max_users", cfg.MaxUsers)
	return srv.ListenAndServe()
}
