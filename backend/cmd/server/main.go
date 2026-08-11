package main

import (
	"context"
	"github.com/thiagomontozo/netscope/backend/internal/auth"
	"github.com/thiagomontozo/netscope/backend/internal/config"
	"github.com/thiagomontozo/netscope/backend/internal/database"
	"github.com/thiagomontozo/netscope/backend/internal/http/router"
	"github.com/thiagomontozo/netscope/backend/internal/modules"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg, err := config.Load()
	if err != nil {
		logger.Error("configuration rejected", "error", err)
		os.Exit(1)
	}
	startupCtx, cancelStartup := context.WithTimeout(context.Background(), 10*time.Second)
	pool, err := database.Open(startupCtx, cfg.DatabaseURL)
	cancelStartup()
	if err != nil {
		logger.Error("database unavailable", "error", err)
		os.Exit(1)
	}
	defer pool.Close()
	registry := modules.NewRegistry()
	for _, adapter := range modules.BuiltinDefinitions() {
		if err := registry.Register(adapter); err != nil {
			logger.Error("module registration failed", "moduleId", adapter.Definition.ID, "error", err)
			os.Exit(1)
		}
	}
	store := database.ControlPlane{Pool: pool}
	runtime := router.Runtime{Store: store, Auth: auth.Service{Pool: pool, SessionTTL: cfg.SessionTTL, MasterKey: []byte(cfg.MasterKey)}, Production: cfg.Environment == "production", MaxConcurrent: cfg.MaxConcurrentJobs}
	server := &http.Server{Addr: cfg.Address, Handler: router.New(logger, registry, runtime), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 20}
	shutdown, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		logger.Info("NetScope API listening", "address", cfg.Address, "environment", cfg.Environment)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("server failed", "error", err)
			stop()
		}
	}()
	<-shutdown.Done()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
	}
}
