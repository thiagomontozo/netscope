package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"github.com/thiagomontozo/netscope/backend/internal/agents"
	"github.com/thiagomontozo/netscope/backend/internal/auth"
	"github.com/thiagomontozo/netscope/backend/internal/config"
	"github.com/thiagomontozo/netscope/backend/internal/database"
	"github.com/thiagomontozo/netscope/backend/internal/http/router"
	"github.com/thiagomontozo/netscope/backend/internal/modules"
	"github.com/thiagomontozo/netscope/backend/internal/retention"
	"github.com/thiagomontozo/netscope/backend/internal/scheduler"
	"github.com/thiagomontozo/netscope/backend/internal/storage"
	"github.com/thiagomontozo/netscope/backend/internal/vulnerabilities"
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
	var objectStorage storage.ObjectStorage
	if cfg.StorageDriver == "s3" {
		objectStorage, err = storage.NewS3(storage.S3Config{Endpoint: cfg.S3Endpoint, Bucket: cfg.S3Bucket, Region: cfg.S3Region, AccessKey: cfg.S3AccessKey, SecretKey: cfg.S3SecretKey, PathStyle: true})
	} else {
		objectStorage, err = storage.NewLocal(cfg.StoragePath)
	}
	if err != nil {
		logger.Error("object storage unavailable", "error", err)
		os.Exit(1)
	}
	var certificateAuthority *agents.CertificateAuthority
	if cfg.AgentCACertificateFile != "" {
		certificateAuthority, err = agents.LoadCertificateAuthority(cfg.AgentCACertificateFile, cfg.AgentCAKeyFile)
		if err != nil {
			logger.Error("agent certificate authority unavailable", "error", err)
			os.Exit(1)
		}
	}
	nvdProvider := vulnerabilities.NVDProvider{APIKey: cfg.NVDAPIKey}
	kevProvider := &vulnerabilities.CISAKEVProvider{CatalogURL: cfg.CISAKEVCatalogURL}
	runtime := router.Runtime{Store: store, Auth: auth.Service{Pool: pool, SessionTTL: cfg.SessionTTL, MasterKey: []byte(cfg.MasterKey)}, Enrollment: agents.EnrollmentService{Pool: pool, CA: certificateAuthority}, Storage: objectStorage, NVD: nvdProvider, KEV: kevProvider, Production: cfg.Environment == "production", MaxConcurrent: cfg.MaxConcurrentJobs}
	server := &http.Server{Addr: cfg.Address, Handler: router.New(logger, registry, runtime), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 20}
	if cfg.AgentCACertificateFile != "" {
		caPEM, readErr := os.ReadFile(cfg.AgentCACertificateFile)
		if readErr != nil {
			logger.Error("agent CA certificate unavailable", "error", readErr)
			os.Exit(1)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			logger.Error("agent CA certificate is invalid")
			os.Exit(1)
		}
		server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: pool}
	}
	shutdown, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		service := retention.Service{Pool: pool, Storage: objectStorage}
		for {
			select {
			case <-shutdown.Done():
				return
			case <-ticker.C:
				if err := service.RunOnce(shutdown); err != nil {
					logger.Error("retention cycle failed", "error", err)
				}
			}
		}
	}()
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		service := scheduler.Service{Pool: pool, Store: store, Registry: registry, MaxConcurrent: cfg.MaxConcurrentJobs}
		for {
			select {
			case <-shutdown.Done():
				return
			case <-ticker.C:
				if err := service.RunOnce(shutdown); err != nil {
					logger.Error("scheduler cycle failed", "error", err)
				}
			}
		}
	}()
	go func() {
		ticker := time.NewTicker(time.Duration(cfg.AgentHeartbeatSeconds) * time.Second)
		defer ticker.Stop()
		policy := agents.PresencePolicy{HeartbeatIntervalSeconds: cfg.AgentHeartbeatSeconds, DegradedAfterMisses: cfg.AgentDegradedMisses, OfflineAfterMisses: cfg.AgentOfflineMisses}
		for {
			select {
			case <-shutdown.Done():
				return
			case <-ticker.C:
				if err := agents.UpdatePresence(shutdown, pool, policy); err != nil {
					logger.Error("agent presence cycle failed", "error", err)
				}
			}
		}
	}()
	go func() {
		logger.Info("NetScope API listening", "address", cfg.Address, "environment", cfg.Environment)
		var serveErr error
		if cfg.TLSCertificateFile != "" {
			serveErr = server.ListenAndServeTLS(cfg.TLSCertificateFile, cfg.TLSKeyFile)
		} else {
			serveErr = server.ListenAndServe()
		}
		if serveErr != nil && serveErr != http.ErrServerClosed {
			logger.Error("server failed", "error", serveErr)
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
