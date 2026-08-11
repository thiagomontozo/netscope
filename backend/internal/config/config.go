package config

import (
	"errors"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Environment       string
	Address           string
	DatabaseURL       string
	StoragePath       string
	MasterKey         string
	SessionTTL        time.Duration
	MaxConcurrentJobs int
}

func Load() (Config, error) {
	c := Config{Environment: env("NETSCOPE_ENV", "development"), Address: env("NETSCOPE_ADDRESS", ":8080"), DatabaseURL: os.Getenv("NETSCOPE_DATABASE_URL"), StoragePath: env("NETSCOPE_STORAGE_PATH", "./storage"), MasterKey: os.Getenv("NETSCOPE_MASTER_KEY"), SessionTTL: 12 * time.Hour, MaxConcurrentJobs: intEnv("NETSCOPE_MAX_CONCURRENT_JOBS", 8)}
	if c.DatabaseURL == "" {
		return Config{}, errors.New("NETSCOPE_DATABASE_URL is required")
	}
	if c.Environment == "production" && len(c.MasterKey) < 32 {
		return Config{}, errors.New("NETSCOPE_MASTER_KEY must be configured securely in production")
	}
	return c, nil
}
func env(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
func intEnv(name string, fallback int) int {
	v, err := strconv.Atoi(os.Getenv(name))
	if err == nil && v > 0 {
		return v
	}
	return fallback
}
