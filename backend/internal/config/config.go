package config

import (
	"errors"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Environment              string
	Address                  string
	DatabaseURL              string
	StoragePath              string
	MasterKey                string
	SessionTTL               time.Duration
	MaxConcurrentJobs        int
	TLSCertificateFile       string
	TLSKeyFile               string
	AgentCACertificateFile   string
	AgentCAKeyFile           string
	StorageDriver            string
	S3Endpoint               string
	S3Bucket                 string
	S3Region                 string
	S3AccessKey              string
	S3SecretKey              string
	NVDAPIKey                string
	CISAKEVCatalogURL        string
	AgentHeartbeatSeconds    int
	AgentDegradedMisses      int
	AgentOfflineMisses       int
	JobSigningKeyFile        string
	JobSigningKeyID          string
	RequireSignedJobs        bool
	MaxArtifactDownloadBytes int64
	MaxArtifactUploadBytes   int64
	ArtifactTokenTTL         time.Duration
}

func Load() (Config, error) {
	c := Config{Environment: env("NETSCOPE_ENV", "development"), Address: env("NETSCOPE_ADDRESS", ":8080"), DatabaseURL: os.Getenv("NETSCOPE_DATABASE_URL"), StoragePath: env("NETSCOPE_STORAGE_PATH", "./storage"), MasterKey: os.Getenv("NETSCOPE_MASTER_KEY"), SessionTTL: 12 * time.Hour, MaxConcurrentJobs: intEnv("NETSCOPE_MAX_CONCURRENT_JOBS", 8), TLSCertificateFile: os.Getenv("NETSCOPE_TLS_CERT_FILE"), TLSKeyFile: os.Getenv("NETSCOPE_TLS_KEY_FILE"), AgentCACertificateFile: os.Getenv("NETSCOPE_AGENT_CA_CERT_FILE"), AgentCAKeyFile: os.Getenv("NETSCOPE_AGENT_CA_KEY_FILE"), StorageDriver: env("NETSCOPE_STORAGE_DRIVER", "local"), S3Endpoint: os.Getenv("NETSCOPE_S3_ENDPOINT"), S3Bucket: os.Getenv("NETSCOPE_S3_BUCKET"), S3Region: os.Getenv("NETSCOPE_S3_REGION"), S3AccessKey: os.Getenv("NETSCOPE_S3_ACCESS_KEY"), S3SecretKey: os.Getenv("NETSCOPE_S3_SECRET_KEY"), NVDAPIKey: os.Getenv("NETSCOPE_NVD_API_KEY"), CISAKEVCatalogURL: os.Getenv("NETSCOPE_CISA_KEV_URL"), AgentHeartbeatSeconds: intEnv("NETSCOPE_AGENT_HEARTBEAT_SECONDS", 30), AgentDegradedMisses: intEnv("NETSCOPE_AGENT_DEGRADED_MISSES", 3), AgentOfflineMisses: intEnv("NETSCOPE_AGENT_OFFLINE_MISSES", 6), JobSigningKeyFile: os.Getenv("NETSCOPE_JOB_SIGNING_KEY_FILE"), JobSigningKeyID: os.Getenv("NETSCOPE_JOB_SIGNING_KEY_ID"), RequireSignedJobs: boolEnv("NETSCOPE_REQUIRE_SIGNED_JOBS", false), MaxArtifactDownloadBytes: int64(intEnv("NETSCOPE_MAX_ARTIFACT_DOWNLOAD_BYTES", 1<<30)), MaxArtifactUploadBytes: int64(intEnv("NETSCOPE_MAX_ARTIFACT_UPLOAD_BYTES", 1<<30)), ArtifactTokenTTL: 5 * time.Minute}
	if c.AgentOfflineMisses <= c.AgentDegradedMisses {
		return Config{}, errors.New("agent offline threshold must exceed degraded threshold")
	}
	if c.DatabaseURL == "" {
		return Config{}, errors.New("NETSCOPE_DATABASE_URL is required")
	}
	if c.Environment == "production" && len(c.MasterKey) < 32 {
		return Config{}, errors.New("NETSCOPE_MASTER_KEY must be configured securely in production")
	}
	if c.Environment == "production" && (c.TLSCertificateFile == "" || c.TLSKeyFile == "" || c.AgentCACertificateFile == "" || c.AgentCAKeyFile == "") {
		return Config{}, errors.New("TLS server and agent CA files are required in production")
	}
	if c.RequireSignedJobs && (c.JobSigningKeyFile == "" || c.JobSigningKeyID == "") {
		return Config{}, errors.New("signed job policy requires NETSCOPE_JOB_SIGNING_KEY_FILE and NETSCOPE_JOB_SIGNING_KEY_ID")
	}
	return c, nil
}
func boolEnv(name string, fallback bool) bool {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
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
