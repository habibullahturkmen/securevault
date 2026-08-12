// Package config loads and validates all runtime configuration from the
// environment. The master key (KEK) enters the process only here and is
// never logged, stored, or echoed back.
package config

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
)

const (
	// MasterKeySize is the required KEK length: AES-256 needs 32 bytes.
	MasterKeySize = 32

	defaultListenAddr     = "127.0.0.1:8080"
	defaultDataDir        = "./data"
	defaultMaxUploadBytes = 25 << 20 // 25 MiB
)

// Config holds every runtime setting for the server.
type Config struct {
	ListenAddr     string
	DatabaseURL    string
	DataDir        string
	MasterKey      []byte
	MaxUploadBytes int64
	Dev            bool
}

// Load reads configuration from the environment and validates it.
// It fails closed: a missing or malformed master key is a startup error,
// never a silent fallback.
func Load() (*Config, error) {
	cfg := &Config{
		ListenAddr:     envOr("LISTEN_ADDR", defaultListenAddr),
		DatabaseURL:    os.Getenv("DATABASE_URL"),
		DataDir:        envOr("DATA_DIR", defaultDataDir),
		MaxUploadBytes: defaultMaxUploadBytes,
		Dev:            envOr("ENV", "dev") == "dev",
	}

	if cfg.DatabaseURL == "" {
		return nil, errors.New("DATABASE_URL is required")
	}

	keyHex := os.Getenv("SECUREVAULT_MASTER_KEY")
	if keyHex == "" {
		return nil, errors.New("SECUREVAULT_MASTER_KEY is required (32-byte hex; generate with `make genkey`)")
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, errors.New("SECUREVAULT_MASTER_KEY must be hex-encoded")
	}
	if len(key) != MasterKeySize {
		return nil, fmt.Errorf("SECUREVAULT_MASTER_KEY must decode to %d bytes, got %d", MasterKeySize, len(key))
	}
	cfg.MasterKey = key

	if v := os.Getenv("MAX_UPLOAD_BYTES"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			return nil, errors.New("MAX_UPLOAD_BYTES must be a positive integer")
		}
		cfg.MaxUploadBytes = n
	}

	return cfg, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
