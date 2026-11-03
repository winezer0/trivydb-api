package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/winezer0/slogs"
	"gopkg.in/yaml.v3"
)

const DefaultDBRepository = "ghcr.io/aquasecurity/trivy-db:2"

type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Database DatabaseConfig `yaml:"database"`
	Log      LogConfig      `yaml:"log"`
}

type LogConfig struct {
	slogs.LogConfig `yaml:",inline"`
	FilePath        *string `yaml:"file_path,omitempty"`
}

func defaultLogConfig() LogConfig {
	logConfig := slogs.NewConfig("info", "./data/app.log", "json")
	logConfig.FileLevel = "info"
	logConfig.MaxBackups = 5
	return LogConfig{LogConfig: logConfig}
}

func (c LogConfig) SlogsConfig() slogs.LogConfig {
	config := c.LogConfig
	if c.FilePath != nil {
		config.LogFilePath = *c.FilePath
	}
	return config
}

type ServerConfig struct {
	Addr                   string `yaml:"addr"`
	ShutdownTimeoutSeconds int    `yaml:"shutdown_timeout_seconds"`
	MaxConcurrentRequests  int    `yaml:"max_concurrent_requests"`
	APIKey                 string `yaml:"api_key"`
}

type DatabaseConfig struct {
	DSN            string `yaml:"dsn"`
	Repository     string `yaml:"repository"`
	UpdateInterval string `yaml:"update_interval"`
}

func Load(file string) (Config, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return Config{}, fmt.Errorf("read config %q: %w", file, err)
	}
	cfg := Config{
		Server:   ServerConfig{Addr: ":8088", ShutdownTimeoutSeconds: 10, MaxConcurrentRequests: 100},
		Database: DatabaseConfig{DSN: "./data/db.versions", Repository: DefaultDBRepository, UpdateInterval: "6h"},
		Log:      defaultLogConfig(),
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("parse config %q: %w", file, err)
	}
	cfg.applyDefaults()
	base, err := filepath.Abs(filepath.Dir(file))
	if err != nil {
		return Config{}, fmt.Errorf("resolve config directory: %w", err)
	}
	cfg.Database.DSN = resolvePath(base, cfg.Database.DSN)
	if cfg.Log.FilePath != nil && *cfg.Log.FilePath != "" {
		resolved := resolvePath(base, *cfg.Log.FilePath)
		cfg.Log.FilePath = &resolved
	} else if cfg.Log.FilePath == nil && cfg.Log.LogFilePath != "" {
		cfg.Log.LogFilePath = resolvePath(base, cfg.Log.LogFilePath)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c *Config) applyDefaults() {
	if strings.TrimSpace(c.Server.Addr) == "" {
		c.Server.Addr = ":8088"
	}
	if c.Server.ShutdownTimeoutSeconds == 0 {
		c.Server.ShutdownTimeoutSeconds = 10
	}
	if strings.TrimSpace(c.Database.DSN) == "" {
		c.Database.DSN = "./data/db.versions"
	}
	if strings.TrimSpace(c.Database.Repository) == "" {
		c.Database.Repository = DefaultDBRepository
	}
	if strings.TrimSpace(c.Database.UpdateInterval) == "" {
		c.Database.UpdateInterval = "6h"
	}
}

func (c Config) Validate() error {
	if c.Server.ShutdownTimeoutSeconds < 0 {
		return errors.New("server.shutdown_timeout_seconds cannot be negative")
	}
	if c.Server.MaxConcurrentRequests < 0 {
		return errors.New("server.max_concurrent_requests cannot be negative")
	}
	if strings.TrimSpace(c.Database.DSN) == "" {
		return errors.New("database.dsn is required")
	}
	interval, err := time.ParseDuration(c.Database.UpdateInterval)
	if err != nil {
		return fmt.Errorf("database.update_interval: %w", err)
	}
	if interval < 0 {
		return errors.New("database.update_interval cannot be negative")
	}
	return nil
}

func (c Config) UpdateIntervalDuration() (time.Duration, error) {
	return time.ParseDuration(c.Database.UpdateInterval)
}

func resolvePath(base, value string) string {
	if filepath.IsAbs(value) {
		return filepath.Clean(value)
	}
	return filepath.Clean(filepath.Join(base, value))
}
