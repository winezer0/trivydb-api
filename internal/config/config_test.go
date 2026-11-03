package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAppliesDefaultsAndResolvesRelativePaths(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(file, []byte("server:\n  api_key: secret\ndatabase:\n  dsn: ./data/db.versions\nlog:\n  console_format: TLCM\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(file)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Addr != ":8088" || cfg.Server.ShutdownTimeoutSeconds != 10 {
		t.Fatalf("server defaults not applied: %+v", cfg.Server)
	}
	if cfg.Server.MaxConcurrentRequests != 100 {
		t.Fatalf("max concurrent requests = %d, want default 100", cfg.Server.MaxConcurrentRequests)
	}
	if cfg.Database.DSN != filepath.Join(dir, "data", "db.versions") {
		t.Fatalf("database path = %q", cfg.Database.DSN)
	}
	if cfg.Database.UpdateInterval != "6h" {
		t.Fatalf("update interval = %q, want 6h", cfg.Database.UpdateInterval)
	}
	logConfig := cfg.Log.SlogsConfig()
	if logConfig.ConsoleFormat != "TLCM" || logConfig.LogFilePath != filepath.Join(dir, "data", "app.log") {
		t.Fatalf("unexpected log config: %+v", cfg.Log)
	}
	if logConfig.FileLevel != "info" || logConfig.MaxBackups != 5 {
		t.Fatalf("log defaults not applied: %+v", logConfig)
	}
}

func TestLoadEmptyFilePathDisablesLogFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(file, []byte("log:\n  file_path: \"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(file)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Log.SlogsConfig().LogFilePath; got != "" {
		t.Fatalf("log file path = %q, want disabled", got)
	}
}
