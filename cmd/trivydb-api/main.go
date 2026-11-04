package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	"github.com/tanspec/trivydb-api/internal/config"
	"github.com/tanspec/trivydb-api/internal/trivydbapi"
	"github.com/winezer0/slogs"
)

type CLI struct {
	Config string   `short:"c" default:"config.yaml" help:"Configuration file."`
	Serve  struct{} `cmd:"" default:"1" help:"Start the HTTP API service."`
	Update struct{} `cmd:"" help:"Download and activate the Trivy database, then exit."`
}

func main() {
	if err := run(); err != nil {
		slog.Error("Trivy DB API stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	var cli CLI
	ctx := kong.Parse(&cli, kong.Name("trivydb-api"), kong.Description("Trivy vulnerability database API and updater."))
	switch ctx.Command() {
	case "serve":
		return serve(cli.Config)
	case "update":
		return update(cli.Config)
	default:
		return fmt.Errorf("unknown command %q", ctx.Command())
	}
}

func serve(configPath string) error {
	cfg, closeLogger, err := loadConfigAndLogger(configPath)
	if err != nil {
		return err
	}
	defer closeLogger()

	interval, err := cfg.UpdateIntervalDuration()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	service, err := trivydbapi.New(ctx, serverOptions(cfg, interval))
	if err != nil {
		return err
	}
	defer service.Close()
	service.StartUpdater(ctx)

	server := &http.Server{
		Addr: cfg.Server.Addr, Handler: service.Handler(),
		ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.Server.ShutdownTimeoutSeconds)*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			slog.Warn("HTTP server shutdown failed", "error", err)
		}
	}()
	slog.Info("Trivy DB API listening", "addr", cfg.Server.Addr, "database", cfg.Database.DSN)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve Trivy DB API: %w", err)
	}
	return nil
}

func update(configPath string) error {
	cfg, closeLogger, err := loadConfigAndLogger(configPath)
	if err != nil {
		return err
	}
	defer closeLogger()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	slog.Info("Running one-shot Trivy DB update", "database", cfg.Database.DSN)
	if err := trivydbapi.UpdateDatabase(ctx, serverOptions(cfg, 0)); err != nil {
		return fmt.Errorf("update Trivy database: %w", err)
	}
	slog.Info("Trivy DB update completed")
	return nil
}

func loadConfigAndLogger(configPath string) (config.Config, func(), error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return config.Config{}, func() {}, err
	}
	if err := slogs.Init(cfg.Log.SlogsConfig()); err != nil {
		return config.Config{}, func() {}, fmt.Errorf("initialize logging: %w", err)
	}
	slog.SetDefault(slogs.Default().Slog())
	return cfg, func() { _ = slogs.CloseAll() }, nil
}

func serverOptions(cfg config.Config, updateInterval time.Duration) trivydbapi.Options {
	return trivydbapi.Options{
		DBDir: cfg.Database.DSN, APIKey: cfg.Server.APIKey,
		DBRepository: cfg.Database.Repository, UpdateInterval: updateInterval,
		UpdateProxy:           cfg.Database.UpdateProxy,
		MaxConcurrentRequests: cfg.Server.MaxConcurrentRequests,
	}
}
