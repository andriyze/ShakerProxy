package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"shakerproxy.dev/shakerproxy/internal/forwarder"
)

func main() {
	manager := &forwarder.Manager{Root: envOr("SHAKERPROXY_FORWARDER_ROOT", "/var/lib/shakerproxy/forwarders")}
	if len(os.Args) == 2 && os.Args[1] == "-healthcheck" {
		if _, err := manager.Status(); err != nil {
			os.Exit(1)
		}
		return
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	logger.Info("payload-free forwarder starting")
	manager.Run(ctx, time.Second)
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
