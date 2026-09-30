package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"shakerproxy.dev/shakerproxy/internal/cloudconnector"
)

const version = "0.1.0-dev.1"

func main() {
	if len(os.Args) == 2 && os.Args[1] == "version" {
		fmt.Println(version)
		return
	}
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: shakerproxy-cloud-connector [version]")
		os.Exit(2)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	config, err := cloudconnector.DaemonConfigFromEnvironment(version)
	if err != nil {
		logger.Error("cloud connector configuration rejected", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := cloudconnector.RunDaemon(ctx, logger, config); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("cloud connector stopped", "error", err)
		os.Exit(1)
	}
}
