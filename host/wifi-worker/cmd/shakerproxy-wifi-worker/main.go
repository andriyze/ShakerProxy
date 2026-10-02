// Command shakerproxy-wifi-worker turns the 802.11 management frames
// ShakerProxy's passive Wi-Fi monitor records into Traffic events. It runs
// without network access or capabilities (see
// shakerproxy-wifi-worker.service): it reads the ring buffer dumpcap writes
// and the scope gatewayd writes, and leaves one event file per observation
// in the host event spool the event forwarder delivers to ingest.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"shakerproxy.dev/shakerproxy/internal/hostevents"
	"shakerproxy.dev/shakerproxy/internal/wifi"
)

var version = "0.1.0-dev.1"

type spoolSink struct{ spool *hostevents.Spool }

func (s spoolSink) Publish(event wifi.Event) {
	s.spool.Enqueue(hostevents.Event{At: event.At, Encode: event.Encode})
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "version" {
		fmt.Println(version)
		return
	}
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: shakerproxy-wifi-worker [version]")
		os.Exit(2)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	spool, err := hostevents.New(envOr("SHAKERPROXY_EVENT_SPOOL", hostevents.DefaultSpool), "Wi-Fi events", logger)
	if err != nil {
		logger.Error("host event spool is unavailable", "error", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go spool.Run(ctx)
	worker := &wifi.Worker{
		RingDirectory: envOr("SHAKERPROXY_WIFI_RING", wifi.DefaultRingDirectory),
		ScopePath:     envOr("SHAKERPROXY_WIFI_SCOPE", wifi.DefaultScopePath),
		StatePath:     envOr("SHAKERPROXY_WIFI_STATE", wifi.DefaultStatePath),
		Sink:          spoolSink{spool: spool},
		Logger:        logger,
	}
	logger.Info("Wi-Fi worker starting", "ring", worker.RingDirectory, "scope", worker.ScopePath, "version", version)
	if err := worker.Run(ctx); err != nil {
		logger.Error("Wi-Fi worker stopped", "error", err)
		os.Exit(1)
	}
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
