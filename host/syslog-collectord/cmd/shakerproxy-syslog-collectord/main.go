// Command shakerproxy-syslog-collectord receives a network device's own logs
// (the lab router and its access points) over syslog and turns them into
// ShakerProxy events and device identity. It is off unless the integration is
// enabled, and accepts only allowlisted sources. It is normally started by
// systemd as shakerproxy-syslog-collectord.service and left running: it does
// nothing until its config file enables it, so turning it on from the
// dashboard needs no privileged service management.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"shakerproxy.dev/shakerproxy/internal/syslogcollector"
)

const usage = `shakerproxy-syslog-collectord — ShakerProxy network-gear log collector

It receives the lab router's remote syslog (UniFi first) and turns DHCP
leases, Wi-Fi associations, firewall and IDS lines into events that appear in
the Live view, API and MCP. In single-arm and inline-bridge labs this is how
ShakerProxy sees what the router sees but never captures on the wire.

The collector runs continuously and does nothing until the integration is
enabled (from the dashboard, the API, or shakerproxy syslog enable). It then
accepts logs only from the configured allowed sources.

Environment:
  SHAKERPROXY_SYSLOG_CONFIG_FILE     config the dashboard writes
                                     (default /var/lib/shakerproxy/forwarders/syslog-collector.json)
  SHAKERPROXY_SYSLOG_STATUS_FILE     status for the dashboard
                                     (default /var/lib/shakerproxy/forwarders/syslog-collector-status.json)
  SHAKERPROXY_INGEST_ORIGIN          ingestd base URL (default http://127.0.0.1:9600)
  SHAKERPROXY_INGEST_TOKEN_FILE      ingest token file (default /run/secrets/ingest_token)
`

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	for _, argument := range os.Args[1:] {
		if argument == "-h" || argument == "--help" || argument == "help" {
			fmt.Print(usage)
			return
		}
	}
	if err := run(logger); err != nil {
		logger.Error("network-gear syslog collector stopped", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	origin := envOr("SHAKERPROXY_INGEST_ORIGIN", "http://127.0.0.1:9600")
	tokenPath := envOr("SHAKERPROXY_INGEST_TOKEN_FILE", "/run/secrets/ingest_token")
	newSink := func() (syslogcollector.Sink, error) {
		token, err := os.ReadFile(tokenPath)
		if err != nil {
			return nil, fmt.Errorf("read ingest token: %w", err)
		}
		return syslogcollector.NewHTTPSink(origin, []byte(strings.TrimSpace(string(token))))
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	supervisor := &syslogcollector.Supervisor{
		ConfigPath: envOr("SHAKERPROXY_SYSLOG_CONFIG_FILE", "/var/lib/shakerproxy/syslog-collector/config.json"),
		StatusPath: envOr("SHAKERPROXY_SYSLOG_STATUS_FILE", "/var/lib/shakerproxy/syslog-collector/status.json"),
		Interval:   5 * time.Second,
		NewSink:    newSink,
		Logger:     logger,
	}
	logger.Info("network-gear syslog collector started; waiting for the integration to be enabled")
	return supervisor.Run(ctx)
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
