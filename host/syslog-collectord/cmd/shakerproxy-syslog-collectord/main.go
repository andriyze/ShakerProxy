// Command shakerproxy-syslog-collectord receives a network device's own logs
// (the lab router and its access points) over syslog and turns them into
// ShakerProxy events and device identity. It is off unless explicitly enabled,
// and accepts only allowlisted sources. It is normally started by systemd as
// shakerproxy-syslog-collectord.service.
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

Off by default. Set SHAKERPROXY_SYSLOG_ENABLED=1 and at least one allowed
source to turn it on.

Environment:
  SHAKERPROXY_SYSLOG_ENABLED         "1" to run; anything else keeps it off
  SHAKERPROXY_SYSLOG_BIND            listen address (default :1514)
  SHAKERPROXY_SYSLOG_TCP             "1"/"0" to accept TCP (default on)
  SHAKERPROXY_SYSLOG_UDP             "1" to also accept UDP (spoofable; default off)
  SHAKERPROXY_SYSLOG_ALLOWED         comma-separated device IPs to accept (required)
  SHAKERPROXY_SYSLOG_STATUS_FILE     where to write status for the dashboard
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
	if os.Getenv("SHAKERPROXY_SYSLOG_ENABLED") != "1" {
		logger.Info("network-gear syslog collector is disabled; set SHAKERPROXY_SYSLOG_ENABLED=1 to run it")
		return
	}
	if err := run(logger); err != nil {
		logger.Error("network-gear syslog collector stopped", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	allowed, err := syslogcollector.ParseAllowedSources(os.Getenv("SHAKERPROXY_SYSLOG_ALLOWED"))
	if err != nil {
		return err
	}
	origin := envOr("SHAKERPROXY_INGEST_ORIGIN", "http://127.0.0.1:9600")
	token, err := os.ReadFile(envOr("SHAKERPROXY_INGEST_TOKEN_FILE", "/run/secrets/ingest_token"))
	if err != nil {
		return fmt.Errorf("read ingest token: %w", err)
	}
	sink, err := syslogcollector.NewHTTPSink(origin, []byte(strings.TrimSpace(string(token))))
	if err != nil {
		return err
	}
	config := syslogcollector.Config{
		Enabled:        true,
		BindAddress:    envOr("SHAKERPROXY_SYSLOG_BIND", ":1514"),
		EnableTCP:      os.Getenv("SHAKERPROXY_SYSLOG_TCP") != "0",
		EnableUDP:      os.Getenv("SHAKERPROXY_SYSLOG_UDP") == "1",
		AllowedSources: allowed,
	}
	receiver, err := syslogcollector.NewReceiver(config, sink, logger)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	statusFile := os.Getenv("SHAKERPROXY_SYSLOG_STATUS_FILE")
	if statusFile != "" {
		go writeStatusLoop(ctx, statusFile, config, receiver, logger)
	}
	logger.Info("network-gear syslog collector listening", "bind", config.BindAddress, "tcp", config.EnableTCP, "udp", config.EnableUDP, "allowed_sources", len(allowed))
	return receiver.Run(ctx)
}

func writeStatusLoop(ctx context.Context, path string, config syslogcollector.Config, receiver *syslogcollector.Receiver, logger *slog.Logger) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	write := func() {
		allowed := make([]string, 0, len(config.AllowedSources))
		for _, address := range config.AllowedSources {
			allowed = append(allowed, address.String())
		}
		status := syslogcollector.Status{
			Enabled: config.Enabled, BindAddress: config.BindAddress, TCP: config.EnableTCP, UDP: config.EnableUDP,
			AllowedSources: allowed, Stats: receiver.Stats(),
		}
		if err := syslogcollector.WriteStatusFile(path, status); err != nil {
			logger.Warn("network-gear syslog status could not be written", "error", err)
		}
	}
	write()
	for {
		select {
		case <-ctx.Done():
			write()
			return
		case <-ticker.C:
			write()
		}
	}
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
