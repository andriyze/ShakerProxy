package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"shakerproxy.dev/shakerproxy/internal/dnsproxy"
)

const usage = `shakerproxy-dnsd — ShakerProxy local DNS forwarder

Usage:
  shakerproxy-dnsd            serve (normally started by systemd as shakerproxy-dnsd.service)
  shakerproxy-dnsd --help     show this help and exit

The gateway redirects lab clients' DNS here when "Force plain DNS through
ShakerProxy" is on or a device has blocked domains. Names blocked for a device are
answered with NXDOMAIN; everything else is forwarded to the policy's upstream
servers, or to the host resolver when the policy names none.

Environment:
  SHAKERPROXY_DNS_BIND                 listen address (default %s, both IPv4 and IPv6)
  SHAKERPROXY_TRAFFIC_POLICY_FILE      runtime policy (default /var/lib/shakerproxy/traffic/policy.json)
  SHAKERPROXY_DNS_TIMEOUT_SECONDS      upstream timeout, 1-30 (default 4)
  SHAKERPROXY_DNS_MAX_CONCURRENT       concurrent queries, 16-4096 (default 256)
  SHAKERPROXY_DNS_FALLBACK_UPSTREAMS   comma-separated IP:53 used when the policy names
                                   no upstream (default: the host resolver)
  SHAKERPROXY_DNS_EVENT_SPOOL          where each answered lookup is left for Traffic
                                   (default %s; "off" disables)

Example:
  sudo systemctl status shakerproxy-dnsd
  dig @<lab gateway> example.com
`

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Getenv, os.Stdout, os.Stderr, serve))
}

type serveFunc func(context.Context, *dnsproxy.Server) error

func serve(ctx context.Context, server *dnsproxy.Server) error { return server.Serve(ctx) }

func run(parent context.Context, arguments []string, getenv func(string) string, stdout, stderr io.Writer, serveWith serveFunc) int {
	flags := flag.NewFlagSet("shakerproxy-dnsd", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	help := flags.Bool("help", false, "show help")
	flags.BoolVar(help, "h", false, "show help")
	if err := flags.Parse(arguments); err != nil {
		fmt.Fprintf(stderr, "shakerproxy-dnsd: %v\n\n", err)
		fmt.Fprintf(stderr, usage, dnsproxy.DefaultBind, dnsproxy.DefaultEventSpool)
		return 2
	}
	if *help {
		fmt.Fprintf(stdout, usage, dnsproxy.DefaultBind, dnsproxy.DefaultEventSpool)
		return 0
	}
	if flags.NArg() != 0 {
		fmt.Fprintf(stderr, "shakerproxy-dnsd: unexpected argument %q\n\n", flags.Arg(0))
		fmt.Fprintf(stderr, usage, dnsproxy.DefaultBind, dnsproxy.DefaultEventSpool)
		return 2
	}

	logger := slog.New(slog.NewJSONHandler(stdout, nil))
	concurrency := envInt(logger, getenv, "SHAKERPROXY_DNS_MAX_CONCURRENT", 256, 16, 4096)
	timeout := time.Duration(envInt(logger, getenv, "SHAKERPROXY_DNS_TIMEOUT_SECONDS", 4, 1, 30)) * time.Second
	var fallback []string
	for _, value := range strings.Split(getenv("SHAKERPROXY_DNS_FALLBACK_UPSTREAMS"), ",") {
		if value = strings.TrimSpace(value); value != "" {
			fallback = append(fallback, value)
		}
	}
	server := &dnsproxy.Server{
		Bind:          envOr(getenv, "SHAKERPROXY_DNS_BIND", dnsproxy.DefaultBind),
		Provider:      &dnsproxy.FilePolicyProvider{Path: envOr(getenv, "SHAKERPROXY_TRAFFIC_POLICY_FILE", "/var/lib/shakerproxy/traffic/policy.json"), FallbackUpstreams: fallback},
		Logger:        logger,
		Timeout:       timeout,
		MaxConcurrent: concurrency,
	}
	ctx, stop := signal.NotifyContext(parent, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	recording := false
	if spool := envOr(getenv, "SHAKERPROXY_DNS_EVENT_SPOOL", dnsproxy.DefaultEventSpool); spool != "off" {
		// Answering DNS matters more than recording it: without a usable
		// spool the forwarder still serves, and says so once.
		if recorder, err := dnsproxy.NewSpoolRecorder(spool, logger); err != nil {
			logger.Warn("DNS lookups are not recorded for Traffic", "spool", spool, "error", err)
		} else {
			server.Observer = recorder
			recording = true
			go recorder.Run(ctx)
		}
	}
	logger.Info("ShakerProxy DNS forwarder starting", "bind", server.Bind, "timeout", timeout.String(), "max_concurrent", concurrency, "fallback_upstreams", len(fallback), "recording_lookups", recording)
	if err := serveWith(ctx, server); err != nil {
		logger.Error("ShakerProxy DNS forwarder stopped", "error", err)
		return 1
	}
	return 0
}

func envOr(getenv func(string) string, name, fallback string) string {
	if value := strings.TrimSpace(getenv(name)); value != "" {
		return value
	}
	return fallback
}

// envInt clamps out-of-range values to the nearest bound and says so; an
// unparsable value falls back to the default, also with a warning.
func envInt(logger *slog.Logger, getenv func(string) string, name string, fallback, minimum, maximum int) int {
	raw := strings.TrimSpace(getenv(name))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		logger.Warn("ignoring invalid setting; using the default", "setting", name, "value", raw, "default", fallback)
		return fallback
	}
	if value < minimum || value > maximum {
		clamped := min(max(value, minimum), maximum)
		logger.Warn("setting is outside its allowed range; clamping", "setting", name, "value", value, "minimum", minimum, "maximum", maximum, "using", clamped)
		return clamped
	}
	return value
}
