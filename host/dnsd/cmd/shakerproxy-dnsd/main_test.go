package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/dnsproxy"
)

func environment(values map[string]string) func(string) string {
	return func(name string) string { return values[name] }
}

func TestHelpPrintsUsageWithoutServing(t *testing.T) {
	for _, arguments := range [][]string{{"--help"}, {"-h"}, {"-help"}} {
		var stdout, stderr bytes.Buffer
		served := false
		code := run(context.Background(), arguments, environment(nil), &stdout, &stderr, func(context.Context, *dnsproxy.Server) error {
			served = true
			return nil
		})
		if code != 0 || served || !strings.Contains(stdout.String(), "Usage:") {
			t.Fatalf("%v: code=%d served=%t output=%q", arguments, code, served, stdout.String())
		}
	}
}

func TestUnknownArgumentsFailWithoutServing(t *testing.T) {
	for _, arguments := range [][]string{{"serve"}, {"--bind", "0.0.0.0:53"}} {
		var stdout, stderr bytes.Buffer
		served := false
		code := run(context.Background(), arguments, environment(nil), &stdout, &stderr, func(context.Context, *dnsproxy.Server) error {
			served = true
			return nil
		})
		if code != 2 || served || !strings.Contains(stderr.String(), "Usage:") {
			t.Fatalf("%v: code=%d served=%t stderr=%q", arguments, code, served, stderr.String())
		}
	}
}

func TestOutOfRangeSettingsAreClampedLoudly(t *testing.T) {
	var stdout, stderr bytes.Buffer
	var configured *dnsproxy.Server
	code := run(context.Background(), nil, environment(map[string]string{
		"SHAKERPROXY_DNS_TIMEOUT_SECONDS":    "60",
		"SHAKERPROXY_DNS_MAX_CONCURRENT":     "many",
		"SHAKERPROXY_DNS_FALLBACK_UPSTREAMS": "192.0.2.1:53, 192.0.2.2:53",
	}), &stdout, &stderr, func(_ context.Context, server *dnsproxy.Server) error {
		configured = server
		return nil
	})
	if code != 0 || configured == nil {
		t.Fatalf("code=%d", code)
	}
	if configured.Timeout != 30*time.Second || configured.MaxConcurrent != 256 || configured.Bind != dnsproxy.DefaultBind {
		t.Fatalf("unexpected configuration: timeout=%s concurrency=%d bind=%q", configured.Timeout, configured.MaxConcurrent, configured.Bind)
	}
	provider := configured.Provider.(*dnsproxy.FilePolicyProvider)
	if len(provider.FallbackUpstreams) != 2 {
		t.Fatalf("fallback upstreams not parsed: %#v", provider.FallbackUpstreams)
	}
	log := stdout.String()
	if !strings.Contains(log, "SHAKERPROXY_DNS_TIMEOUT_SECONDS") || !strings.Contains(log, "clamping") || !strings.Contains(log, "SHAKERPROXY_DNS_MAX_CONCURRENT") {
		t.Fatalf("clamping and invalid values were not reported: %s", log)
	}
}
