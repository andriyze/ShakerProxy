package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"shakerproxy.dev/shakerproxy/internal/configlock"
	"shakerproxy.dev/shakerproxy/internal/testlab"
)

type daemon struct {
	mu      sync.Mutex
	busy    bool
	lastRun *testlab.Run
	logger  *slog.Logger
}

func main() {
	if handleHelperMode() {
		return
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "shakerproxy-testlabd must run as root")
		os.Exit(1)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	d := &daemon{logger: logger}
	socketPath := envOr("SHAKERPROXY_TESTLAB_SOCKET", testlab.DefaultSocketPath)
	_ = os.Remove(socketPath)
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o750); err != nil {
		logger.Error("create socket directory", "error", err)
		os.Exit(1)
	}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		logger.Error("listen", "error", err)
		os.Exit(1)
	}
	defer listener.Close()
	if err := os.Chmod(socketPath, 0o660); err != nil {
		logger.Error("chmod socket", "error", err)
		os.Exit(1)
	}
	if err := os.Chown(socketPath, 0, envInt("SHAKERPROXY_CONTROL_API_GID", 65532)); err != nil {
		logger.Error("chown socket", "error", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", d.status)
	mux.HandleFunc("POST /v1/run", d.run)
	mux.HandleFunc("POST /v1/cleanup", d.cleanup)
	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      110 * time.Second,
		IdleTimeout:       10 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	logger.Info("test lab service starting", "socket", socketPath)
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("serve", "error", err)
		os.Exit(1)
	}
}

func (d *daemon) status(w http.ResponseWriter, _ *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()

	prerequisites := prerequisiteResults()
	available := true
	for _, item := range prerequisites {
		if item.Status == testlab.TestFail {
			available = false
		}
	}
	state := testlab.StateIdle
	if d.busy {
		state = testlab.StateRunning
	} else if d.lastRun != nil {
		state = d.lastRun.State
	}
	writeJSON(w, http.StatusOK, testlab.Status{
		Schema:      testlab.SchemaVersion,
		State:       state,
		Available:   available,
		Busy:        d.busy,
		LastRun:     d.lastRun,
		Prereq:      prerequisites,
		UpdatedAt:   time.Now().UTC(),
		Limitations: statusLimitations(),
	})
}

func (d *daemon) run(w http.ResponseWriter, r *http.Request) {
	var request testlab.RunRequest
	decoder := json.NewDecoder(io.LimitReader(r.Body, 8<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || !testlab.ValidProfile(request.Profile) {
		writeError(w, http.StatusBadRequest, "invalid test-lab profile")
		return
	}

	d.mu.Lock()
	if d.busy {
		d.mu.Unlock()
		writeError(w, http.StatusConflict, "test lab is already running")
		return
	}
	d.busy = true
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		d.busy = false
		d.mu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(r.Context(), testlab.DefaultRunTimeout)
	defer cancel()
	run := d.execute(ctx, request.Profile)
	d.mu.Lock()
	d.lastRun = &run
	d.mu.Unlock()
	writeJSON(w, http.StatusOK, run)
}

func (d *daemon) cleanup(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	if d.busy {
		d.mu.Unlock()
		writeError(w, http.StatusConflict, "test lab is running")
		return
	}
	d.mu.Unlock()

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	lockCtx, lockCancel := context.WithTimeout(ctx, 2*time.Second)
	guard, err := (configlock.Manager{}).Acquire(lockCtx, configlock.Request{
		OperationID: cleanupOperationID(),
		Category:    configlock.CategoryNetwork,
		Actor:       "shakerproxy-testlabd",
	})
	lockCancel()
	if err != nil {
		writeError(w, http.StatusConflict, "appliance configuration is busy; test-lab cleanup did not run")
		return
	}
	defer guard.Release()
	cleanupLab(ctx)
	writeJSON(w, http.StatusOK, map[string]any{"clean": true})
}

// execute returns a named result so the deferred finalizeRun updates the value
// the caller receives; with an unnamed result the returned copy would keep the
// RUNNING state and zero counts.
func (d *daemon) execute(ctx context.Context, profile testlab.Profile) (run testlab.Run) {
	startedAt := time.Now().UTC()
	run = testlab.Run{
		Schema:    testlab.SchemaVersion,
		RunID:     randomID(),
		Profile:   profile,
		State:     testlab.StateRunning,
		StartedAt: startedAt,
		Environment: testlab.Environment{
			Bridge:              clientBridge,
			CIDR:                testlab.DefaultClientCIDR,
			GatewayIPv4:         testlab.DefaultGatewayIPv4,
			NormalClientIPv4:    testlab.DefaultNormalClient,
			BypassClientIPv4:    testlab.DefaultBypassClient,
			DNSClientIPv4:       testlab.DefaultDNSClient,
			NamespaceIsolation:  true,
			ShakerProxyDNSPort:  envInt("SHAKERPROXY_LOCAL_DNS_PORT", 5353),
			ShakerProxyMITMPort: envInt("SHAKERPROXY_MITM_PORT", 8085),
		},
		Limitations: runLimitations(),
	}
	defer finalizeRun(&run)

	lockCtx, lockCancel := context.WithTimeout(ctx, 2*time.Second)
	guard, err := (configlock.Manager{}).Acquire(lockCtx, configlock.Request{
		OperationID: run.RunID,
		Category:    configlock.CategoryNetwork,
		Actor:       "shakerproxy-testlabd",
	})
	lockCancel()
	if err != nil {
		run.Results = append(run.Results, result(
			"configuration-lock",
			"Appliance configuration lock",
			"safety",
			testlab.TestFail,
			"Another privileged ShakerProxy mutation is active; virtual networking was not changed.",
			err.Error(),
			time.Since(startedAt),
		))
		return run
	}

	originalForward := strings.TrimSpace(readFile("/proc/sys/net/ipv4/ip_forward"))
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		cleanupLab(cleanupCtx)
		if originalForward == "0" || originalForward == "1" {
			_, _ = runCommand(cleanupCtx, "sysctl", "-w", "net.ipv4.ip_forward="+originalForward)
		}
		cleanupCancel()
		_ = guard.Release()
	}()

	for _, prerequisite := range prerequisiteResults() {
		if prerequisite.Status == testlab.TestFail {
			run.Results = append(run.Results, prerequisite)
			return run
		}
	}
	cleanupLab(ctx)
	if err := setupLab(ctx); err != nil {
		run.Results = append(run.Results, result(
			"virtual-lab-setup",
			"Virtual client topology",
			"network",
			testlab.TestFail,
			err.Error(),
			"",
			time.Since(startedAt),
		))
		return run
	}
	run.Results = append(run.Results, result(
		"virtual-lab-setup",
		"Virtual client topology",
		"network",
		testlab.TestPass,
		"Three isolated clients and one target namespace were created on two RFC 2544 benchmark subnets.",
		"lgtest-*",
		time.Since(startedAt),
	))

	if shouldRun(profile, "network") {
		run.Results = append(run.Results,
			commandTest(ctx, "ipv4-routing", "IPv4 routed HTTP", "network", normalNS, []string{
				"curl", "--fail", "--silent", "--show-error", "--max-time", "8", "http://" + targetIPv4 + ":8080/health",
			}, true),
			commandTest(ctx, "client-isolation", "Independent virtual client identity", "network", bypassNS, []string{
				"curl", "--fail", "--silent", "--show-error", "--max-time", "8", "http://" + targetIPv4 + ":8080/whoami",
			}, true),
		)
	}
	if shouldRun(profile, "dns") {
		run.Results = append(run.Results, commandTest(ctx, "udp-dns", "UDP DNS transaction", "dns", dnsNS, []string{
			os.Args[0], "--probe-dns", targetIPv4 + ":53",
		}, true))
		// Prove DoT works before blocking it, so the block result cannot pass
		// merely because nothing was listening.
		run.Results = append(run.Results, commandTest(ctx, "dot-baseline", "DoT reachable before blocking", "dns", dnsNS, []string{
			os.Args[0], "--probe-tls", targetIPv4 + ":853",
		}, true))
		if err := addDotBlock(ctx); err != nil {
			run.Results = append(run.Results, result("dot-block-mechanic", "DoT blocking mechanic", "dns", testlab.TestFail, err.Error(), "", 0))
		} else {
			run.Results = append(run.Results, commandTest(ctx, "dot-block-mechanic", "DoT blocking mechanic", "dns", dnsNS, []string{
				os.Args[0], "--probe-tls", targetIPv4 + ":853",
			}, false))
		}
		run.Results = append(run.Results, result(
			"encrypted-dns-product-proof",
			"ShakerProxy encrypted-DNS policy proof",
			"dns",
			testlab.TestSkip,
			"Synthetic blocking is intentionally not counted as ShakerProxy policy proof. Run the normal traffic-policy acceptance flow for DoH/DoT/DoQ classification and fallback evidence.",
			"docs/testing/mvp-physical-client-acceptance.md",
			0,
		))
	}
	if shouldRun(profile, "tls") {
		if !fileExists("/var/lib/shakerproxy/public/interception-ca.crt") && !fileExists("/var/lib/shakerproxy/public/interception-ca.pem") {
			run.Results = append(run.Results, result("tls-interception", "TLS interception", "tls", testlab.TestSkip, "Interception CA is not provisioned on this host.", "", 0))
		} else {
			run.Results = append(run.Results, result(
				"tls-interception",
				"TLS interception",
				"tls",
				testlab.TestSkip,
				"Virtual topology is ready, but the test service does not bypass authoritative traffic-policy ownership to force interception. Select a virtual client through the normal policy path before claiming TLS proof.",
				"shakerproxy://selftest/tls-interception",
				0,
			))
		}
		run.Results = append(run.Results, result(
			"pinning-recovery",
			"Pinned/custom-trust recovery",
			"tls",
			testlab.TestSkip,
			"Automatic probable-pinning bypass requires a real intercepted client with stable device attribution and repeated TLS failure evidence.",
			"docs/testing/mvp-physical-client-acceptance.md",
			0,
		))
	}
	if profile == testlab.ProfileFull {
		run.Results = append(run.Results,
			result("pcap-analysis", "PCAP → Zeek/Suricata → search", "analysis", testlab.TestSkip, "This host-side lab does not fabricate analyzer evidence. Start a normal ShakerProxy capture while virtual clients run, then verify resulting events through Traffic search.", "shakerproxy://selftest/analysis", 0),
			result("mcp-query", "MCP metadata query", "agent", testlab.TestSkip, "MCP requires a separately scoped API token; the self-test service never creates or reads agent credentials.", "docs/mcp-agent-integration.md", 0),
		)
	}
	return run
}

func finalizeRun(run *testlab.Run) {
	finishedAt := time.Now().UTC()
	run.FinishedAt = &finishedAt
	for _, item := range run.Results {
		switch item.Status {
		case testlab.TestPass:
			run.PassCount++
		case testlab.TestFail:
			run.FailCount++
		case testlab.TestSkip:
			run.SkipCount++
		}
	}
	switch {
	case run.FailCount > 0:
		run.State = testlab.StateFailed
	case run.SkipCount > 0:
		run.State = testlab.StateDegraded
	default:
		run.State = testlab.StatePassed
	}
}

func statusLimitations() []string {
	return []string{
		"Virtual clients prove isolated IPv4 runtime behavior; they do not certify Android, iOS, Wi-Fi, or Smart TV platform behavior.",
		"Encrypted-DNS and automatic mobile-pinning classification require the real ShakerProxy policy/event path; synthetic drops are never reported as product proof.",
	}
}

func runLimitations() []string {
	return []string{
		"Synthetic Linux namespaces are not substitutes for physical-client certification.",
		"The pinning test proves TLS rejection/recovery mechanics only when the real policy path is used; this service does not fabricate that evidence.",
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
