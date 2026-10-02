package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"shakerproxy.dev/shakerproxy/internal/configlock"
	"shakerproxy.dev/shakerproxy/internal/coverage"
	"shakerproxy.dev/shakerproxy/internal/testlab"
)

// The visibility coverage check runs in three requests from control-api:
// prepare (this service builds the virtual lab and steers its DNS to the real
// DNS forwarder), probe (one of each traffic type from a virtual client), and
// cleanup. Between them control-api records the client bridge through
// gatewayd, so the probes travel the production capture, analyzer and ingest
// path. The configuration lock is held only while objects change.

func decodeStrict(r *http.Request, value any) error {
	decoder := json.NewDecoder(io.LimitReader(r.Body, 8<<10))
	decoder.DisallowUnknownFields()
	return decoder.Decode(value)
}

func withConfigurationLock(ctx context.Context, operation string, run func(context.Context)) bool {
	lockCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	guard, err := (configlock.Manager{}).Acquire(lockCtx, configlock.Request{
		OperationID: operation,
		Category:    configlock.CategoryNetwork,
		Actor:       "shakerproxy-testlabd",
	})
	cancel()
	if err != nil {
		return false
	}
	defer func() { _ = guard.Release() }()
	run(ctx)
	return true
}

func (d *daemon) coveragePrepare(w http.ResponseWriter, r *http.Request) {
	var request testlab.CoveragePrepareRequest
	if err := decodeStrict(r, &request); err != nil || !testlab.ValidCoverageRunID(request.RunID) {
		writeError(w, http.StatusBadRequest, "invalid coverage request")
		return
	}
	d.mu.Lock()
	if d.busy || d.coverageRun != "" {
		d.mu.Unlock()
		writeError(w, http.StatusConflict, "the virtual test lab is in use")
		return
	}
	d.busy = true
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		d.busy = false
		d.mu.Unlock()
	}()
	for _, prerequisite := range prerequisiteResults() {
		if prerequisite.Status == testlab.TestFail {
			writeError(w, http.StatusServiceUnavailable, "test-lab prerequisite missing: "+prerequisite.Name)
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	originalForward := strings.TrimSpace(readFile("/proc/sys/net/ipv4/ip_forward"))
	var setupErr error
	locked := withConfigurationLock(ctx, request.RunID+"-prepare", func(ctx context.Context) {
		cleanupCoverage(ctx)
		cleanupLab(ctx)
		if setupErr = setupLab(ctx); setupErr == nil {
			setupErr = setupCoverage(ctx)
		}
		if setupErr != nil {
			cleanupCoverage(ctx)
			cleanupLab(ctx)
			restoreForward(ctx, originalForward)
		}
	})
	if !locked {
		writeError(w, http.StatusConflict, "appliance configuration is busy; the coverage lab was not built")
		return
	}
	if setupErr != nil {
		d.logger.Error("coverage lab setup failed", "run_id", request.RunID, "error", setupErr)
		writeError(w, http.StatusServiceUnavailable, "the coverage lab could not be built: "+bound(setupErr.Error(), 512))
		return
	}
	expiresAt := time.Now().Add(testlab.CoverageLease).UTC()
	d.mu.Lock()
	d.coverageRun = request.RunID
	d.coverageForward = originalForward
	runID := request.RunID
	d.coverageTimer = time.AfterFunc(testlab.CoverageLease, func() {
		d.logger.Warn("coverage lab lease expired; removing it", "run_id", runID)
		d.finishCoverage(context.Background(), runID)
	})
	d.mu.Unlock()
	writeJSON(w, http.StatusOK, testlab.CoveragePrepareResponse{Schema: testlab.SchemaVersion, RunID: request.RunID, Bridge: clientBridge, ExpiresAt: expiresAt})
}

func (d *daemon) coverageProbe(w http.ResponseWriter, r *http.Request) {
	var request testlab.CoverageProbeRequest
	if err := decodeStrict(r, &request); err != nil || !testlab.ValidCoverageRunID(request.Plan.RunID) {
		writeError(w, http.StatusBadRequest, "invalid coverage request")
		return
	}
	d.mu.Lock()
	if d.coverageRun != request.Plan.RunID || d.busy {
		d.mu.Unlock()
		writeError(w, http.StatusConflict, "this coverage run is not prepared")
		return
	}
	d.busy = true
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		d.busy = false
		d.mu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(r.Context(), 75*time.Second)
	defer cancel()
	plan, err := json.Marshal(request.Plan)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid coverage plan")
		return
	}
	output, err := runCommand(ctx, "ip", "netns", "exec", normalNS, os.Args[0], "--coverage-probes", string(plan))
	var outcomes []coverage.ProbeOutcome
	if decodeErr := json.Unmarshal([]byte(lastLine(output)), &outcomes); err != nil || decodeErr != nil {
		d.logger.Error("coverage probes failed", "run_id", request.Plan.RunID, "error", err, "decode_error", decodeErr)
		writeError(w, http.StatusServiceUnavailable, "the coverage probes could not run")
		return
	}
	writeJSON(w, http.StatusOK, testlab.CoverageProbeResponse{Schema: testlab.SchemaVersion, RunID: request.Plan.RunID, Outcomes: outcomes})
}

func (d *daemon) coverageCleanup(w http.ResponseWriter, r *http.Request) {
	var request testlab.CoverageCleanupRequest
	if err := decodeStrict(r, &request); err != nil || !testlab.ValidCoverageRunID(request.RunID) {
		writeError(w, http.StatusBadRequest, "invalid coverage request")
		return
	}
	d.mu.Lock()
	active := d.coverageRun
	d.mu.Unlock()
	if active != "" && active != request.RunID {
		writeError(w, http.StatusConflict, "another coverage run owns the virtual test lab")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	if !d.finishCoverage(ctx, request.RunID) {
		writeError(w, http.StatusConflict, "appliance configuration is busy; retry the coverage cleanup")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"clean": true})
}

// finishCoverage removes a prepared coverage lab. It reports false when the
// configuration lock could not be taken; the lease timer retries later.
func (d *daemon) finishCoverage(ctx context.Context, runID string) bool {
	d.mu.Lock()
	if d.coverageRun != "" && d.coverageRun != runID {
		d.mu.Unlock()
		return true
	}
	forward := d.coverageForward
	d.mu.Unlock()
	cleaned := withConfigurationLock(ctx, runID+"-cleanup", func(ctx context.Context) {
		cleanupCoverage(ctx)
		cleanupLab(ctx)
		restoreForward(ctx, forward)
	})
	d.mu.Lock()
	defer d.mu.Unlock()
	if !cleaned {
		if d.coverageTimer != nil && d.coverageRun == runID {
			d.coverageTimer.Reset(30 * time.Second)
		}
		return false
	}
	if d.coverageTimer != nil {
		d.coverageTimer.Stop()
		d.coverageTimer = nil
	}
	d.coverageRun, d.coverageForward = "", ""
	return true
}

func restoreForward(ctx context.Context, value string) {
	if value == "0" || value == "1" {
		_, _ = runCommand(ctx, "sysctl", "-w", "net.ipv4.ip_forward="+value)
	}
}

func dnsForwarderPort() string {
	return strconv.Itoa(envInt("SHAKERPROXY_DNSD_PORT", 1053))
}

// coverageInputRules let the virtual clients reach the DNS forwarder; the
// production rules accept it only from the lab network.
func coverageInputRules() [][]string {
	rules := [][]string{}
	for _, protocol := range []string{"udp", "tcp"} {
		rules = append(rules, []string{"-i", clientBridge, "-p", protocol, "--dport", dnsForwarderPort(), "-m", "comment", "--comment", testTable, "-j", "ACCEPT"})
	}
	return rules
}

// setupCoverage steers the virtual clients' DNS for their gateway to
// ShakerProxy's DNS forwarder, as the lab's own DNS redirect does, inside
// the test lab's dedicated nftables table.
func setupCoverage(ctx context.Context) error {
	commands := [][]string{
		{"nft", "add", "chain", "inet", testTable, "prerouting", "{", "type", "nat", "hook", "prerouting", "priority", "-100", ";", "policy", "accept", ";", "}"},
		// Unprivileged ICMP echo sockets inside the probing client's own
		// namespace only, so the ICMP probe needs no raw-socket capability.
		{"ip", "netns", "exec", normalNS, "sysctl", "-w", "net.ipv4.ping_group_range=0 2147483647"},
	}
	for _, protocol := range []string{"udp", "tcp"} {
		commands = append(commands, []string{"nft", "add", "rule", "inet", testTable, "prerouting", "iifname", clientBridge, "ip", "daddr", testlab.DefaultGatewayIPv4, protocol, "dport", "53", "redirect", "to", ":" + dnsForwarderPort()})
	}
	for _, command := range commands {
		if _, err := runCommand(ctx, command[0], command[1:]...); err != nil {
			return err
		}
	}
	for _, rule := range coverageInputRules() {
		if _, err := runCommand(ctx, "iptables", append([]string{"-I", "INPUT", "1"}, rule...)...); err != nil {
			return err
		}
	}
	return nil
}

func cleanupCoverage(ctx context.Context) {
	for _, rule := range coverageInputRules() {
		for attempt := 0; attempt < 8; attempt++ {
			if _, err := runCommand(ctx, "iptables", append([]string{"-D", "INPUT"}, rule...)...); err != nil {
				break
			}
		}
	}
	// The redirect lives in the test lab table, which cleanupLab deletes.
}

func lastLine(output string) string {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	return lines[len(lines)-1]
}
