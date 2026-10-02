package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"shakerproxy.dev/shakerproxy/internal/analyzer"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	stateRoot := envOr("SHAKERPROXY_ANALYZER_STATE_ROOT", "/var/lib/shakerproxy/analyzer")
	if len(os.Args) == 2 && os.Args[1] == "-healthcheck" {
		if err := healthcheck(stateRoot, time.Now()); err != nil {
			logger.Error("analyzer healthcheck failed", "error", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 2 || len(os.Args) == 2 && os.Args[1] != "-once" {
		logger.Error("unsupported analyzer argument")
		os.Exit(2)
	}
	engine, err := analyzer.ParseEngine(os.Getenv("SHAKERPROXY_ANALYZER_ENGINE"))
	if err != nil {
		logger.Error("analyzer engine rejected", "error", err)
		os.Exit(1)
	}
	token, err := analyzer.LoadToken(envOr("SHAKERPROXY_INGEST_TOKEN_FILE", "/run/secrets/ingest_token"))
	if err != nil {
		logger.Error("analyzer ingest token unavailable", "error", err)
		os.Exit(1)
	}
	pollInterval, err := durationEnv("SHAKERPROXY_ANALYZER_POLL_INTERVAL", analyzer.DefaultPollInterval)
	if err != nil {
		logger.Error("analyzer poll interval rejected", "error", err)
		os.Exit(1)
	}
	analysisLimit, err := durationEnv("SHAKERPROXY_ANALYZER_TIME_LIMIT", analyzer.DefaultAnalysisLimit)
	if err != nil {
		logger.Error("analyzer time limit rejected", "error", err)
		os.Exit(1)
	}
	maxOutput, err := int64Env("SHAKERPROXY_ANALYZER_MAX_OUTPUT_BYTES", analyzer.DefaultMaxOutputBytes)
	if err != nil {
		logger.Error("analyzer output limit rejected", "error", err)
		os.Exit(1)
	}
	config := analyzer.Config{
		Engine: engine, CaptureRoot: envOr("SHAKERPROXY_CAPTURE_ROOT", "/var/lib/shakerproxy/pcap"), StateRoot: stateRoot,
		WorkRoot: envOr("SHAKERPROXY_ANALYZER_WORK_ROOT", "/work"), IngestURL: envOr("SHAKERPROXY_INGEST_URL", "http://ingestd:8081"),
		Token: token, SourceVersion: os.Getenv("SHAKERPROXY_ANALYZER_SOURCE_VERSION"), PollInterval: pollInterval,
		AnalysisLimit: analysisLimit, MaxOutputBytes: maxOutput,
	}
	runner, err := analyzer.NewRunner(config)
	if err != nil {
		logger.Error("analyzer configuration rejected", "error", err)
		os.Exit(1)
	}
	maintenanceToken, err := analyzer.LoadMaintenanceToken(envOr("SHAKERPROXY_ANALYZER_MAINTENANCE_TOKEN_FILE", "/run/secrets/event_deletion_token"))
	if err != nil {
		logger.Error("analyzer maintenance token unavailable", "error", err)
		os.Exit(1)
	}
	deletionService, err := analyzer.NewCheckpointDeletionService(runner.State, engine)
	if err != nil {
		logger.Error("analyzer checkpoint deletion service unavailable", "error", err)
		os.Exit(1)
	}
	maintenanceHandler, err := analyzer.NewMaintenanceHandler(deletionService, maintenanceToken)
	if err != nil {
		logger.Error("analyzer maintenance service rejected", "error", err)
		os.Exit(1)
	}
	maintenanceListener, err := net.Listen("tcp", envOr("SHAKERPROXY_ANALYZER_MAINTENANCE_BIND", "0.0.0.0:8082"))
	if err != nil {
		logger.Error("analyzer maintenance listener unavailable", "error", err)
		os.Exit(1)
	}
	maintenanceServer := &http.Server{
		Handler: maintenanceHandler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 << 10,
	}
	now := time.Now().UTC()
	status := analyzer.Status{Schema: analyzer.SchemaVersion, Engine: engine, SourceVersion: config.SourceVersion, StartedAt: now, UpdatedAt: now}
	if previous, readErr := runner.State.ReadStatus(); readErr == nil {
		if previous.Engine != engine || previous.SourceVersion != config.SourceVersion {
			logger.Error("analyzer state belongs to a different runtime")
			os.Exit(1)
		}
		status = previous
	} else if !errors.Is(readErr, os.ErrNotExist) {
		logger.Error("analyzer status state is invalid", "error", readErr)
		os.Exit(1)
	}
	if runner.Ruleset != nil {
		status.RulesetID = runner.Ruleset.RulesetID
		status.RulesetVersion = runner.Ruleset.Version
		status.RulesetSHA256 = runner.Ruleset.SHA256
	}
	status.ScanInProgress = false
	status.UpdatedAt = time.Now().UTC()
	if err := runner.State.WriteStatus(status); err != nil {
		logger.Error("analyzer status cannot be persisted", "error", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	defer func() {
		shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = maintenanceServer.Shutdown(shutdownContext)
	}()
	go func() {
		if serveErr := maintenanceServer.Serve(maintenanceListener); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			logger.Error("analyzer maintenance service stopped", "error", serveErr)
			stop()
		}
	}()
	// Live analysis follows the automatic lab recording with one long Zeek;
	// the offline pass below analyzes every segment it does not cover.
	var live *analyzer.LiveAnalyzer
	liveDone := make(chan struct{})
	if engine == analyzer.EngineZeek && len(os.Args) == 1 && liveEnabled(os.Getenv("SHAKERPROXY_ZEEK_LIVE")) {
		coverage, coverageErr := analyzer.NewLiveCoverage(runner.State, config.CaptureRoot, time.Now)
		if coverageErr != nil {
			logger.Error("live analysis coverage state is invalid", "error", coverageErr)
			os.Exit(1)
		}
		runner.Live = coverage
		live = analyzer.NewLiveAnalyzer(runner, coverage, logger)
		go func() {
			defer close(liveDone)
			live.Run(ctx)
		}()
		logger.Info("live analysis of the lab recording enabled", "engine", engine)
	} else {
		close(liveDone)
	}
	// refreshLive copies live analysis progress into the status; the caller
	// holds statusMutex.
	refreshLive := func() {
		switch {
		case live != nil:
			snapshot := live.Status()
			status.Live = &snapshot
			status.DeliveredEvents += live.TakeDelivered()
		case engine == analyzer.EngineZeek:
			status.Live = &analyzer.LiveStatus{State: analyzer.LiveStateOff}
		}
	}
	var statusMutex sync.Mutex
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case heartbeatAt := <-ticker.C:
				statusMutex.Lock()
				refreshLive()
				status.UpdatedAt = heartbeatAt.UTC()
				writeErr := runner.State.WriteStatus(status)
				statusMutex.Unlock()
				if writeErr != nil {
					logger.Error("analyzer heartbeat cannot be persisted", "error", writeErr)
				}
			}
		}
	}()
	logger.Info("offline analyzer worker starting", "engine", engine, "source_version", config.SourceVersion, "ruleset_version", status.RulesetVersion, "ruleset_sha256", status.RulesetSHA256, "capture_root", config.CaptureRoot, "maintenance_address", maintenanceListener.Addr().String())
	for {
		scanStarted := time.Now().UTC()
		statusMutex.Lock()
		status.LastScanAt = scanStarted
		status.ScanInProgress = true
		status.UpdatedAt = scanStarted
		startWriteErr := runner.State.WriteStatus(status)
		statusMutex.Unlock()
		if startWriteErr != nil {
			logger.Error("analyzer scan state cannot be persisted", "error", startWriteErr)
			os.Exit(1)
		}
		result := runner.RunOnce(ctx)
		statusMutex.Lock()
		status.LastScanAt = scanStarted
		status.ScanInProgress = false
		status.UpdatedAt = time.Now().UTC()
		status.CompletedCaptures += uint64(result.Completed)
		status.DeliveredEvents += uint64(result.Events)
		refreshLive()
		if len(result.Errors) == 0 {
			status.LastSuccessAt = status.UpdatedAt
			if result.Deferred == 0 {
				// Keep the last failure visible while a capture waits in retry
				// backoff; clear it once nothing is deferred.
				status.LastError = ""
			}
		} else {
			status.LastError = boundedError(errors.Join(result.Errors...))
			logger.Warn("analyzer scan completed with isolated failures", "engine", engine, "discovered", result.Discovered, "completed", result.Completed, "errors", len(result.Errors), "detail", status.LastError)
		}
		if err := runner.State.WriteStatus(status); err != nil {
			statusMutex.Unlock()
			logger.Error("analyzer status cannot be persisted", "error", err)
			os.Exit(1)
		}
		statusMutex.Unlock()
		if result.Completed > 0 || result.Events > 0 {
			logger.Info("analyzer scan completed", "engine", engine, "captures", result.Completed, "events", result.Events, "already_complete", result.Skipped, "deferred", result.Deferred)
		}
		if len(os.Args) == 2 && os.Args[1] == "-once" {
			if len(result.Errors) > 0 {
				os.Exit(1)
			}
			return
		}
		timer := time.NewTimer(config.PollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			// Live analysis finishes the segment being written and delivers
			// what Zeek produced before the worker exits.
			<-liveDone
			logger.Info("offline analyzer worker stopped", "engine", engine)
			return
		case <-timer.C:
		}
	}
}

func healthcheck(stateRoot string, now time.Time) error {
	health, err := (analyzer.StateStore{Root: stateRoot}).Health(now)
	if err != nil {
		return err
	}
	if health.Validate() != nil || !health.Healthy {
		return errors.New("analyzer health is stale")
	}
	return nil
}

func durationEnv(name string, fallback time.Duration) (time.Duration, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	return time.ParseDuration(value)
}

func int64Env(name string, fallback int64) (int64, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	return strconv.ParseInt(value, 10, 64)
}

func boundedError(err error) string {
	if err == nil {
		return ""
	}
	value := strings.Map(func(char rune) rune {
		if char < 0x20 || char == 0x7f {
			return ' '
		}
		return char
	}, err.Error())
	if len(value) > 2048 {
		value = value[:2048]
	}
	return strings.TrimSpace(value)
}

// liveEnabled reads SHAKERPROXY_ZEEK_LIVE; live analysis is on unless it is
// set to off, false, or 0.
func liveEnabled(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "off", "false", "0", "no":
		return false
	default:
		return true
	}
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
