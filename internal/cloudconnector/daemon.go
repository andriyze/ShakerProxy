package cloudconnector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const connectorRuntimeStateFile = "connector-runtime.json"

type DaemonConfig struct {
	Root              string
	ControlSocket     string
	PolicySocket      string
	ServerCAFile      string
	Version           string
	HeartbeatInterval time.Duration
}

type ConnectorRuntimeState struct {
	SchemaVersion        int       `json:"schema_version"`
	AppliedRevision      uint64    `json:"applied_revision"`
	DesiredRevision      uint64    `json:"desired_revision"`
	LastSyncAt           time.Time `json:"last_sync_at,omitempty"`
	LastJobAt            time.Time `json:"last_job_at,omitempty"`
	LastJobID            string    `json:"last_job_id,omitempty"`
	LastJobState         string    `json:"last_job_state,omitempty"`
	MetadataFailures     uint32    `json:"metadata_failures,omitempty"`
	NextMetadataAttempt  time.Time `json:"next_metadata_attempt,omitempty"`
	LastMetadataUploadAt time.Time `json:"last_metadata_upload_at,omitempty"`
	// CloudCapabilities is the optional-feature list from the last successful
	// sync, kept so a restart does not forget what the cloud accepts.
	CloudCapabilities []string `json:"cloud_capabilities,omitempty"`
}

func DaemonConfigFromEnvironment(version string) (DaemonConfig, error) {
	interval := 30 * time.Second
	if value := strings.TrimSpace(os.Getenv("SHAKERPROXY_CLOUD_HEARTBEAT_SECONDS")); value != "" {
		seconds, err := strconv.Atoi(value)
		if err != nil || seconds < 10 || seconds > 300 {
			return DaemonConfig{}, errors.New("SHAKERPROXY_CLOUD_HEARTBEAT_SECONDS must be between 10 and 300")
		}
		interval = time.Duration(seconds) * time.Second
	}
	config := DaemonConfig{
		Root:              environmentOr("SHAKERPROXY_CLOUD_STATE_ROOT", "/var/lib/shakerproxy/cloud"),
		ControlSocket:     environmentOr("SHAKERPROXY_CLOUD_CONNECTOR_SOCKET", "/run/shakerproxy-cloud/connector.sock"),
		PolicySocket:      environmentOr("SHAKERPROXY_TRAFFIC_POLICY_SOCKET", DefaultPolicySocket),
		ServerCAFile:      strings.TrimSpace(os.Getenv("SHAKERPROXY_CLOUD_SERVER_CA_FILE")),
		Version:           version,
		HeartbeatInterval: interval,
	}
	if strings.TrimSpace(config.Root) == "" || !filepath.IsAbs(config.Root) || strings.TrimSpace(config.ControlSocket) == "" || !filepath.IsAbs(config.ControlSocket) || strings.TrimSpace(config.PolicySocket) == "" || !filepath.IsAbs(config.PolicySocket) {
		return DaemonConfig{}, errors.New("connector state and Unix socket paths must be absolute")
	}
	if config.ServerCAFile != "" && !filepath.IsAbs(config.ServerCAFile) {
		return DaemonConfig{}, errors.New("cloud server CA file path must be absolute")
	}
	return config, nil
}

func RunDaemon(ctx context.Context, logger *slog.Logger, config DaemonConfig) error {
	if logger == nil {
		logger = slog.Default()
	}
	if strings.TrimSpace(config.Version) == "" {
		return errors.New("connector build version is required")
	}
	httpClient, err := cloudHTTPClient(config.ServerCAFile)
	if err != nil {
		return err
	}
	client := Client{Root: config.Root, HTTPClient: httpClient}
	ledger := &ExecutionLedger{Root: config.Root}
	metadataQueue := &MetadataQueue{Root: config.Root}
	deviceRuntime := &DeviceRuntimeStore{Root: config.Root}
	protocolRollup := &ProtocolRollup{Root: config.Root}
	defer func() {
		if err := protocolRollup.Persist(); err != nil {
			logger.Warn("protocol rollup state was not saved at shutdown", "error", err)
		}
	}()
	if err := startDaemonLocalControl(ctx, config.ControlSocket, client, metadataQueue, deviceRuntime, protocolRollup, config.Version, logger); err != nil {
		return fmt.Errorf("start connector local control: %w", err)
	}
	state, err := waitForDaemonEnrollment(ctx, client, logger)
	if err != nil {
		return err
	}
	logger.Info(
		"cloud connector active",
		"sensor_id", state.SensorID,
		"cloud", state.CloudURL,
		"protocol", ProtocolVersion,
		"capabilities", daemonCapabilities(config),
	)

	ticker := time.NewTicker(config.HeartbeatInterval)
	defer ticker.Stop()
	for {
		if err := runDaemonCycle(ctx, logger, client, ledger, metadataQueue, deviceRuntime, protocolRollup, config); err != nil && ctx.Err() == nil {
			logger.Warn("cloud connector cycle failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func runDaemonCycle(ctx context.Context, logger *slog.Logger, client Client, ledger *ExecutionLedger, metadataQueue *MetadataQueue, deviceRuntime *DeviceRuntimeStore, protocolRollup *ProtocolRollup, config DaemonConfig) error {
	maintenanceCtx, cancelMaintenance := context.WithTimeout(ctx, 45*time.Second)
	renewed, renewalErr := client.EnsureCertificate(maintenanceCtx, DefaultRenewBefore)
	cancelMaintenance()
	if renewalErr != nil {
		logger.Warn("cloud certificate maintenance failed", "error", renewalErr)
	} else if renewed {
		logger.Info("cloud sensor certificate lifecycle advanced")
	}

	runtimeState, err := loadConnectorRuntimeState(config.Root)
	if err != nil {
		return err
	}
	ledgerSummary, ledgerErr := ledger.Summary()
	if ledgerErr != nil {
		return ledgerErr
	}
	metadataSummary, metadataErr := metadataQueue.Summary()
	if metadataErr != nil {
		metadataSummary = map[string]any{"available": false}
	} else {
		metadataSummary["available"] = true
	}
	heartbeatCtx, cancelHeartbeat := context.WithTimeout(ctx, 15*time.Second)
	heartbeatErr := client.SendHeartbeat(heartbeatCtx, Heartbeat{
		SoftwareVersion: config.Version,
		HealthState:     "ONLINE",
		AppliedRevision: runtimeState.AppliedRevision,
		QueueDepth:      metadataQueueDepth(metadataSummary),
		Payload: map[string]any{
			"connector_version": config.Version,
			"capabilities":      daemonCapabilities(config),
			"job_ledger":        ledgerSummary,
			"metadata_queue":    metadataSummary,
			"device_runtime":    deviceRuntimeSummary(deviceRuntime),
			"protocol_rollup":   protocolRollup.Summary(),
			"traffic_policy": map[string]any{
				"desired_revision": runtimeState.DesiredRevision,
				"applied_revision": runtimeState.AppliedRevision,
			},
		},
	})
	cancelHeartbeat()
	if heartbeatErr != nil {
		logger.Warn("cloud heartbeat failed", "error", heartbeatErr)
	}
	if err := queueDaemonProtocolSummaries(protocolRollup, metadataQueue, deviceRuntime, runtimeState.CloudCapabilities); err != nil {
		logger.Warn("protocol summaries were not queued", "error", err)
	}
	if err := flushDaemonMetadata(ctx, client, metadataQueue, &runtimeState, config.Root); err != nil {
		logger.Warn("cloud metadata upload deferred", "error", err, "retry_at", runtimeState.NextMetadataAttempt)
	}

	syncCtx, cancelSync := context.WithTimeout(ctx, 20*time.Second)
	syncResponse, syncErr := client.Sync(syncCtx, runtimeState.AppliedRevision, daemonCapabilities(config))
	cancelSync()
	if syncErr != nil {
		if heartbeatErr != nil {
			return fmt.Errorf("heartbeat: %v; sync: %w", heartbeatErr, syncErr)
		}
		return syncErr
	}
	runtimeState.DesiredRevision = syncResponse.DesiredRevision
	if containsCapability(runtimeState.CloudCapabilities, ProtocolSummaryCapability) && !containsCapability(syncResponse.Capabilities, ProtocolSummaryCapability) {
		// The cloud was downgraded. Remove queued summaries now so it never has
		// to reject them one by one through poison isolation.
		if dropped, err := metadataQueue.DropType(MetadataProtocolSummary); err != nil {
			logger.Warn("queued protocol summaries could not be removed", "error", err)
		} else if dropped != 0 {
			logger.Info("cloud no longer accepts protocol summaries; removed queued summaries", "dropped", dropped)
		}
	}
	runtimeState.CloudCapabilities = syncResponse.Capabilities
	runtimeState.LastSyncAt = time.Now().UTC()
	if err := saveConnectorRuntimeState(config.Root, runtimeState); err != nil {
		return err
	}
	for _, job := range syncResponse.Jobs {
		updated, err := executeDaemonJob(ctx, logger, client, ledger, metadataQueue, deviceRuntime, config, runtimeState, job)
		if err != nil {
			logger.Warn("cloud job processing failed", "job_id", job.ID, "job_type", job.Type, "error", err)
			continue
		}
		runtimeState = updated
	}
	return nil
}

func flushDaemonMetadata(ctx context.Context, client Client, queue *MetadataQueue, runtimeState *ConnectorRuntimeState, root string) error {
	now := time.Now().UTC()
	if runtimeState.NextMetadataAttempt.After(now) {
		return nil
	}
	uploaded := 0
	for uploaded < 4 {
		uploadCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		flushed, err := queue.FlushOne(uploadCtx, client)
		cancel()
		if err != nil {
			if runtimeState.MetadataFailures < 32 {
				runtimeState.MetadataFailures++
			}
			runtimeState.NextMetadataAttempt = now.Add(metadataRetryDelay(runtimeState.MetadataFailures))
			if saveErr := saveConnectorRuntimeState(root, *runtimeState); saveErr != nil {
				return fmt.Errorf("metadata upload: %v; persist retry: %w", err, saveErr)
			}
			return err
		}
		if !flushed {
			break
		}
		uploaded++
	}
	changed := runtimeState.MetadataFailures != 0 || !runtimeState.NextMetadataAttempt.IsZero() || uploaded != 0
	runtimeState.MetadataFailures = 0
	runtimeState.NextMetadataAttempt = time.Time{}
	if uploaded != 0 {
		runtimeState.LastMetadataUploadAt = now
	}
	if changed {
		return saveConnectorRuntimeState(root, *runtimeState)
	}
	return nil
}

// queueDaemonProtocolSummaries moves due protocol rollups into the metadata
// queue, but only while the cloud advertises ProtocolSummaryCapability. Without
// it, summaries stay in the bounded rollup and expire after its late window.
func queueDaemonProtocolSummaries(rollup *ProtocolRollup, queue *MetadataQueue, deviceRuntime *DeviceRuntimeStore, cloudCapabilities []string) error {
	if rollup == nil || queue == nil {
		return nil
	}
	if !containsCapability(cloudCapabilities, ProtocolSummaryCapability) {
		return rollup.Persist()
	}
	categories := map[string]string{}
	if deviceRuntime != nil {
		if snapshot, err := deviceRuntime.Snapshot(); err == nil {
			categories = snapshot.DeviceCategories
		}
	}
	_, err := rollup.Emit(categories, func(events []LocalMetadataEvent) error {
		_, err := queue.Enqueue(events)
		return err
	})
	return err
}

func metadataRetryDelay(failures uint32) time.Duration {
	if failures == 0 {
		return 0
	}
	exponent := failures - 1
	if exponent > 5 {
		exponent = 5
	}
	delay := 10 * time.Second * time.Duration(uint64(1)<<exponent)
	if delay > 5*time.Minute {
		return 5 * time.Minute
	}
	return delay
}

func executeDaemonJob(
	ctx context.Context,
	logger *slog.Logger,
	client Client,
	ledger *ExecutionLedger,
	metadataQueue *MetadataQueue,
	deviceRuntime *DeviceRuntimeStore,
	config DaemonConfig,
	runtimeState ConnectorRuntimeState,
	job CloudJob,
) (ConnectorRuntimeState, error) {
	state, err := client.LoadState()
	if err != nil {
		return runtimeState, err
	}
	var existing ExecutionRecord
	var foundExisting bool
	if record, found, err := ledger.Get(job.ID); err != nil {
		return runtimeState, err
	} else if found {
		existing = record
		foundExisting = true
		if existing.IdempotencyKey != job.IdempotencyKey || existing.JobType != job.Type {
			_ = client.SendJobStatus(ctx, job.ID, "REJECTED", map[string]any{"reason": "job_identity_reused"})
			return runtimeState, errors.New("cloud job ID was reused with a different identity")
		}
		if terminalExecutionState(existing.State) {
			runtimeState, err = reconcileTerminalExecution(config.Root, runtimeState, job, existing)
			if err != nil {
				return runtimeState, err
			}
			if err := client.SendJobStatus(ctx, job.ID, existing.State, existing.Result); err != nil {
				return runtimeState, fmt.Errorf("replay durable job result: %w", err)
			}
			return runtimeState, nil
		}
	}

	now := time.Now().UTC()
	capabilities := daemonCapabilities(config)
	validationErr := validateDaemonJob(job, state, runtimeState.AppliedRevision, capabilities, now)
	if validationErr != nil {
		result := map[string]any{"reason": "local_validation_rejected", "detail": validationErr.Error()}
		record := ExecutionRecord{
			JobID:          job.ID,
			IdempotencyKey: job.IdempotencyKey,
			JobType:        job.Type,
			State:          "REJECTED",
			Result:         result,
			ExpiresAt:      job.ExpiresAt,
		}
		if err := ledger.Put(record); err != nil {
			return runtimeState, err
		}
		if err := client.SendJobStatus(ctx, job.ID, "REJECTED", result); err != nil {
			return runtimeState, err
		}
		return runtimeState, nil
	}

	delivered := ExecutionRecord{
		JobID:          job.ID,
		IdempotencyKey: job.IdempotencyKey,
		JobType:        job.Type,
		State:          "DELIVERED",
		Result:         map[string]any{},
		ExpiresAt:      job.ExpiresAt,
	}
	if foundExisting {
		delivered = existing
	}
	if !foundExisting {
		if err := ledger.Put(delivered); err != nil {
			return runtimeState, err
		}
		if err := client.SendJobStatus(ctx, job.ID, "DELIVERED", nil); err != nil {
			return runtimeState, err
		}
	}

	running := delivered
	running.State = "RUNNING"
	if !foundExisting || existing.State == "DELIVERED" {
		if err := ledger.Put(running); err != nil {
			return runtimeState, err
		}
		if err := client.SendJobStatus(ctx, job.ID, "RUNNING", nil); err != nil {
			return runtimeState, err
		}
	} else if existing.State == "RUNNING" {
		running = existing
	} else {
		return runtimeState, fmt.Errorf("cannot resume cloud job from local execution state %q", existing.State)
	}

	deadline := job.ExpiresAt
	maximumDeadline := now.Add(2 * time.Minute)
	if deadline.After(maximumDeadline) {
		deadline = maximumDeadline
	}
	jobCtx, cancelJob := context.WithDeadline(ctx, deadline)
	result, executionErr := dispatchDaemonJob(jobCtx, client, deviceRuntime, config, state, runtimeState.AppliedRevision, capabilities, job)
	cancelJob()
	if executionErr == nil && (job.Type == JobCaptureStart || job.Type == JobCaptureStop) {
		if err := enqueueCaptureSummary(metadataQueue, job, result, time.Now().UTC()); err != nil {
			return runtimeState, err
		}
		result["capture_metadata_queued"] = true
	}
	terminalState := "SUCCEEDED"
	if executionErr != nil {
		terminalState = "FAILED"
		result = map[string]any{"reason": "execution_failed", "detail": boundedDaemonError(executionErr)}
	}
	terminal := running
	terminal.State = terminalState
	terminal.Result = result
	if err := ledger.Put(terminal); err != nil {
		return runtimeState, err
	}
	if terminalState == "SUCCEEDED" && (job.Type == JobPolicyApply || job.Type == JobPolicyRollback) {
		parameters, parseErr := parseTrafficPolicyParameters(job.Parameters)
		if parseErr == nil {
			runtimeState.AppliedRevision = parameters.Revision
		}
	}
	runtimeState.LastJobAt = time.Now().UTC()
	runtimeState.LastJobID = job.ID
	runtimeState.LastJobState = terminalState
	if err := saveConnectorRuntimeState(config.Root, runtimeState); err != nil {
		return runtimeState, err
	}
	if err := client.SendJobStatus(ctx, job.ID, terminalState, result); err != nil {
		return runtimeState, fmt.Errorf("report durable job result: %w", err)
	}
	logger.Info("cloud job completed", "job_id", job.ID, "job_type", job.Type, "state", terminalState)
	return runtimeState, nil
}

func reconcileTerminalExecution(root string, runtimeState ConnectorRuntimeState, job CloudJob, existing ExecutionRecord) (ConnectorRuntimeState, error) {
	changed := false
	if existing.State == "SUCCEEDED" && (job.Type == JobPolicyApply || job.Type == JobPolicyRollback) {
		parameters, err := parseTrafficPolicyParameters(job.Parameters)
		if err != nil {
			return runtimeState, fmt.Errorf("reconcile durable traffic policy result: %w", err)
		}
		if runtimeState.AppliedRevision != parameters.Revision {
			runtimeState.AppliedRevision = parameters.Revision
			changed = true
		}
	}
	if runtimeState.LastJobID != job.ID || runtimeState.LastJobState != existing.State || runtimeState.LastJobAt.Before(existing.UpdatedAt) {
		runtimeState.LastJobID = job.ID
		runtimeState.LastJobState = existing.State
		runtimeState.LastJobAt = existing.UpdatedAt
		changed = true
	}
	if changed {
		if err := saveConnectorRuntimeState(root, runtimeState); err != nil {
			return runtimeState, fmt.Errorf("persist reconciled connector runtime state: %w", err)
		}
	}
	return runtimeState, nil
}

func metadataQueueDepth(summary map[string]any) uint64 {
	if summary == nil {
		return 0
	}
	switch value := summary["event_count"].(type) {
	case int:
		if value > 0 {
			return uint64(value)
		}
	case int64:
		if value > 0 {
			return uint64(value)
		}
	case uint64:
		return value
	case float64:
		if value > 0 && value == float64(uint64(value)) {
			return uint64(value)
		}
	}
	return 0
}

func validateDaemonJob(job CloudJob, state State, appliedRevision uint64, capabilities []string, now time.Time) error {
	switch job.Type {
	case JobCaptureStart:
		_, err := ValidateCaptureStartJob(job, state, appliedRevision, capabilities, now)
		return err
	case JobCaptureStop:
		_, err := ValidateCaptureStopJob(job, state, appliedRevision, capabilities, now)
		return err
	case JobDeviceRename:
		_, err := ValidateDeviceRenameJob(job, state, appliedRevision, capabilities, now)
		return err
	case JobDiagnosticsCollect:
		return ValidateDiagnosticsJob(job, state, appliedRevision, capabilities, now)
	case JobPolicyApply, JobPolicyRollback:
		return ValidateTrafficPolicyJob(job, state, appliedRevision, capabilities, now)
	default:
		return fmt.Errorf("remote job type %q is not implemented by this sensor", job.Type)
	}
}

func dispatchDaemonJob(ctx context.Context, client Client, deviceRuntime *DeviceRuntimeStore, config DaemonConfig, state State, appliedRevision uint64, capabilities []string, job CloudJob) (map[string]any, error) {
	switch job.Type {
	case JobCaptureStart:
		parameters, err := ValidateCaptureStartJob(job, state, appliedRevision, capabilities, client.now())
		if err != nil {
			return nil, err
		}
		control := LocalCaptureControlFromEnvironment()
		control.IdempotencyKey = captureJobIdempotencyKey(job)
		return control.Start(ctx, parameters)
	case JobCaptureStop:
		parameters, err := ValidateCaptureStopJob(job, state, appliedRevision, capabilities, client.now())
		if err != nil {
			return nil, err
		}
		control := LocalCaptureControlFromEnvironment()
		control.IdempotencyKey = captureJobIdempotencyKey(job)
		return control.Stop(ctx, parameters)
	case JobDeviceRename:
		parameters, err := parseDeviceRenameParameters(job.Parameters)
		if err != nil {
			return nil, err
		}
		return ExecuteDeviceRenameJob(ctx, deviceRuntime, parameters)
	case JobDiagnosticsCollect:
		return (DiagnosticsExecutor{BuildVersion: config.Version}).Execute(ctx, client)
	case JobPolicyApply, JobPolicyRollback:
		runtime, err := TrafficPolicyRuntimeFromEnvironment()
		if err != nil {
			return nil, err
		}
		runtime = mergeTrafficPolicyDeviceRuntime(runtime, deviceRuntime)
		executor := TrafficPolicyExecutor{SocketPath: config.PolicySocket, Runtime: &runtime}
		return executor.Execute(ctx, job)
	default:
		return nil, fmt.Errorf("remote job type %q is unsupported", job.Type)
	}
}

func daemonCapabilities(config DaemonConfig) []string {
	values := []string{DeviceNamingCapability, DiagnosticsCapability, ProtocolSummaryCapability}
	if _, err := TrafficPolicyRuntimeFromEnvironment(); err == nil && TrafficPolicyControlConfigured(config.PolicySocket) {
		values = append(values, TrafficPolicyCapability, TrafficPolicyRollbackCapability)
	}
	if LocalCaptureControlConfigured() {
		values = append(values, CaptureControlCapability)
	}
	sort.Strings(values)
	return values
}

func deviceRuntimeSummary(store *DeviceRuntimeStore) map[string]any {
	if store == nil {
		return map[string]any{"available": false}
	}
	summary, err := store.Summary()
	if err != nil {
		return map[string]any{"available": false}
	}
	summary["available"] = true
	return summary
}

func startDaemonLocalControl(ctx context.Context, socket string, client Client, metadataQueue *MetadataQueue, deviceRuntime *DeviceRuntimeStore, protocolRollup *ProtocolRollup, version string, logger *slog.Logger) error {
	if err := os.MkdirAll(filepath.Dir(socket), 0o750); err != nil {
		return err
	}
	if info, err := os.Lstat(socket); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return errors.New("refusing to replace non-socket connector control path")
		}
		if err := os.Remove(socket); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	if err := os.Chmod(socket, 0o660); err != nil {
		_ = listener.Close()
		return err
	}
	server := &http.Server{
		Handler: LocalServer{
			Client:          client,
			SoftwareVersion: version,
			MetadataQueue:   metadataQueue,
			DeviceRuntime:   deviceRuntime,
			ProtocolRollup:  protocolRollup,
		}.Handler(),
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       35 * time.Second,
		WriteTimeout:      35 * time.Second,
		IdleTimeout:       15 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
		_ = listener.Close()
		_ = os.Remove(socket)
	}()
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("local cloud connector control server stopped", "error", err)
		}
	}()
	logger.Info("local cloud connector control ready", "socket", socket)
	return nil
}

func waitForDaemonEnrollment(ctx context.Context, client Client, logger *slog.Logger) (State, error) {
	loggedIdle := false
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		state, err := client.LoadState()
		if err == nil {
			return state, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return State{}, err
		}
		if !loggedIdle {
			logger.Info("cloud connector idle; use shakerproxy-cloud enroll to activate cloud connectivity")
			loggedIdle = true
		}
		select {
		case <-ctx.Done():
			return State{}, ctx.Err()
		case <-ticker.C:
		}
	}
}

func loadConnectorRuntimeState(root string) (ConnectorRuntimeState, error) {
	data, err := os.ReadFile(filepath.Join(root, connectorRuntimeStateFile))
	if errors.Is(err, os.ErrNotExist) {
		return ConnectorRuntimeState{SchemaVersion: 1}, nil
	}
	if err != nil {
		return ConnectorRuntimeState{}, err
	}
	if len(data) > 64<<10 {
		return ConnectorRuntimeState{}, errors.New("connector runtime state exceeds maximum size")
	}
	var state ConnectorRuntimeState
	if err := json.Unmarshal(data, &state); err != nil {
		return ConnectorRuntimeState{}, fmt.Errorf("decode connector runtime state: %w", err)
	}
	if state.SchemaVersion != 1 {
		return ConnectorRuntimeState{}, errors.New("unsupported connector runtime state schema")
	}
	return state, nil
}

func saveConnectorRuntimeState(root string, state ConnectorRuntimeState) error {
	state.SchemaVersion = 1
	encoded, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(root, connectorRuntimeStateFile), append(encoded, '\n'), 0o600)
}

func environmentOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func terminalExecutionState(value string) bool {
	return value == "SUCCEEDED" || value == "FAILED" || value == "REJECTED"
}

func boundedDaemonError(err error) string {
	if err == nil {
		return ""
	}
	value := err.Error()
	if len(value) > 1024 {
		value = value[:1024]
	}
	return value
}
