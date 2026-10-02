package main

import (
	"bytes"
	"context"
	"crypto/subtle"
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
	"sort"
	"strings"
	"syscall"
	"time"

	"shakerproxy.dev/shakerproxy/internal/cloudconnector"
)

const (
	// maximumEventBytes matches the addon's bound; a spooled file may add one
	// trailing newline.
	maximumEventBytes     = 192 << 10
	maximumTokenBytes     = 128
	maximumAttempts       = 3
	maximumQuarantined    = 1000
	maximumTrackedFailure = 4096
)

type configuration struct {
	SpoolRoot       string
	IngestURL       string
	TokenFile       string
	ConnectorSocket string
	Interval        time.Duration
	Timeout         time.Duration
	// Source is the only event source this spool may deliver: MITMPROXY
	// (the interception addon, the default) or HOST (shakerproxy-dnsd's
	// lookups and shakerproxy-gatewayd's connection openings only).
	Source string
}

const (
	sourceMitmproxy = "MITMPROXY"
	sourceHost      = "HOST"
	hostDNSKind     = "shakerproxy.dns"
	hostConnKind    = "shakerproxy.conn"
)

func (c configuration) source() string {
	if c.Source == "" {
		return sourceMitmproxy
	}
	return c.Source
}

type forwarder struct {
	configuration   configuration
	client          *http.Client
	connectorClient *http.Client
	logger          *slog.Logger
	token           []byte
	attempts        map[string]int
	cloudFailures   int
}

// forwardError separates events that can never be delivered (malformed,
// oversized, rejected by ingestd) from outages that affect every event.
type forwardError struct {
	err       error
	permanent bool
	immediate bool
}

func (e *forwardError) Error() string { return e.err.Error() }
func (e *forwardError) Unwrap() error { return e.err }

func permanentError(immediate bool, format string, arguments ...any) error {
	return &forwardError{err: fmt.Errorf(format, arguments...), permanent: true, immediate: immediate}
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	config := configuration{
		SpoolRoot:       envOr("SHAKERPROXY_EVENT_SPOOL", envOr("SHAKERPROXY_MITM_EVENT_SPOOL", "/var/lib/shakerproxy/mitmproxy-events/pending")),
		Source:          envOr("SHAKERPROXY_EVENT_SOURCE", sourceMitmproxy),
		IngestURL:       envOr("SHAKERPROXY_INGEST_URL", "http://ingestd:8081/v1/events"),
		TokenFile:       envOr("SHAKERPROXY_INGEST_TOKEN_FILE", "/run/secrets/ingest_token"),
		ConnectorSocket: os.Getenv("SHAKERPROXY_CLOUD_CONNECTOR_SOCKET"),
		Interval:        durationEnv("SHAKERPROXY_MITM_FORWARD_INTERVAL", time.Second, 100*time.Millisecond, time.Minute),
		Timeout:         durationEnv("SHAKERPROXY_MITM_FORWARD_TIMEOUT", 10*time.Second, time.Second, time.Minute),
	}
	instance, err := newForwarder(config, logger)
	if err != nil {
		logger.Error("mitm event forwarder configuration rejected", "error", err)
		os.Exit(1)
	}
	if len(os.Args) == 2 && os.Args[1] == "healthcheck" {
		if err := instance.healthcheck(); err != nil {
			logger.Error("mitm event forwarder unhealthy", "error", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: mitm-event-forwarderd [healthcheck]")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	logger.Info("mitm event forwarder starting", "spool", config.SpoolRoot, "source", config.source(), "interval", config.Interval)
	if err := instance.run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("mitm event forwarder stopped", "error", err)
		os.Exit(1)
	}
}

func newForwarder(config configuration, logger *slog.Logger) (*forwarder, error) {
	if config.SpoolRoot == "" || !filepath.IsAbs(config.SpoolRoot) {
		return nil, errors.New("event spool root must be absolute")
	}
	if config.IngestURL == "" || !strings.HasPrefix(config.IngestURL, "http://ingestd:") {
		return nil, errors.New("ingest URL must use the internal ingestd service")
	}
	if config.ConnectorSocket != "" && !filepath.IsAbs(config.ConnectorSocket) {
		return nil, errors.New("cloud connector socket must be absolute")
	}
	if source := config.source(); source != sourceMitmproxy && source != sourceHost {
		return nil, fmt.Errorf("event source %q is not supported", source)
	}
	data, err := os.ReadFile(config.TokenFile)
	if err != nil {
		return nil, fmt.Errorf("read ingest token: %w", err)
	}
	token := bytes.TrimSpace(data)
	if len(token) < 32 || len(token) > maximumTokenBytes {
		return nil, errors.New("ingest token length is invalid")
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	instance := &forwarder{configuration: config, client: &http.Client{Timeout: config.Timeout}, logger: logger, token: append([]byte(nil), token...)}
	if config.ConnectorSocket != "" {
		instance.connectorClient = unixHTTPClient(config.ConnectorSocket, config.Timeout)
	}
	return instance, nil
}

func (f *forwarder) log() *slog.Logger {
	if f.logger == nil {
		f.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return f.logger
}

func (f *forwarder) run(ctx context.Context) error {
	ticker := time.NewTicker(f.configuration.Interval)
	defer ticker.Stop()
	for {
		if err := f.drain(ctx); err != nil && ctx.Err() == nil {
			f.log().Warn("mitm event drain paused", "error", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (f *forwarder) drain(ctx context.Context) error {
	entries, err := os.ReadDir(f.configuration.SpoolRoot)
	if err != nil {
		return err
	}
	files := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if entry.Type().IsRegular() && strings.HasPrefix(name, "evt_") && strings.HasSuffix(name, ".json") && filepath.Base(name) == name {
			files = append(files, name)
		}
	}
	// The addon names events evt_<time><sequence>_..., so name order is
	// chronological.
	sort.Strings(files)
	if len(files) > 256 {
		files = files[:256]
	}
	if f.attempts == nil {
		f.attempts = map[string]int{}
	}
	for _, name := range files {
		path := filepath.Join(f.configuration.SpoolRoot, name)
		err := f.forwardOne(ctx, path)
		if err == nil {
			delete(f.attempts, name)
			continue
		}
		var failure *forwardError
		if !errors.As(err, &failure) || !failure.permanent {
			// ingestd is unreachable or overloaded: every later event would
			// fail too, so pause until the next tick.
			return err
		}
		if len(f.attempts) >= maximumTrackedFailure {
			f.attempts = map[string]int{}
		}
		f.attempts[name]++
		if failure.immediate || f.attempts[name] >= maximumAttempts {
			delete(f.attempts, name)
			f.quarantine(path, err)
			continue
		}
		f.log().Warn("mitm event rejected; will retry", "file", name, "attempt", f.attempts[name], "error", err)
	}
	return nil
}

// quarantine moves an undeliverable event aside so it can never stall the
// spool, keeping at most maximumQuarantined files for diagnosis.
func (f *forwarder) quarantine(path string, reason error) {
	directory := filepath.Join(filepath.Dir(f.configuration.SpoolRoot), "quarantine")
	name := filepath.Base(path)
	if err := os.MkdirAll(directory, 0o700); err == nil {
		if err := os.Rename(path, filepath.Join(directory, name)); err == nil {
			f.log().Warn("mitm event quarantined", "file", name, "directory", directory, "error", reason)
			pruneQuarantine(directory)
			return
		}
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		f.log().Error("undeliverable mitm event could not be removed", "file", name, "error", err)
		return
	}
	f.log().Warn("undeliverable mitm event dropped", "file", name, "error", reason)
}

func pruneQuarantine(directory string) {
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) <= maximumQuarantined {
		return
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.Type().IsRegular() && strings.HasPrefix(entry.Name(), "evt_") {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names[:max(0, len(names)-maximumQuarantined)] {
		_ = os.Remove(filepath.Join(directory, name))
	}
}

func (f *forwarder) forwardOne(ctx context.Context, path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximumEventBytes+1 {
		return permanentError(true, "spooled event %s is not a bounded regular file", filepath.Base(path))
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	envelope, err := decodeSpooledEnvelope(data, f.configuration.source())
	if err != nil {
		return permanentError(true, "spooled event %s is invalid: %w", filepath.Base(path), err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, f.configuration.IngestURL, bytes.NewReader(data))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+string(f.token))
	response, err := f.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	switch {
	case response.StatusCode == http.StatusAccepted || response.StatusCode == http.StatusOK:
	case response.StatusCode >= 400 && response.StatusCode < 500 && response.StatusCode != http.StatusRequestTimeout && response.StatusCode != http.StatusTooManyRequests:
		return permanentError(false, "ingestd rejected %s with HTTP %d", filepath.Base(path), response.StatusCode)
	default:
		return fmt.Errorf("ingestd returned HTTP %d", response.StatusCode)
	}
	// Cloud metadata is best effort: local evidence is already stored, and a
	// connector outage must not stall the local spool.
	if f.connectorClient != nil {
		if event, ok := cloudMetadataEvent(envelope); ok {
			if err := f.enqueueCloudMetadata(ctx, event); err != nil {
				f.cloudFailures++
				if f.cloudFailures == 1 || f.cloudFailures%100 == 0 {
					f.log().Warn("cloud metadata was not queued; local event kept", "failures", f.cloudFailures, "error", err)
				}
			} else {
				f.cloudFailures = 0
			}
		}
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove acknowledged event: %w", err)
	}
	return nil
}

type eventEnvelope struct {
	Schema        int            `json:"schema"`
	EventID       string         `json:"event_id"`
	Source        string         `json:"source"`
	Kind          string         `json:"kind"`
	OccurredAt    time.Time      `json:"occurred_at"`
	SourceVersion string         `json:"source_version"`
	ParserVersion string         `json:"parser_version"`
	CaptureID     string         `json:"capture_id,omitempty"`
	DeviceID      string         `json:"device_id,omitempty"`
	FlowID        string         `json:"flow_id,omitempty"`
	Confidence    int            `json:"confidence"`
	Payload       map[string]any `json:"payload"`
}

func decodeEnvelope(data []byte) (eventEnvelope, error) {
	return decodeSpooledEnvelope(data, sourceMitmproxy)
}

// decodeSpooledEnvelope accepts only events of the spool's own source. The
// host event spool is writable by shakerproxy-dnsd and shakerproxy-gatewayd,
// so it may carry lookups and connection openings and nothing else (in
// particular no HOST detections).
func decodeSpooledEnvelope(data []byte, source string) (eventEnvelope, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var envelope eventEnvelope
	if err := decoder.Decode(&envelope); err != nil {
		return eventEnvelope{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return eventEnvelope{}, errors.New("event contains trailing data")
	}
	if source == sourceHost && envelope.Kind != hostDNSKind && envelope.Kind != hostConnKind {
		return eventEnvelope{}, errors.New("the host event spool accepts only lookup and connection events")
	}
	if envelope.Schema != 1 || !strings.HasPrefix(envelope.EventID, "evt_") || envelope.Source != source || envelope.Kind == "" || envelope.OccurredAt.IsZero() || envelope.SourceVersion == "" || envelope.ParserVersion == "" || envelope.Confidence < 0 || envelope.Confidence > 100 || envelope.Payload == nil {
		return eventEnvelope{}, errors.New("event envelope fields are invalid")
	}
	return envelope, nil
}

func validateEnvelope(data []byte) error {
	_, err := decodeEnvelope(data)
	return err
}

func (f *forwarder) enqueueCloudMetadata(ctx context.Context, event cloudconnector.LocalMetadataEvent) error {
	encoded, err := json.Marshal(map[string]any{"events": []cloudconnector.LocalMetadataEvent{event}})
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/v1/metadata/enqueue", bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := f.connectorClient.Do(request)
	if err != nil {
		return fmt.Errorf("queue cloud MITM metadata: %w", err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	if response.StatusCode != http.StatusAccepted {
		return fmt.Errorf("cloud connector metadata queue returned HTTP %d", response.StatusCode)
	}
	return nil
}

func unixHTTPClient(socketPath string, timeout time.Duration) *http.Client {
	transport := &http.Transport{
		DisableCompression: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", socketPath)
		},
	}
	return &http.Client{Transport: transport, Timeout: timeout}
}

func cloudMetadataEvent(envelope eventEnvelope) (cloudconnector.LocalMetadataEvent, bool) {
	if envelope.OccurredAt.Before(time.Now().UTC().Add(-7 * 24 * time.Hour)) {
		return cloudconnector.LocalMetadataEvent{}, false
	}
	attributes := map[string]any{"source": "mitmproxy", "event_kind": envelope.Kind, "flow_id": envelope.FlowID}
	payload := envelope.Payload
	var eventType cloudconnector.MetadataEventType
	var cloudPayload map[string]any
	switch envelope.Kind {
	case "tls_intercepted", "tls_passthrough", "tls_interception_failed":
		state := "failed"
		if envelope.Kind == "tls_intercepted" {
			state = "intercepted"
		} else if envelope.Kind == "tls_passthrough" {
			state = "bypassed"
		}
		cloudPayload = map[string]any{
			"local_device_id": envelope.DeviceID, "client_ip": stringValue(payload["source_ip"]),
			"destination_ip": stringValue(payload["destination_ip"]), "destination_port": intValue(payload["destination_port"]),
			"server_name": stringValue(payload["sni"]), "interception_state": state,
			"failure_reason": stringValue(payload["reason"]), "pinning_suspected": stringValue(payload["reason"]) == "probable_certificate_pinning_or_custom_trust_store",
			"attributes": attributes,
		}
		eventType = cloudconnector.MetadataTLSEvent
	case "encrypted_dns_detected":
		queryName := stringValue(payload["query_name"])
		if queryName == "" {
			queryName = "encrypted-query"
			attributes["query_name_available"] = false
		}
		cloudPayload = map[string]any{
			"local_device_id": envelope.DeviceID, "client_ip": stringValue(payload["source_ip"]),
			"resolver_ip": stringValue(payload["destination_ip"]), "query_name": queryName,
			"query_type": stringValue(payload["query_type"]), "transport": "doh", "encrypted": true,
			"resolver_provider": stringValue(payload["resolver_provider"]), "detection_confidence": float64(envelope.Confidence) / 100,
			"blocked": boolValue(payload["blocked"]), "policy_reason": "decrypted_doh_request", "attributes": attributes,
		}
		eventType = cloudconnector.MetadataDNSEvent
	case "http_response":
		destinationIP := stringValue(payload["destination_ip"])
		if net.ParseIP(destinationIP) == nil {
			return cloudconnector.LocalMetadataEvent{}, false
		}
		cloudPayload = map[string]any{
			"local_device_id": envelope.DeviceID, "source_ip": stringValue(payload["source_ip"]),
			"source_port": intValue(payload["source_port"]), "destination_ip": destinationIP,
			"destination_port": intValue(payload["destination_port"]), "transport": "tcp",
			"application_protocol": stringValue(payload["service"]), "bytes_sent": intValue(payload["request_bytes"]),
			"bytes_received": intValue(payload["response_bytes"]), "duration_ms": 0, "attributes": attributes,
		}
		eventType = cloudconnector.MetadataFlowSummary
	default:
		return cloudconnector.LocalMetadataEvent{}, false
	}
	encoded, err := json.Marshal(cloudPayload)
	if err != nil {
		return cloudconnector.LocalMetadataEvent{}, false
	}
	return cloudconnector.LocalMetadataEvent{EventID: envelope.EventID, Type: eventType, ObservedAt: envelope.OccurredAt.UTC(), Payload: encoded}, true
}

func stringValue(value any) string {
	result, _ := value.(string)
	return result
}

func intValue(value any) int {
	switch typed := value.(type) {
	case float64:
		return int(typed)
	case int:
		return typed
	default:
		return 0
	}
}

func boolValue(value any) bool {
	result, _ := value.(bool)
	return result
}

func (f *forwarder) healthcheck() error {
	info, err := os.Stat(f.configuration.SpoolRoot)
	if err != nil || !info.IsDir() {
		return errors.New("event spool is unavailable")
	}
	data, err := os.ReadFile(f.configuration.TokenFile)
	if err != nil {
		return err
	}
	candidate := bytes.TrimSpace(data)
	if len(candidate) != len(f.token) || subtle.ConstantTimeCompare(candidate, f.token) != 1 {
		return errors.New("ingest token changed; restart is required")
	}
	if f.configuration.ConnectorSocket != "" {
		info, err := os.Stat(f.configuration.ConnectorSocket)
		if err != nil || info.Mode()&os.ModeSocket == 0 {
			return errors.New("cloud connector socket is unavailable")
		}
	}
	return nil
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func durationEnv(name string, fallback, minimum, maximum time.Duration) time.Duration {
	value, err := time.ParseDuration(os.Getenv(name))
	if err != nil || value < minimum || value > maximum {
		return fallback
	}
	return value
}
