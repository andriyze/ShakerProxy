package cloudconnector

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"shakerproxy.dev/shakerproxy/internal/capture"
)

const (
	JobCaptureStart          = "capture.start"
	JobCaptureStop           = "capture.stop"
	CaptureControlCapability = "capture.control"
	DefaultLocalControlCA    = "/var/lib/shakerproxy/public/management-ca.crt"
	DefaultLocalControlToken = "/var/lib/shakerproxy/cloud/control-api.token"
)

type CaptureStartParameters struct {
	Name            string   `json:"name"`
	DeviceIDs       []string `json:"device_ids"`
	DurationSeconds int      `json:"duration_seconds"`
	MetadataOnly    bool     `json:"metadata_only"`
}

type CaptureStopParameters struct {
	CaptureID string `json:"capture_id"`
}

type LocalCaptureControl struct {
	BaseURL        string
	TokenFile      string
	CAFile         string
	StartPath      string
	StopPath       string
	HTTPClient     *http.Client
	IdempotencyKey string
}

var localCaptureIDPattern = regexp.MustCompile(`^capture-[a-f0-9]{32}$`)

func ValidateCaptureStartJob(job CloudJob, state State, appliedRevision uint64, capabilities []string, now time.Time) (CaptureStartParameters, error) {
	if err := validateCaptureJobEnvelope(job, state, appliedRevision, capabilities, now, JobCaptureStart); err != nil {
		return CaptureStartParameters{}, err
	}
	allowed := map[string]struct{}{"name": {}, "device_ids": {}, "duration_seconds": {}, "metadata_only": {}}
	if err := exactParameterKeys(job.Parameters, allowed); err != nil {
		return CaptureStartParameters{}, err
	}
	name, ok := job.Parameters["name"].(string)
	if !ok {
		return CaptureStartParameters{}, errors.New("capture start name is missing")
	}
	parameters := CaptureStartParameters{Name: strings.TrimSpace(name)}
	if parameters.Name == "" || len(parameters.Name) > 96 {
		return CaptureStartParameters{}, errors.New("capture start name is invalid")
	}
	if value, ok := job.Parameters["metadata_only"]; ok {
		metadataOnly, valid := value.(bool)
		if !valid {
			return CaptureStartParameters{}, errors.New("capture metadata_only must be boolean")
		}
		parameters.MetadataOnly = metadataOnly
	}
	if value, ok := numericParameter(job.Parameters["duration_seconds"]); ok {
		parameters.DurationSeconds = value
	} else if _, present := job.Parameters["duration_seconds"]; present {
		return CaptureStartParameters{}, errors.New("capture duration_seconds is invalid")
	}
	if parameters.DurationSeconds < 0 || (parameters.DurationSeconds > 0 && parameters.DurationSeconds < 10) || parameters.DurationSeconds > 86400 {
		return CaptureStartParameters{}, errors.New("capture duration must be zero or between 10 and 86400 seconds")
	}
	if value, ok := job.Parameters["device_ids"]; ok {
		encoded, err := json.Marshal(value)
		if err != nil {
			return CaptureStartParameters{}, err
		}
		if err := json.Unmarshal(encoded, &parameters.DeviceIDs); err != nil {
			return CaptureStartParameters{}, errors.New("capture device_ids must be a string array")
		}
	}
	if len(parameters.DeviceIDs) != 0 {
		return CaptureStartParameters{}, errors.New("device-scoped capture is not supported by the local capture API")
	}
	return parameters, nil
}

func ValidateCaptureStopJob(job CloudJob, state State, appliedRevision uint64, capabilities []string, now time.Time) (CaptureStopParameters, error) {
	if err := validateCaptureJobEnvelope(job, state, appliedRevision, capabilities, now, JobCaptureStop); err != nil {
		return CaptureStopParameters{}, err
	}
	if err := exactParameterKeys(job.Parameters, map[string]struct{}{"capture_id": {}}); err != nil {
		return CaptureStopParameters{}, err
	}
	captureID, ok := job.Parameters["capture_id"].(string)
	if !ok {
		return CaptureStopParameters{}, errors.New("capture stop capture_id is missing")
	}
	captureID = strings.TrimSpace(captureID)
	if !localCaptureIDPattern.MatchString(captureID) {
		return CaptureStopParameters{}, errors.New("capture stop capture_id is invalid")
	}
	return CaptureStopParameters{CaptureID: captureID}, nil
}

func (control LocalCaptureControl) Start(ctx context.Context, parameters CaptureStartParameters) (map[string]any, error) {
	fields := localCaptureStartFields()
	body := make(map[string]any, len(fields))
	for _, field := range fields {
		switch field {
		case "name":
			body[field] = parameters.Name
		case "mode":
			if parameters.MetadataOnly {
				body[field] = "HEADERS_ONLY"
			} else {
				body[field] = "FULL_PACKETS"
			}
		case "segment_size_mib":
			body[field] = 32
		case "segment_seconds":
			body[field] = 300
		case "max_files":
			body[field] = 8
		case "stop_after_seconds":
			if parameters.DurationSeconds == 0 {
				body[field] = 3600
			} else {
				body[field] = parameters.DurationSeconds
			}
		case "retention_lock":
			body[field] = false
		case "start_reason":
			body[field] = "cloud-request"
		}
	}
	if len(body) == 0 {
		return nil, errors.New("local capture start schema is unavailable")
	}
	return control.request(ctx, http.MethodPost, control.startPath(), body)
}

func (control LocalCaptureControl) Stop(ctx context.Context, parameters CaptureStopParameters) (map[string]any, error) {
	path := strings.ReplaceAll(control.stopPath(), "{captureID}", url.PathEscape(parameters.CaptureID))
	path = strings.ReplaceAll(path, "{capture_id}", url.PathEscape(parameters.CaptureID))
	if strings.Contains(path, "{") || strings.Contains(path, "}") {
		return nil, errors.New("local capture stop path template is invalid")
	}
	return control.request(ctx, http.MethodPost, path, map[string]any{})
}

func (control LocalCaptureControl) request(ctx context.Context, method, path string, body any) (map[string]any, error) {
	baseURL, err := normalizeLocalControlURL(control.BaseURL)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(path, "/api/v1/") || strings.ContainsAny(path, "\r\n?#") {
		return nil, errors.New("local control API path is invalid")
	}
	tokenFile := control.TokenFile
	if tokenFile == "" {
		tokenFile = DefaultLocalControlToken
	}
	token, err := readLocalControlToken(tokenFile)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	if len(encoded) > 64<<10 {
		return nil, errors.New("local capture control request exceeds 64 KiB")
	}
	request, err := http.NewRequestWithContext(ctx, method, baseURL+path, bytes.NewReader(encoded))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+token)
	idempotencyKey := strings.TrimSpace(control.IdempotencyKey)
	if idempotencyKey == "" {
		idempotencyKey = "cloud-connector-" + strconv.FormatInt(time.Now().UTC().UnixNano(), 36)
	}
	request.Header.Set("Idempotency-Key", idempotencyKey)

	client := control.HTTPClient
	if client == nil {
		client, err = control.secureHTTPClient()
		if err != nil {
			return nil, err
		}
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("call local capture control API: %w", err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 256<<10))
	if err != nil {
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("local capture control API returned HTTP %d", response.StatusCode)
	}
	result := map[string]any{"accepted": true}
	if len(bytes.TrimSpace(data)) != 0 {
		if err := json.Unmarshal(data, &result); err != nil {
			return nil, errors.New("local capture control response is not valid JSON")
		}
	}
	return result, nil
}

func captureJobIdempotencyKey(job CloudJob) string {
	digest := sha256.Sum256([]byte(job.ID + "\x00" + job.IdempotencyKey + "\x00" + job.Type))
	return "cloud-job-" + hex.EncodeToString(digest[:16])
}

type captureMetadataPayload struct {
	LocalCaptureID string     `json:"local_capture_id"`
	Name           string     `json:"name,omitempty"`
	State          string     `json:"state"`
	StartedAt      *time.Time `json:"started_at,omitempty"`
	StoppedAt      *time.Time `json:"stopped_at,omitempty"`
	PacketCount    uint64     `json:"packet_count"`
	ByteCount      uint64     `json:"byte_count"`
	LocalOnly      bool       `json:"local_only"`
}

func enqueueCaptureSummary(queue *MetadataQueue, job CloudJob, result map[string]any, observedAt time.Time) error {
	if queue == nil {
		return errors.New("capture metadata queue is unavailable")
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("encode local capture result: %w", err)
	}
	var view capture.View
	if err := json.Unmarshal(encoded, &view); err != nil {
		return fmt.Errorf("decode local capture result: %w", err)
	}
	if !capture.ValidSessionID(view.Session.ID) {
		return errors.New("local capture result has an invalid capture ID")
	}
	payload := captureMetadataPayload{
		LocalCaptureID: view.Session.ID,
		Name:           view.Session.Request.Name,
		State:          cloudCaptureState(view.State),
		PacketCount:    capturePacketCount(view),
		ByteCount:      captureByteCount(view),
		LocalOnly:      true,
	}
	if !view.Session.StartedAt.IsZero() {
		startedAt := view.Session.StartedAt.UTC()
		payload.StartedAt = &startedAt
	}
	if view.Worker != nil && !view.Worker.EndedAt.IsZero() {
		stoppedAt := view.Worker.EndedAt.UTC()
		payload.StoppedAt = &stoppedAt
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode capture metadata: %w", err)
	}
	digest := sha256.Sum256([]byte(job.ID + "\x00" + job.IdempotencyKey + "\x00" + job.Type + "\x00" + view.Session.ID))
	_, err = queue.Enqueue([]LocalMetadataEvent{{
		EventID:    "capture-summary-" + hex.EncodeToString(digest[:16]),
		Type:       MetadataCaptureSummary,
		ObservedAt: observedAt.UTC(),
		Payload:    payloadJSON,
	}})
	if err != nil {
		return fmt.Errorf("enqueue capture metadata: %w", err)
	}
	return nil
}

func cloudCaptureState(state capture.State) string {
	switch state {
	case capture.StateStarting:
		return "pending"
	case capture.StateRunning:
		return "running"
	case capture.StateStopped, capture.StateCompleted:
		return "completed"
	case capture.StateFailed, capture.StateStoragePressure:
		return "failed"
	default:
		return "unknown"
	}
}

func capturePacketCount(view capture.View) uint64 {
	if view.Manifest != nil {
		return view.Manifest.PacketsCaptured
	}
	if view.Worker != nil {
		return view.Worker.PacketsCaptured
	}
	return 0
}

func captureByteCount(view capture.View) uint64 {
	if view.Manifest != nil && view.Manifest.TotalSizeBytes > 0 {
		return uint64(view.Manifest.TotalSizeBytes)
	}
	if view.CurrentBytes > 0 {
		return uint64(view.CurrentBytes)
	}
	return 0
}

func (control LocalCaptureControl) secureHTTPClient() (*http.Client, error) {
	caFile := control.CAFile
	if caFile == "" {
		caFile = DefaultLocalControlCA
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read local management CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("local management CA is invalid")
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          4,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			RootCAs:    pool,
		},
	}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("local control API redirects are not permitted")
		},
	}, nil
}

func validateCaptureJobEnvelope(job CloudJob, state State, appliedRevision uint64, capabilities []string, now time.Time, expectedType string) error {
	if strings.TrimSpace(job.ID) == "" || len(job.ID) > 64 || strings.TrimSpace(job.IdempotencyKey) == "" || len(job.IdempotencyKey) > 128 {
		return errors.New("capture job identity is invalid")
	}
	if job.SensorID != state.SensorID || job.OrganizationID != state.OrganizationID || job.Type != expectedType {
		return errors.New("capture job identity or type is invalid")
	}
	if job.RequiredCapability != CaptureControlCapability || !containsCapability(capabilities, CaptureControlCapability) {
		return errors.New("capture control capability is not available")
	}
	if job.ApprovalState != "NOT_REQUIRED" && job.ApprovalState != "APPROVED" {
		return errors.New("capture job is not approved")
	}
	if job.ExpiresAt.IsZero() || !job.ExpiresAt.After(now) || job.ExpiresAt.After(now.Add(2*time.Hour)) {
		return errors.New("capture job expiry is outside the accepted window")
	}
	if job.CreatedAt.IsZero() || job.CreatedAt.After(now.Add(2*time.Minute)) || job.CreatedAt.Before(now.Add(-24*time.Hour)) {
		return errors.New("capture job creation time is outside the accepted window")
	}
	if job.ExpectedRevision != nil && *job.ExpectedRevision != appliedRevision {
		return errors.New("capture job expected revision does not match")
	}
	return nil
}

func exactParameterKeys(parameters map[string]any, allowed map[string]struct{}) error {
	for key := range parameters {
		if _, ok := allowed[key]; !ok {
			return fmt.Errorf("unsupported job parameter %q", key)
		}
	}
	return nil
}

func numericParameter(value any) (int, bool) {
	switch typed := value.(type) {
	case float64:
		if typed < 0 || typed != float64(int(typed)) {
			return 0, false
		}
		return int(typed), true
	case int:
		return typed, true
	case json.Number:
		parsed, err := strconv.Atoi(typed.String())
		return parsed, err == nil
	default:
		return 0, false
	}
}

func normalizeJobIDs(values []string, maximumLength, maximumCount int) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" || len(value) > maximumLength {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
		if len(result) == maximumCount {
			break
		}
	}
	return result
}

func normalizeLocalControlURL(value string) (string, error) {
	value = strings.TrimRight(strings.TrimSpace(value), "/")
	if value == "" {
		return "", errors.New("SHAKERPROXY_LOCAL_CONTROL_URL is not configured")
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" {
		return "", errors.New("local control URL must be a root HTTPS URL")
	}
	hostname := strings.ToLower(parsed.Hostname())
	ip := net.ParseIP(hostname)
	if hostname != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return "", errors.New("local control URL must resolve through an explicit loopback hostname or address")
	}
	return value, nil
}

func readLocalControlToken(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", errors.New("local control token path must be absolute")
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("read local control token metadata: %w", err)
	}
	if info.Mode().Perm()&0o007 != 0 || info.Size() > 4096 {
		return "", errors.New("local control token file permissions or size are unsafe")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(data))
	if len(token) < 32 || len(token) > 512 || strings.ContainsAny(token, "\r\n \t") {
		return "", errors.New("local control token is invalid")
	}
	return token, nil
}

func (control LocalCaptureControl) startPath() string {
	if strings.TrimSpace(control.StartPath) != "" {
		return control.StartPath
	}
	return DefaultLocalCaptureStartPath
}

func (control LocalCaptureControl) stopPath() string {
	if strings.TrimSpace(control.StopPath) != "" {
		return control.StopPath
	}
	return DefaultLocalCaptureStopPath
}
