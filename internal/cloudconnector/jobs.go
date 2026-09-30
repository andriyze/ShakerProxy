package cloudconnector

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	JobDiagnosticsCollect = "diagnostics.collect"
	DiagnosticsCapability = "diagnostics.read"
)

type CloudJob struct {
	ID                 string         `json:"job_id"`
	Type               string         `json:"job_type"`
	OrganizationID     string         `json:"organization_id"`
	SensorID           string         `json:"sensor_id"`
	RequestedBy        string         `json:"requested_by"`
	CreatedAt          time.Time      `json:"created_at"`
	ExpiresAt          time.Time      `json:"expires_at"`
	IdempotencyKey     string         `json:"idempotency_key"`
	ExpectedRevision   *uint64        `json:"expected_revision,omitempty"`
	RequiredCapability string         `json:"required_capability,omitempty"`
	ApprovalState      string         `json:"approval_state"`
	Parameters         map[string]any `json:"parameters"`
}

type SyncRequest struct {
	ProtocolVersion string   `json:"protocol_version"`
	SensorID        string   `json:"sensor_id"`
	OrganizationID  string   `json:"organization_id"`
	AppliedRevision uint64   `json:"applied_revision"`
	Capabilities    []string `json:"capabilities"`
}

type SyncResponse struct {
	ProtocolVersion string     `json:"protocol_version"`
	DesiredRevision uint64     `json:"desired_revision"`
	Jobs            []CloudJob `json:"jobs"`
	// Capabilities lists optional features the cloud accepts, such as
	// ProtocolSummaryCapability. Older clouds omit it.
	Capabilities []string `json:"capabilities,omitempty"`
}

type JobStatusRequest struct {
	ProtocolVersion string         `json:"protocol_version"`
	SensorID        string         `json:"sensor_id"`
	OrganizationID  string         `json:"organization_id"`
	JobID           string         `json:"job_id"`
	State           string         `json:"state"`
	ObservedAt      time.Time      `json:"observed_at"`
	Result          map[string]any `json:"result,omitempty"`
}

type JobStatusResponse struct {
	Accepted        bool   `json:"accepted"`
	ProtocolVersion string `json:"protocol_version"`
}

type DiagnosticsExecutor struct {
	BuildVersion string
}

func (c Client) Sync(ctx context.Context, appliedRevision uint64, capabilities []string) (SyncResponse, error) {
	state, err := c.LoadState()
	if err != nil {
		return SyncResponse{}, err
	}
	identity, leaf, err := c.loadCurrentIdentity()
	if err != nil {
		return SyncResponse{}, err
	}
	if !leaf.NotAfter.After(c.now()) {
		return SyncResponse{}, errors.New("sensor certificate has expired")
	}
	client, err := c.clientWithIdentity(identity)
	if err != nil {
		return SyncResponse{}, err
	}
	request := SyncRequest{
		ProtocolVersion: ProtocolVersion,
		SensorID:        state.SensorID,
		OrganizationID:  state.OrganizationID,
		AppliedRevision: appliedRevision,
		Capabilities:    append([]string(nil), capabilities...),
	}
	var response SyncResponse
	if err := c.doJSONWithClient(ctx, client, http.MethodPost, state.CloudURL+"/connector/v1/sync", request, &response, nil); err != nil {
		return SyncResponse{}, err
	}
	if response.ProtocolVersion != ProtocolVersion {
		return SyncResponse{}, fmt.Errorf("cloud sync returned unsupported protocol version %q", response.ProtocolVersion)
	}
	if len(response.Jobs) > 8 {
		return SyncResponse{}, errors.New("cloud sync returned too many jobs")
	}
	response.Capabilities = normalizeCloudCapabilities(response.Capabilities)
	return response, nil
}

func (c Client) SendJobStatus(ctx context.Context, jobID, status string, result map[string]any) error {
	state, err := c.LoadState()
	if err != nil {
		return err
	}
	identity, leaf, err := c.loadCurrentIdentity()
	if err != nil {
		return err
	}
	if !leaf.NotAfter.After(c.now()) {
		return errors.New("sensor certificate has expired")
	}
	client, err := c.clientWithIdentity(identity)
	if err != nil {
		return err
	}
	request := JobStatusRequest{
		ProtocolVersion: ProtocolVersion,
		SensorID:        state.SensorID,
		OrganizationID:  state.OrganizationID,
		JobID:           jobID,
		State:           status,
		ObservedAt:      c.now(),
		Result:          result,
	}
	var response JobStatusResponse
	if err := c.doJSONWithClient(ctx, client, http.MethodPost, state.CloudURL+"/connector/v1/jobs/status", request, &response, nil); err != nil {
		return err
	}
	if !response.Accepted || response.ProtocolVersion != ProtocolVersion {
		return errors.New("cloud did not accept job status")
	}
	return nil
}

func ValidateDiagnosticsJob(job CloudJob, state State, appliedRevision uint64, capabilities []string, now time.Time) error {
	if strings.TrimSpace(job.ID) == "" || len(job.ID) > 64 {
		return errors.New("job ID is invalid")
	}
	if strings.TrimSpace(job.IdempotencyKey) == "" || len(job.IdempotencyKey) > 128 {
		return errors.New("job idempotency key is invalid")
	}
	if job.SensorID != state.SensorID || job.OrganizationID != state.OrganizationID {
		return errors.New("job identity does not match the enrolled sensor")
	}
	if job.Type != JobDiagnosticsCollect {
		return errors.New("job type is not supported by this sensor connector")
	}
	if job.RequiredCapability != DiagnosticsCapability {
		return errors.New("diagnostics job requires an unexpected capability")
	}
	if !containsCapability(capabilities, job.RequiredCapability) {
		return errors.New("sensor does not advertise the required capability")
	}
	if job.ApprovalState != "NOT_REQUIRED" && job.ApprovalState != "APPROVED" {
		return errors.New("job has not been approved for execution")
	}
	if job.ExpiresAt.IsZero() || !job.ExpiresAt.After(now) || job.ExpiresAt.After(now.Add(2*time.Hour)) {
		return errors.New("job expiry is outside the accepted window")
	}
	if job.CreatedAt.IsZero() || job.CreatedAt.After(now.Add(2*time.Minute)) || job.CreatedAt.Before(now.Add(-24*time.Hour)) {
		return errors.New("job creation time is outside the accepted window")
	}
	if job.ExpectedRevision != nil && *job.ExpectedRevision != appliedRevision {
		return errors.New("job expected revision does not match the sensor revision")
	}
	if len(job.Parameters) != 0 {
		return errors.New("diagnostics job does not accept remote parameters")
	}
	return nil
}

func (e DiagnosticsExecutor) Execute(ctx context.Context, client Client) (map[string]any, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	state, err := client.LoadState()
	if err != nil {
		return nil, err
	}
	_, leaf, err := client.loadCurrentIdentity()
	if err != nil {
		return nil, err
	}
	hostname, err := osHostname()
	if err != nil {
		hostname = ""
	}
	return map[string]any{
		"connector_version":      e.BuildVersion,
		"protocol_version":       ProtocolVersion,
		"go_version":             runtime.Version(),
		"goos":                   runtime.GOOS,
		"goarch":                 runtime.GOARCH,
		"hostname":               hostname,
		"sensor_id":              state.SensorID,
		"certificate_expires_at": leaf.NotAfter.UTC(),
		"observed_at":            client.now(),
	}, nil
}

// normalizeCloudCapabilities keeps a bounded, sorted, de-duplicated set of
// well-formed capability names; anything else in the cloud's list is ignored.
func normalizeCloudCapabilities(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" || len(value) > 96 || !metadataEventIDPattern.MatchString(value) {
			continue
		}
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
		if len(result) == 64 {
			break
		}
	}
	sort.Strings(result)
	return result
}

func containsCapability(capabilities []string, required string) bool {
	for _, value := range capabilities {
		if value == required {
			return true
		}
	}
	return false
}

var osHostname = os.Hostname
