package cloudconnector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"shakerproxy.dev/shakerproxy/internal/trafficpolicy"
)

const (
	JobPolicyApply                  = "policy.apply"
	JobPolicyRollback               = "policy.rollback"
	TrafficPolicyCapability         = "traffic-policy.apply"
	TrafficPolicyRollbackCapability = "traffic-policy.rollback"
	DefaultPolicySocket             = "/run/shakerproxy-traffic-policy/policy.sock"
)

var trafficPolicyIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type TrafficPolicyExecutor struct {
	SocketPath string
	HTTPClient *http.Client
	Runtime    *trafficpolicy.Runtime
}

type trafficPolicyJobParameters struct {
	PolicyID string                            `json:"policy_id"`
	Revision uint64                            `json:"revision"`
	Digest   string                            `json:"digest"`
	Policy   trafficpolicy.EnforcementDocument `json:"policy"`
}

type trafficPolicyServiceResponse struct {
	Applied    bool                 `json:"applied"`
	Idempotent bool                 `json:"idempotent"`
	Status     trafficpolicy.Status `json:"status"`
}

func ValidateTrafficPolicyJob(job CloudJob, state State, appliedRevision uint64, capabilities []string, now time.Time) error {
	if strings.TrimSpace(job.ID) == "" || len(job.ID) > 64 {
		return errors.New("job ID is invalid")
	}
	if strings.TrimSpace(job.IdempotencyKey) == "" || len(job.IdempotencyKey) > 128 {
		return errors.New("job idempotency key is invalid")
	}
	if job.SensorID != state.SensorID || job.OrganizationID != state.OrganizationID {
		return errors.New("job identity does not match the enrolled sensor")
	}
	requiredCapability := TrafficPolicyCapability
	if job.Type == JobPolicyRollback {
		requiredCapability = TrafficPolicyRollbackCapability
	} else if job.Type != JobPolicyApply {
		return errors.New("job type is not a traffic policy operation")
	}
	if job.RequiredCapability != requiredCapability || !containsCapability(capabilities, requiredCapability) {
		return errors.New("sensor does not advertise the required traffic policy capability")
	}
	if job.ApprovalState != "APPROVED" {
		return errors.New("traffic policy job requires explicit cloud approval")
	}
	if job.ExpiresAt.IsZero() || !job.ExpiresAt.After(now) || job.ExpiresAt.After(now.Add(2*time.Hour)) {
		return errors.New("traffic policy job expiry is outside the accepted window")
	}
	if job.CreatedAt.IsZero() || job.CreatedAt.After(now.Add(2*time.Minute)) || job.CreatedAt.Before(now.Add(-24*time.Hour)) {
		return errors.New("traffic policy job creation time is outside the accepted window")
	}
	if job.ExpectedRevision == nil || *job.ExpectedRevision != appliedRevision {
		return errors.New("traffic policy job expected revision does not match the sensor")
	}
	_, err := parseTrafficPolicyParameters(job.Parameters)
	return err
}

func (executor TrafficPolicyExecutor) Execute(ctx context.Context, job CloudJob) (map[string]any, error) {
	parameters, err := parseTrafficPolicyParameters(job.Parameters)
	if err != nil {
		return nil, err
	}
	runtime, err := executor.runtime()
	if err != nil {
		return nil, err
	}
	request := trafficpolicy.ApplyRequest{
		PolicyID: parameters.PolicyID,
		Revision: parameters.Revision,
		Digest:   parameters.Digest,
		Policy:   parameters.Policy,
		Runtime:  runtime,
	}
	if err := request.NormalizeAndValidate(time.Now().UTC()); err != nil {
		return nil, fmt.Errorf("validate local traffic policy request: %w", err)
	}
	var response trafficPolicyServiceResponse
	if err := executor.request(ctx, http.MethodPost, "/v1/apply", request, &response); err != nil {
		return nil, err
	}
	if !response.Applied || response.Status.PolicyID != parameters.PolicyID || response.Status.Revision != parameters.Revision || response.Status.Digest != parameters.Digest {
		return nil, errors.New("local traffic policy service returned inconsistent applied state")
	}
	operation := "apply"
	if job.Type == JobPolicyRollback {
		operation = "rollback"
	}
	return map[string]any{
		"policy_id":          parameters.PolicyID,
		"revision":           parameters.Revision,
		"digest":             parameters.Digest,
		"local_revision":     response.Status.Revision,
		"local_digest":       response.Status.Digest,
		"encrypted_dns_mode": response.Status.EncryptedDNSMode,
		"tls_mode":           response.Status.TLSMode,
		"applied_at":         response.Status.AppliedAt,
		"operation":          operation,
		"idempotent":         response.Idempotent,
		"local_service":      "shakerproxy-traffic-policy",
	}, nil
}

func (executor TrafficPolicyExecutor) request(ctx context.Context, method, path string, body any, destination any) error {
	encoded, err := json.Marshal(body)
	if err != nil {
		return err
	}
	if len(encoded) > 512<<10 {
		return errors.New("local traffic policy request exceeds 512 KiB")
	}
	request, err := http.NewRequestWithContext(ctx, method, "http://unix"+path, bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	client := executor.HTTPClient
	if client == nil {
		client = unixHTTPClient(executor.socketPath(), 45*time.Second)
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("call local traffic policy service: %w", err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, (256<<10)+1))
	if err != nil {
		return err
	}
	if len(data) > 256<<10 {
		return errors.New("local traffic policy response exceeds 256 KiB")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("local traffic policy service returned HTTP %d", response.StatusCode)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode local traffic policy response: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("local traffic policy response contains trailing data")
	}
	return nil
}

func parseTrafficPolicyParameters(values map[string]any) (trafficPolicyJobParameters, error) {
	if len(values) != 4 {
		return trafficPolicyJobParameters{}, errors.New("traffic policy job parameters must contain exactly policy_id, revision, digest, and policy")
	}
	for key := range values {
		if key != "policy_id" && key != "revision" && key != "digest" && key != "policy" {
			return trafficPolicyJobParameters{}, fmt.Errorf("traffic policy job contains unsupported parameter %q", key)
		}
	}
	encoded, err := json.Marshal(values)
	if err != nil {
		return trafficPolicyJobParameters{}, err
	}
	if len(encoded) > 256<<10 {
		return trafficPolicyJobParameters{}, errors.New("traffic policy job parameters exceed maximum size")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	var parameters trafficPolicyJobParameters
	if err := decoder.Decode(&parameters); err != nil {
		return trafficPolicyJobParameters{}, fmt.Errorf("decode traffic policy job parameters: %w", err)
	}
	parameters.PolicyID = strings.TrimSpace(parameters.PolicyID)
	parameters.Digest = strings.ToLower(strings.TrimSpace(parameters.Digest))
	if !trafficPolicyIDPattern.MatchString(parameters.PolicyID) || parameters.Revision == 0 {
		return trafficPolicyJobParameters{}, errors.New("traffic policy job identity is incomplete")
	}
	if err := parameters.Policy.NormalizeAndValidate(time.Now().UTC()); err != nil {
		return trafficPolicyJobParameters{}, fmt.Errorf("validate traffic policy locally: %w", err)
	}
	calculated, err := parameters.Policy.Digest()
	if err != nil || calculated != parameters.Digest {
		return trafficPolicyJobParameters{}, errors.New("traffic policy digest does not match the normalized policy")
	}
	return parameters, nil
}

func TrafficPolicyRuntimeFromEnvironment() (trafficpolicy.Runtime, error) {
	runtime := trafficpolicy.Runtime{
		TestInterfaces:    splitPolicyCSV(os.Getenv("SHAKERPROXY_TEST_INTERFACES")),
		ScopeIPv4:         splitPolicyCSV(os.Getenv("SHAKERPROXY_TRAFFIC_SCOPE_IPV4")),
		ScopeIPv6:         splitPolicyCSV(os.Getenv("SHAKERPROXY_TRAFFIC_SCOPE_IPV6")),
		TLSInterceptPorts: []int{443},
	}
	var err error
	runtime.LocalDNSPort, err = policyPortFromEnvironment("SHAKERPROXY_LOCAL_DNS_PORT", trafficpolicy.DefaultDNSListenPort)
	if err != nil {
		return trafficpolicy.Runtime{}, err
	}
	runtime.MITMPort, err = policyPortFromEnvironment("SHAKERPROXY_MITM_PORT", 8085)
	if err != nil {
		return trafficpolicy.Runtime{}, err
	}
	if raw := strings.TrimSpace(os.Getenv("SHAKERPROXY_TLS_INTERCEPT_PORTS")); raw != "" {
		runtime.TLSInterceptPorts = nil
		for _, value := range splitPolicyCSV(raw) {
			port, parseErr := strconv.Atoi(value)
			if parseErr != nil || port < 1 || port > 65535 {
				return trafficpolicy.Runtime{}, fmt.Errorf("SHAKERPROXY_TLS_INTERCEPT_PORTS contains invalid port %q", value)
			}
			runtime.TLSInterceptPorts = append(runtime.TLSInterceptPorts, port)
		}
	}
	if len(runtime.TestInterfaces) == 0 {
		return trafficpolicy.Runtime{}, errors.New("SHAKERPROXY_TEST_INTERFACES is required for cloud traffic policy execution")
	}
	return runtime, nil
}

func (executor TrafficPolicyExecutor) runtime() (trafficpolicy.Runtime, error) {
	if executor.Runtime != nil {
		return *executor.Runtime, nil
	}
	return TrafficPolicyRuntimeFromEnvironment()
}

func policyPortFromEnvironment(name string, fallback int) (int, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 1 || value > 65535 {
		return 0, fmt.Errorf("%s must be a valid port", name)
	}
	return value, nil
}

func splitPolicyCSV(value string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0)
	for _, raw := range strings.Split(value, ",") {
		item := strings.TrimSpace(raw)
		if item == "" {
			continue
		}
		if _, exists := seen[item]; exists {
			continue
		}
		seen[item] = struct{}{}
		result = append(result, item)
	}
	return result
}

func TrafficPolicyControlConfigured(socketPath string) bool {
	socketPath = strings.TrimSpace(socketPath)
	if socketPath == "" || !filepath.IsAbs(socketPath) {
		return false
	}
	info, err := os.Lstat(socketPath)
	return err == nil && info.Mode()&os.ModeSocket != 0
}

func unixHTTPClient(socketPath string, timeout time.Duration) *http.Client {
	transport := &http.Transport{
		DisableCompression: true,
		MaxIdleConns:       4,
		IdleConnTimeout:    30 * time.Second,
		Proxy:              nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", socketPath)
		},
	}
	return &http.Client{Transport: transport, Timeout: timeout}
}

func (executor TrafficPolicyExecutor) socketPath() string {
	if value := strings.TrimSpace(executor.SocketPath); value != "" {
		return value
	}
	return DefaultPolicySocket
}
