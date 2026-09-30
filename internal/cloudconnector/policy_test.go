package cloudconnector

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/trafficpolicy"
)

type trafficPolicyRoundTripFunc func(*http.Request) (*http.Response, error)

func (function trafficPolicyRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestValidateTrafficPolicyJobRequiresRevisionAndOperationCapability(t *testing.T) {
	now := time.Now().UTC()
	policy := validCloudEnforcementPolicy()
	job := validTrafficPolicyJob(t, JobPolicyRollback, TrafficPolicyRollbackCapability, policy, 6, 7, now)
	state := State{SensorID: job.SensorID, OrganizationID: job.OrganizationID}
	if err := ValidateTrafficPolicyJob(job, state, 6, []string{TrafficPolicyRollbackCapability}, now); err != nil {
		t.Fatalf("validate rollback job: %v", err)
	}
	job.ExpectedRevision = nil
	if err := ValidateTrafficPolicyJob(job, state, 6, []string{TrafficPolicyRollbackCapability}, now); err == nil {
		t.Fatal("expected a missing revision guard to be rejected")
	}
	job = validTrafficPolicyJob(t, JobPolicyRollback, TrafficPolicyCapability, policy, 6, 7, now)
	if err := ValidateTrafficPolicyJob(job, state, 6, []string{TrafficPolicyCapability}, now); err == nil {
		t.Fatal("expected the apply capability to be rejected for rollback")
	}
}

func TestTrafficPolicyExecutorUsesHardenedPolicyServiceContract(t *testing.T) {
	now := time.Now().UTC()
	policy := validCloudEnforcementPolicy()
	policy.EncryptedDNS.Mode = "block"
	policy.EncryptedDNS.BlockDoT = true
	job := validTrafficPolicyJob(t, JobPolicyApply, TrafficPolicyCapability, policy, 13, 14, now)
	runtime := trafficpolicy.Runtime{TestInterfaces: []string{"eth1"}, ScopeIPv4: []string{"192.0.2.0/24"}, LocalDNSPort: 53, MITMPort: 8080, TLSInterceptPorts: []int{443}}
	client, received := fakeTrafficPolicyClient(t, false, now)

	result, err := (TrafficPolicyExecutor{HTTPClient: client, Runtime: &runtime}).Execute(context.Background(), job)
	if err != nil {
		t.Fatalf("execute policy apply: %v", err)
	}
	if received.PolicyID != "policy-1" || received.Revision != 14 || received.Policy.EncryptedDNS.Mode != "block" || received.Runtime.TestInterfaces[0] != "eth1" {
		t.Fatalf("unexpected local apply request: %#v", received)
	}
	if result["revision"] != uint64(14) || result["local_revision"] != uint64(14) || result["idempotent"] != false || result["local_service"] != "shakerproxy-traffic-policy" {
		t.Fatalf("unexpected policy result: %#v", result)
	}
}

func TestTrafficPolicyRollbackAppliesTargetAsNewRevision(t *testing.T) {
	now := time.Now().UTC()
	policy := validCloudEnforcementPolicy()
	policy.Enabled = false
	job := validTrafficPolicyJob(t, JobPolicyRollback, TrafficPolicyRollbackCapability, policy, 21, 22, now)
	runtime := trafficpolicy.Runtime{TestInterfaces: []string{"eth1"}, LocalDNSPort: 53, MITMPort: 8080, TLSInterceptPorts: []int{443}}
	client, received := fakeTrafficPolicyClient(t, true, now)

	result, err := (TrafficPolicyExecutor{HTTPClient: client, Runtime: &runtime}).Execute(context.Background(), job)
	if err != nil {
		t.Fatalf("execute policy rollback: %v", err)
	}
	if received.Revision != 22 || result["operation"] != "rollback" || result["idempotent"] != true {
		t.Fatalf("rollback did not use the new target revision: request=%#v result=%#v", received, result)
	}
}

func TestTrafficPolicyControlRequiresDirectUnixSocketAndRuntime(t *testing.T) {
	directory := t.TempDir()
	socketPath := filepath.Join(directory, "policy.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	if !TrafficPolicyControlConfigured(socketPath) {
		t.Fatal("expected a direct Unix socket to be available")
	}
	linkPath := filepath.Join(directory, "policy-link.sock")
	if err := os.Symlink(socketPath, linkPath); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if TrafficPolicyControlConfigured(linkPath) {
		t.Fatal("refused policy capability must not follow a symlink")
	}
	t.Setenv("SHAKERPROXY_TEST_INTERFACES", "eth1")
	capabilities := daemonCapabilities(DaemonConfig{PolicySocket: socketPath})
	if !containsCapability(capabilities, TrafficPolicyCapability) || !containsCapability(capabilities, TrafficPolicyRollbackCapability) {
		t.Fatalf("policy capabilities are missing for a live socket and valid runtime: %v", capabilities)
	}
	t.Setenv("SHAKERPROXY_TEST_INTERFACES", "")
	capabilities = daemonCapabilities(DaemonConfig{PolicySocket: socketPath})
	if containsCapability(capabilities, TrafficPolicyCapability) {
		t.Fatalf("policy capability was advertised without a configured packet scope: %v", capabilities)
	}
}

func TestTrafficPolicyRuntimeUsesInstalledDNSListener(t *testing.T) {
	t.Setenv("SHAKERPROXY_TEST_INTERFACES", "eth1")
	runtime, err := TrafficPolicyRuntimeFromEnvironment()
	if err != nil {
		t.Fatal(err)
	}
	if runtime.LocalDNSPort != trafficpolicy.DefaultDNSListenPort {
		t.Fatalf("cloud DNS redirect targets %d, want installed listener %d", runtime.LocalDNSPort, trafficpolicy.DefaultDNSListenPort)
	}
}

func TestFleetPolicyDocumentMatchesSensorDigestContract(t *testing.T) {
	policy := trafficpolicy.EnforcementDocument{
		SchemaVersion: trafficpolicy.SchemaVersion,
		Enabled:       true,
		EncryptedDNS: trafficpolicy.EnforcementDNSPolicy{
			Mode:             "block",
			RedirectPlainDNS: true,
			BlockDoT:         true,
			BlockDoQ:         true,
			BlockKnownDoH:    true,
			FailMode:         "passthrough",
		},
		TLS:       trafficpolicy.TLSInterceptionPolicy{Mode: "all", FailMode: "passthrough", AutoBypassPinning: true, PinningThreshold: 3},
		Resolvers: []trafficpolicy.ResolverPolicyTarget{{Provider: "Example", Hostnames: []string{"dns.example.com"}, Transports: []string{"doh"}, Dedicated: true}},
	}
	digest, err := policy.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if digest != "288a25527d21b111624d3af9f14e085d861794d2f5ee892eb8d1f1f6c077084b" {
		t.Fatalf("Fleet policy contract changed: %s", digest)
	}
}

func validCloudEnforcementPolicy() trafficpolicy.EnforcementDocument {
	return trafficpolicy.EnforcementDocument{
		SchemaVersion: trafficpolicy.SchemaVersion,
		Enabled:       true,
		EncryptedDNS: trafficpolicy.EnforcementDNSPolicy{
			Mode:     "observe",
			FailMode: "passthrough",
		},
		TLS: trafficpolicy.TLSInterceptionPolicy{
			Mode:             "off",
			FailMode:         "passthrough",
			PinningThreshold: 3,
		},
	}
}

func validTrafficPolicyJob(t *testing.T, jobType, capability string, policy trafficpolicy.EnforcementDocument, expected, revision uint64, now time.Time) CloudJob {
	t.Helper()
	digest, err := policy.Digest()
	if err != nil {
		t.Fatalf("digest desired policy: %v", err)
	}
	return CloudJob{
		ID:                 "job-policy-1",
		Type:               jobType,
		OrganizationID:     "organization-1",
		SensorID:           "sensor-1",
		CreatedAt:          now.Add(-time.Minute),
		ExpiresAt:          now.Add(time.Hour),
		IdempotencyKey:     "policy-idempotency-1",
		ExpectedRevision:   &expected,
		RequiredCapability: capability,
		ApprovalState:      "APPROVED",
		Parameters: map[string]any{
			"policy_id": "policy-1",
			"revision":  revision,
			"digest":    digest,
			"policy":    policy,
		},
	}
}

func fakeTrafficPolicyClient(t *testing.T, idempotent bool, now time.Time) (*http.Client, *trafficpolicy.ApplyRequest) {
	t.Helper()
	received := &trafficpolicy.ApplyRequest{}
	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1/apply" {
			http.NotFound(response, request)
			return
		}
		decoder := json.NewDecoder(request.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(received); err != nil {
			http.Error(response, err.Error(), http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(response).Encode(trafficPolicyServiceResponse{
			Applied:    true,
			Idempotent: idempotent,
			Status: trafficpolicy.Status{
				SchemaVersion:    trafficpolicy.SchemaVersion,
				PolicyID:         received.PolicyID,
				Revision:         received.Revision,
				Digest:           received.Digest,
				Enabled:          received.Policy.Enabled,
				EncryptedDNSMode: received.Policy.EncryptedDNS.Mode,
				TLSMode:          received.Policy.TLS.Mode,
				AppliedAt:        now,
			},
		})
	})
	transport := trafficPolicyRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		result := recorder.Result()
		data, err := io.ReadAll(result.Body)
		if err != nil {
			return nil, err
		}
		result.Body.Close()
		result.Body = io.NopCloser(bytes.NewReader(data))
		return result, nil
	})
	return &http.Client{Transport: transport}, received
}
