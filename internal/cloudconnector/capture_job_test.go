package cloudconnector

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCaptureStartJobRejectsUnknownParameters(t *testing.T) {
	now := time.Now().UTC()
	job := CloudJob{
		ID:                 "job-1",
		Type:               JobCaptureStart,
		OrganizationID:     "org-1",
		SensorID:           "sensor-1",
		CreatedAt:          now,
		ExpiresAt:          now.Add(10 * time.Minute),
		IdempotencyKey:     "capture-start-1",
		RequiredCapability: CaptureControlCapability,
		ApprovalState:      "APPROVED",
		Parameters: map[string]any{
			"name":             "TV firmware 4.13",
			"device_ids":       []any{"device-1"},
			"duration_seconds": float64(120),
			"metadata_only":    false,
			"shell":            "id",
		},
	}
	if _, err := ValidateCaptureStartJob(job, State{SensorID: "sensor-1", OrganizationID: "org-1"}, 0, []string{CaptureControlCapability}, now); err == nil {
		t.Fatal("unknown capture parameter was accepted")
	}
}

func TestLocalCaptureControlUsesFixedLoopbackAPI(t *testing.T) {
	var received map[string]any
	var receivedIdempotency string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != DefaultLocalCaptureStartPath || r.Method != http.MethodPost {
			http.Error(w, "unexpected route", http.StatusNotFound)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+testLocalControlToken() {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		receivedIdempotency = r.Header.Get("Idempotency-Key")
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"capture_id": "capture-1", "state": "running"})
	}))
	defer server.Close()

	root := t.TempDir()
	tokenPath := filepath.Join(root, "control.token")
	if err := os.WriteFile(tokenPath, []byte(testLocalControlToken()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	control := LocalCaptureControl{BaseURL: server.URL, TokenFile: tokenPath, HTTPClient: server.Client(), IdempotencyKey: "cloud-job-stable-capture-key"}
	result, err := control.Start(t.Context(), CaptureStartParameters{Name: "TV firmware 4.13", DeviceIDs: []string{"device-1"}, DurationSeconds: 120})
	if err != nil {
		t.Fatal(err)
	}
	if result["capture_id"] != "capture-1" || received["name"] != "TV firmware 4.13" || received["mode"] != "FULL_PACKETS" || received["stop_after_seconds"] != float64(120) || receivedIdempotency != "cloud-job-stable-capture-key" {
		t.Fatalf("unexpected local capture result/body: result=%#v body=%#v", result, received)
	}
}

func TestCaptureJobsRejectUnsupportedScopeAndInvalidStopID(t *testing.T) {
	now := time.Now().UTC()
	state := State{SensorID: "sensor-1", OrganizationID: "org-1"}
	start := CloudJob{
		ID: "job-1", Type: JobCaptureStart, OrganizationID: state.OrganizationID, SensorID: state.SensorID,
		CreatedAt: now, ExpiresAt: now.Add(time.Hour), IdempotencyKey: "capture-start-1",
		RequiredCapability: CaptureControlCapability, ApprovalState: "APPROVED",
		Parameters: map[string]any{"name": "scoped", "device_ids": []any{"device-1"}},
	}
	if _, err := ValidateCaptureStartJob(start, state, 0, []string{CaptureControlCapability}, now); err == nil {
		t.Fatal("device-scoped capture was accepted without a local filter boundary")
	}
	stop := start
	stop.Type = JobCaptureStop
	stop.Parameters = map[string]any{"capture_id": "../../etc/passwd"}
	if _, err := ValidateCaptureStopJob(stop, state, 0, []string{CaptureControlCapability}, now); err == nil {
		t.Fatal("invalid local capture ID was accepted")
	}
}

func TestCaptureCapabilityRequiresLoopbackTokenAndCA(t *testing.T) {
	server := httptest.NewTLSServer(http.NotFoundHandler())
	defer server.Close()
	root := t.TempDir()
	tokenPath := filepath.Join(root, "control.token")
	caPath := filepath.Join(root, "management-ca.crt")
	if err := os.WriteFile(tokenPath, []byte(testLocalControlToken()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	certificate := server.Certificate()
	if certificate == nil {
		t.Fatal("test server certificate is unavailable")
	}
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SHAKERPROXY_LOCAL_CONTROL_URL", server.URL)
	t.Setenv("SHAKERPROXY_LOCAL_CONTROL_TOKEN_FILE", tokenPath)
	t.Setenv("SHAKERPROXY_LOCAL_CONTROL_CA_FILE", caPath)
	if !LocalCaptureControlConfigured() {
		t.Fatal("complete local capture authorization was not detected")
	}
	if !containsCapability(daemonCapabilities(DaemonConfig{}), CaptureControlCapability) {
		t.Fatal("authorized daemon did not advertise capture control")
	}
	t.Setenv("SHAKERPROXY_LOCAL_CONTROL_CA_FILE", filepath.Join(root, "missing-ca.crt"))
	if LocalCaptureControlConfigured() {
		t.Fatal("capture control was advertised without its management CA")
	}
}

func TestLocalControlURLRejectsNonLoopback(t *testing.T) {
	if _, err := normalizeLocalControlURL("https://192.0.2.5:8443"); err == nil {
		t.Fatal("non-loopback local control URL was accepted")
	}
	if value, err := normalizeLocalControlURL("https://127.0.0.1:8443"); err != nil || value != "https://127.0.0.1:8443" {
		t.Fatalf("loopback URL was rejected: %q %v", value, err)
	}
}

func testLocalControlToken() string {
	return "lga_01234567890123456789012345678901234567890123"
}
