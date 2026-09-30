package analyzer

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAnalyzerHealthDistinguishesFreshScanningAndStale(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	store := NewStateStore(filepath.Join(t.TempDir(), "state"))
	if err := store.Prepare(); err != nil {
		t.Fatal(err)
	}
	status := Status{Schema: SchemaVersion, Engine: EngineZeek, SourceVersion: "8.2.1", StartedAt: now.Add(-time.Hour), UpdatedAt: now, LastScanAt: now.Add(-time.Minute), LastSuccessAt: now.Add(-time.Minute)}
	if err := store.WriteStatus(status); err != nil {
		t.Fatal(err)
	}
	health, err := store.Health(now)
	if err != nil || health.Validate() != nil || !health.Healthy || health.State != HealthHealthy {
		t.Fatalf("fresh analyzer was not healthy: %#v err=%v", health, err)
	}
	status.ScanInProgress = true
	status.LastSuccessAt = time.Time{}
	if err := store.WriteStatus(status); err != nil {
		t.Fatal(err)
	}
	health, err = store.Health(now)
	if err != nil || health.Validate() != nil || !health.Healthy || health.State != HealthScanning {
		t.Fatalf("heartbeating active scan was not healthy: %#v err=%v", health, err)
	}
	health, err = store.Health(now.Add(3 * time.Minute))
	if err != nil || health.Validate() != nil || health.Healthy || health.State != HealthStale {
		t.Fatalf("stale analyzer heartbeat was accepted: %#v err=%v", health, err)
	}
	status.UpdatedAt = now.Add(10 * time.Second)
	status.LastScanAt = status.UpdatedAt
	if err := store.WriteStatus(status); err != nil {
		t.Fatal(err)
	}
	health, err = store.Health(now)
	if err != nil || health.Validate() != nil || health.Healthy || health.State != HealthStale || health.HeartbeatAgeMillis >= 0 {
		t.Fatalf("future analyzer heartbeat was not represented as stale evidence: %#v err=%v", health, err)
	}
}

func TestMaintenanceStatusIsAuthenticatedAndClientValidated(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	store := NewStateStore(filepath.Join(t.TempDir(), "state"))
	if err := store.Prepare(); err != nil {
		t.Fatal(err)
	}
	status := Status{Schema: SchemaVersion, Engine: EngineSuricata, SourceVersion: "8.0.6", RulesetID: "shakerproxy-cleartext-policy", RulesetVersion: "2026.09.01.1", RulesetSHA256: strings.Repeat("a", 64), StartedAt: now.Add(-time.Hour), UpdatedAt: now, LastScanAt: now.Add(-time.Minute), LastSuccessAt: now.Add(-time.Minute)}
	if err := store.WriteStatus(status); err != nil {
		t.Fatal(err)
	}
	service, err := NewCheckpointDeletionService(store, EngineSuricata)
	if err != nil {
		t.Fatal(err)
	}
	service.Now = func() time.Time { return now }
	token := []byte(strings.Repeat("h", 32))
	handler, err := NewMaintenanceHandler(service, token)
	if err != nil {
		t.Fatal(err)
	}
	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/v1/status", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated analyzer status returned %d", unauthorized.Code)
	}
	httpService := httptest.NewServer(handler)
	defer httpService.Close()
	client, err := NewMaintenanceClient(httpService.URL, token, httpService.Client())
	if err != nil {
		t.Fatal(err)
	}
	health, err := client.Status(t.Context())
	if err != nil || health.Validate() != nil || health.Engine != EngineSuricata || health.RulesetVersion != "2026.09.01.1" || !health.Healthy {
		t.Fatalf("unexpected maintenance status: %#v err=%v", health, err)
	}
}
