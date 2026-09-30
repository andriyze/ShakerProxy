package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/analyzer"
)

func TestAnalyzerStatusAPIProjectsHealthAndIsolatesFailure(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	zeekHealth := analyzer.HealthSnapshot{
		Schema: 1, Engine: analyzer.EngineZeek, State: analyzer.HealthHealthy, Healthy: true,
		SourceVersion: "8.2.1", CompletedCaptures: 7, DeliveredEvents: 42,
		LastSuccessAt: now.Add(-time.Minute), HeartbeatAt: now, CheckedAt: now,
	}
	server, session := configuredAPIServerWithConfig(t, t.TempDir()+"/absent.sock", func(config *Config) {
		config.ZeekCheckpointDeletions = &captureDeletionAnalyzerStub{engine: analyzer.EngineZeek, health: &zeekHealth}
		config.SuricataCheckpointDeletions = &captureDeletionAnalyzerStub{engine: analyzer.EngineSuricata, statusErr: errors.New("secret backend detail")}
	})

	unauthorized := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/analyzers/status", nil)
	request.Host = "shakerproxy.test"
	server.Handler().ServeHTTP(unauthorized, request)
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated analyzer status returned %d", unauthorized.Code)
	}

	request = authenticatedJSONRequest(http.MethodGet, "/api/v1/analyzers/status", "", session, "")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || strings.Contains(recorder.Body.String(), "secret backend detail") {
		t.Fatalf("unexpected analyzer status response %d: %s", recorder.Code, recorder.Body.String())
	}
	var report analyzerStatusReport
	if err := json.Unmarshal(recorder.Body.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Schema != 1 || len(report.Analyzers) != 2 || !report.Analyzers[0].Available || report.Analyzers[0].Health == nil || report.Analyzers[0].Health.DeliveredEvents != 42 || report.Analyzers[1].Available || report.Analyzers[1].Failure != "Analyzer status is temporarily unavailable" {
		t.Fatalf("unexpected analyzer status projection: %#v", report)
	}
}
