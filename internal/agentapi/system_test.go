package agentapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSystemStatusUsesScopedAPIAndValidatesProjection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/system/status" || r.URL.RawQuery != "" || r.Header.Get("Authorization") != "Bearer "+testToken {
			t.Fatalf("unexpected status request %s auth=%q", r.URL.String(), r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"api_version":"1","daemon_version":"test","operating_mode":"SETUP_SAFE","emergency_bypass":false,"network_activation_available":false,"capture_available":false,"traffic_policy_available":false,"started_at":"2026-09-03T18:00:00Z"}`)
	}))
	defer server.Close()
	client, err := NewClient(server.URL, testToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	status, err := client.SystemStatus(context.Background())
	if err != nil || status.OperatingMode != "SETUP_SAFE" || status.DaemonVersion != "test" {
		t.Fatalf("unexpected system status: %#v err=%v", status, err)
	}
}

func TestSystemStatusRejectsIncompleteProjection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"api_version":"1","operating_mode":"SETUP_SAFE"}`)
	}))
	defer server.Close()
	client, err := NewClient(server.URL, testToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.SystemStatus(context.Background()); err == nil {
		t.Fatal("incomplete system status was accepted")
	}
}
