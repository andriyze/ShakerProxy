package agentapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func evidenceTestClient(t *testing.T, routes map[string]string) *Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := routes[r.URL.RequestURI()]
		if !ok || r.Header.Get("Authorization") != "Bearer "+testToken {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"error":{"code":"insufficient_scope","message":"API token does not grant the required scope"}}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, body)
	}))
	t.Cleanup(server.Close)
	client, err := NewClient(server.URL, testToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestEvidenceClientsUseTheCompactRoutesAndValidateThem(t *testing.T) {
	device := "device-0123456789abcdef0123456789abcdef"
	caseID := "case-00000000000000000000000000000001"
	client := evidenceTestClient(t, map[string]string{
		"/api/v1/devices/" + device + "/controls": `{"schema":1,"device_id":"` + device + `","decrypt_https":true,"internet":"BLOCK","blocked_domains":["ads.example.com"],"updated_at":"2026-10-02T13:00:00Z","effective":true,"notes":[]}`,
		"/api/v1/agent/captures?limit=10":         `{"schema":1,"generated_at":"2026-10-02T13:00:00Z","total":1,"returned":1,"truncated":false,"recording":true,"total_bytes":4096,"captures":[{"id":"capture-0000000000000000000000000000000a","name":"Lab traffic","kind":"automatic","state":"RUNNING","active":true,"mode":"FULL","interface":"ens18","started_at":"2026-10-02T13:00:00Z","segments":2,"bytes":4096,"packets_captured":10,"packets_dropped":0,"finalized":false,"storage_pressure":false,"held":false}]}`,
		"/api/v1/agent/cases?limit=10":            `{"schema":1,"generated_at":"2026-10-02T13:00:00Z","total":1,"returned":1,"truncated":false,"cases":[{"id":"` + caseID + `","name":"Smart TV","status":"OPEN","revision":2,"created_by":"admin","created_at":"2026-10-02T13:00:00Z","updated_at":"2026-10-02T13:00:00Z","evidence_counts":{"total":0,"captures":0,"query_snapshots":0,"capture_exports":0},"hold_state":"INACTIVE"}]}`,
		"/api/v1/agent/cases/" + caseID:           `{"schema":1,"case":{"id":"` + caseID + `","name":"Smart TV","status":"OPEN","revision":2,"created_by":"admin","created_at":"2026-10-02T13:00:00Z","updated_at":"2026-10-02T13:00:00Z","evidence_counts":{"total":0,"captures":0,"query_snapshots":0,"capture_exports":0},"hold_state":"INACTIVE"},"evidence":[],"evidence_truncated":false,"timeline":[{"revision":1,"action":"CASE_CREATED","actor":"admin","occurred_at":"2026-10-02T13:00:00Z"}],"timeline_truncated":false,"hold_protected":0,"hold_failed":0}`,
		"/api/v1/system/diagnostics":              `{"schema":1,"generated_at":"2026-10-02T13:00:00Z","overall":"PASS","checks":[{"name":"dhcp","status":"PASS","summary":"Managed DHCPv4 is not required by the active mode","observations":null}],"resource_pressure":{}}`,
	})
	ctx := context.Background()
	if controls, err := client.DeviceControls(ctx, device); err != nil || !controls.DecryptHTTPS || controls.Internet != "BLOCK" {
		t.Fatalf("controls = %+v err=%v", controls, err)
	}
	if page, err := client.Captures(ctx, 10); err != nil || len(page.Captures) != 1 || page.Captures[0].Kind != "automatic" {
		t.Fatalf("captures = %+v err=%v", page, err)
	}
	if page, err := client.Cases(ctx, 10); err != nil || len(page.Cases) != 1 {
		t.Fatalf("cases = %+v err=%v", page, err)
	}
	if detail, err := client.Case(ctx, caseID); err != nil || len(detail.Timeline) != 1 {
		t.Fatalf("case = %+v err=%v", detail, err)
	}
	if report, err := client.Diagnostics(ctx); err != nil || len(report.Checks) != 1 {
		t.Fatalf("diagnostics = %+v err=%v", report, err)
	}
	if _, err := client.Case(ctx, "../../etc"); err == nil || !strings.Contains(err.Error(), "case ID is invalid") {
		t.Fatalf("a malformed case ID reached the API: %v", err)
	}
	if _, err := client.Captures(ctx, 101); err == nil {
		t.Fatal("limit 101 was accepted")
	}
	if _, err := client.Cases(ctx, 5); err == nil || !strings.Contains(err.Error(), "required scope") {
		t.Fatalf("a forbidden route did not explain itself: %v", err)
	}
}

func TestEvidenceClientsRejectInconsistentPages(t *testing.T) {
	client := evidenceTestClient(t, map[string]string{
		// returned does not match the captures sent.
		"/api/v1/agent/captures?limit=10": `{"schema":1,"generated_at":"2026-10-02T13:00:00Z","total":3,"returned":2,"truncated":true,"recording":false,"total_bytes":0,"captures":[]}`,
		"/api/v1/system/diagnostics":      `{"schema":1,"generated_at":"2026-10-02T13:00:00Z","overall":"PASS","checks":[{"name":"dhcp","status":"MAYBE","summary":"x"}],"resource_pressure":{}}`,
	})
	if _, err := client.Captures(context.Background(), 10); err == nil {
		t.Fatal("an inconsistent capture page was accepted")
	}
	if _, err := client.Diagnostics(context.Background()); err == nil {
		t.Fatal("an unknown diagnostic status was accepted")
	}
}
