package agentapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/devicereport"
	"shakerproxy.dev/shakerproxy/internal/testsession"
)

const intelDeviceID = "device-0123456789abcdef0123456789abcdef"

func intelServer(t *testing.T, handler func(w http.ResponseWriter, r *http.Request)) *Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		handler(w, r)
	}))
	t.Cleanup(server.Close)
	client, err := NewClient(server.URL, testToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func writeJSONResponse(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func TestResolveDeviceAndStructuredErrors(t *testing.T) {
	match := DeviceMatch{DeviceID: intelDeviceID, FriendlyName: "Living room TV", Vendor: "Samsung", Addresses: []string{"10.77.0.23"}, HardwareAddresses: []string{"52:54:00:aa:bb:23"}, Online: true, Match: "name"}
	client := intelServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("q") {
		case "living room tv":
			if r.URL.Path != "/api/v1/devices/resolve" {
				t.Errorf("path %s", r.URL.Path)
			}
			writeJSONResponse(w, http.StatusOK, DeviceResolution{Schema: 1, Query: "living room tv", Unique: true, Matches: []DeviceMatch{match}})
		case "lying":
			writeJSONResponse(w, http.StatusOK, DeviceResolution{Schema: 1, Query: "lying", Unique: true, Matches: []DeviceMatch{}})
		default:
			second := match
			second.DeviceID = "device-fedcba9876543210fedcba9876543210"
			writeJSONResponse(w, http.StatusConflict, map[string]any{"error": map[string]any{"code": "device_ambiguous", "message": "\"tv\" matches 2 devices.\nUse the full name.", "candidates": []DeviceMatch{match, second, {DeviceID: "bogus"}}}})
		}
	})
	resolution, err := client.ResolveDevice(context.Background(), " living room tv ")
	if err != nil || !resolution.Unique || resolution.Matches[0].DeviceID != intelDeviceID {
		t.Fatalf("resolve: %#v err=%v", resolution, err)
	}
	if _, err := client.ResolveDevice(context.Background(), "lying"); err == nil {
		t.Fatal("inconsistent unique flag accepted")
	}
	_, err = client.ResolveDevice(context.Background(), "tv")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusConflict || apiErr.Code != "device_ambiguous" || len(apiErr.Candidates) != 2 || strings.Contains(apiErr.Message, "\n") || !strings.HasPrefix(err.Error(), "\"tv\" matches 2 devices.") {
		t.Fatalf("structured error: %#v", err)
	}
	for _, reference := range []string{"", strings.Repeat("x", 129), "bell\x07"} {
		if _, err := client.ResolveDevice(context.Background(), reference); err == nil {
			t.Fatalf("reference %q accepted", reference)
		}
	}
}

func TestDeviceReportAndCompareValidateIdentity(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	report := devicereport.Report{Schema: 1, GeneratedAt: now, WindowStart: now.Add(-time.Hour), WindowEnd: now, CATrust: devicereport.CATrustUnknown, Device: devicereport.Device{DeviceID: intelDeviceID, Addresses: []string{}, HardwareAddresses: []string{}}, Domains: []devicereport.Domain{}, Protocols: []devicereport.Protocol{}, Findings: []devicereport.Finding{}}
	comparison := devicereport.Comparison{Schema: 1, GeneratedAt: now, DeviceID: intelDeviceID, Base: devicereport.CompareSide{SessionID: "ts-000000000000000000000001"}, Compare: devicereport.CompareSide{SessionID: "ts-000000000000000000000002"}}
	var reportQuery, comparePath string
	client := intelServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/report"):
			reportQuery = r.URL.RawQuery
			writeJSONResponse(w, http.StatusOK, report)
		case strings.HasSuffix(r.URL.Path, "/compare"):
			comparePath = r.URL.Path + "?" + r.URL.RawQuery
			writeJSONResponse(w, http.StatusOK, comparison)
		default:
			http.NotFound(w, r)
		}
	})
	got, err := client.DeviceReport(context.Background(), DeviceReportRequest{DeviceID: intelDeviceID, Window: "7d"})
	if err != nil || got.Device.DeviceID != intelDeviceID || reportQuery != "window=7d" {
		t.Fatalf("report: %#v query=%q err=%v", got, reportQuery, err)
	}
	for _, request := range []DeviceReportRequest{{DeviceID: "Living room TV"}, {DeviceID: intelDeviceID, Window: "1y"}, {DeviceID: intelDeviceID, Session: "session-1"}} {
		if _, err := client.DeviceReport(context.Background(), request); err == nil {
			t.Fatalf("invalid report request accepted: %#v", request)
		}
	}
	report.Device.DeviceID = "device-fedcba9876543210fedcba9876543210"
	if _, err := client.DeviceReport(context.Background(), DeviceReportRequest{DeviceID: intelDeviceID}); err == nil {
		t.Fatal("report for another device accepted")
	}
	compared, err := client.CompareRuns(context.Background(), CompareRequest{DeviceID: intelDeviceID, Base: "ts-000000000000000000000001", Compare: "ts-000000000000000000000002"})
	if err != nil || compared.DeviceID != intelDeviceID || comparePath != "/api/v1/devices/"+intelDeviceID+"/compare?base=ts-000000000000000000000001&compare=ts-000000000000000000000002" {
		t.Fatalf("compare: %#v path=%q err=%v", compared, comparePath, err)
	}
	if _, err := client.CompareRuns(context.Background(), CompareRequest{DeviceID: intelDeviceID, Base: "ts-000000000000000000000002", Compare: "ts-000000000000000000000001"}); err == nil {
		t.Fatal("comparison with swapped sessions accepted")
	}
}

func TestTestSessionsAreValidated(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	session := testsession.Session{Schema: 1, ID: "ts-000000000000000000000001", DeviceID: intelDeviceID, Name: "Firmware 2.1", State: testsession.StateRunning, StartedAt: now, CreatedBy: "admin"}
	list := TestSessionList{Schema: 1, Sessions: []testsession.Session{session}, Total: 1}
	var listQuery string
	client := intelServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/test-sessions" {
			listQuery = r.URL.RawQuery
			writeJSONResponse(w, http.StatusOK, list)
			return
		}
		writeJSONResponse(w, http.StatusOK, session)
	})
	got, err := client.TestSessions(context.Background(), TestSessionsRequest{DeviceID: intelDeviceID, State: "RUNNING", Limit: 5})
	if err != nil || len(got.Sessions) != 1 || listQuery != "device="+intelDeviceID+"&limit=5&state=RUNNING" {
		t.Fatalf("sessions: %#v query=%q err=%v", got, listQuery, err)
	}
	one, err := client.TestSession(context.Background(), session.ID)
	if err != nil || one.ID != session.ID {
		t.Fatalf("session: %#v err=%v", one, err)
	}
	if _, err := client.TestSession(context.Background(), "ts-000000000000000000000002"); err == nil {
		t.Fatal("session with a different identity accepted")
	}
	list.Total = 0
	if _, err := client.TestSessions(context.Background(), TestSessionsRequest{}); err == nil {
		t.Fatal("inconsistent session total accepted")
	}
	if _, err := client.TestSessions(context.Background(), TestSessionsRequest{State: "PAUSED"}); err == nil {
		t.Fatal("invalid state accepted")
	}
}

func TestProtocolsTolerateAdditiveFieldsButStayBounded(t *testing.T) {
	body := `{"schema":1,"generated_at":"2026-09-29T12:00:00Z","window":"24h","window_start":"2026-09-28T12:00:00Z","window_end":"2026-09-29T12:00:00Z","future_field":true,
"protocols":[{"protocol":"mqtt","label":"MQTT","category":"iot-messaging","visibility":"CLEARTEXT","evidence":"ANALYZER","exotic":true,"novel":true,"description":"x","flows":12,"bytes":3456,"device_count":1,"devices":[{"device_id":"` + intelDeviceID + `","device_name":"Bench camera","flows":12,"bytes":3456,"last_seen":"2026-09-29T11:00:00Z","extra":1}],"unattributed_flows":0,"first_seen":"2026-09-29T10:00:00Z","last_seen":"2026-09-29T11:00:00Z","ports":[{"transport":"tcp","port":1883,"flows":12}]}],
"coverage":{"total_bytes":3456,"decrypted_bytes":0,"cleartext_bytes":3456,"encrypted_metadata_bytes":0,"opaque_bytes":0,"opaque_percent":0},"truncated":false}`
	var query string
	client := intelServer(t, func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})
	page, err := client.Protocols(context.Background(), ProtocolsRequest{Window: "24h", DeviceID: intelDeviceID, Category: "iot-messaging", Exotic: true})
	if err != nil || len(page.Protocols) != 1 || page.Protocols[0].Devices[0].DeviceName != "Bench camera" || query != "category=iot-messaging&device="+intelDeviceID+"&exotic=true&window=24h" {
		t.Fatalf("protocols: %#v query=%q err=%v", page, query, err)
	}
	for _, request := range []ProtocolsRequest{{Window: "2d"}, {DeviceID: "tv"}, {Category: "a&b"}} {
		if _, err := client.Protocols(context.Background(), request); err == nil {
			t.Fatalf("invalid protocols request accepted: %#v", request)
		}
	}
}

func TestTrafficSearchKeepsServerSummaries(t *testing.T) {
	now := time.Now().UTC()
	client := intelServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSONResponse(w, http.StatusOK, map[string]any{
			"schema": 1, "generated_at": now,
			"events": []map[string]any{{"record_id": strings.Repeat("a", 64), "source": "ZEEK", "kind": "zeek.dns", "occurred_at": now, "received_at": now, "source_version": "8", "parser_version": "v1", "confidence": 80, "dns_query": "api.example.com", "summary": "DNS lookup api.example.com (A) → 1 answer"}},
		})
	})
	page, err := client.TrafficSearch(context.Background(), TrafficSearchRequest{Query: "kind:zeek.dns", Limit: 5})
	if err != nil || len(page.Events) != 1 || page.Events[0].Summary != "DNS lookup api.example.com (A) → 1 answer" || page.Events[0].DNSQuery != "api.example.com" {
		t.Fatalf("event summary: %#v err=%v", page, err)
	}
}
