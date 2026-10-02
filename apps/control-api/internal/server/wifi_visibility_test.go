package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/coverage"
	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
)

func TestWiFiVisibilityReadsAndChangesTheMonitor(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "gateway.sock")
	off := gatewayprotocol.WiFiMonitorStatus{
		Schema: 1, Settings: gatewayprotocol.WiFiMonitorSettings{ChannelMode: gatewayprotocol.WiFiChannelAuto}, Available: true,
		Adapters: []gatewayprotocol.WiFiAdapter{{Interface: "wlan1", Phy: "phy1", MonitorSupported: true}}, NearbyRetentionHours: 24, CheckedAt: time.Now().UTC(),
	}
	on := off
	on.Settings = gatewayprotocol.WiFiMonitorSettings{Enabled: true, ChannelMode: gatewayprotocol.WiFiChannelFixed, Channel: 6}
	on.Active, on.Capturing, on.WorkerRunning, on.Adapter, on.Interface, on.ChannelMode, on.Channel = true, true, true, "wlan1", "spmon0", gatewayprotocol.WiFiChannelFixed, 6
	requests := startGatewaySequenceStub(t, socketPath, off, off, on, on, on)
	server, session := configuredAPIServer(t, socketPath)

	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, authenticatedJSONRequest(http.MethodGet, "/api/v1/wifi-visibility", "", session, ""))
	var view wifiVisibilityView
	if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &view) != nil || view.Settings.Enabled || !view.Available || len(view.Notes) < 3 {
		t.Fatalf("GET returned %d: %s", recorder.Code, recorder.Body.String())
	}

	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, authenticatedJSONRequest(http.MethodPut, "/api/v1/wifi-visibility", `{"enabled":true,"channel":6}`, session, ""))
	if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &view) != nil || !view.Active || view.Channel != 6 {
		t.Fatalf("PUT returned %d: %s", recorder.Code, recorder.Body.String())
	}
	for _, want := range []string{"GetWiFiMonitor", "GetWiFiMonitor", "SetWiFiMonitor"} {
		rpc := <-requests
		if rpc.Method != want {
			t.Fatalf("got RPC %q, want %q", rpc.Method, want)
		}
		if want == "SetWiFiMonitor" {
			var params gatewayprotocol.SetWiFiMonitorParams
			if err := json.Unmarshal(rpc.Params, &params); err != nil || !params.Settings.Enabled || params.Settings.ChannelMode != gatewayprotocol.WiFiChannelFixed || params.Settings.Channel != 6 || params.Settings.Nearby {
				t.Fatalf("set %s err=%v", rpc.Params, err)
			}
		}
	}

	// Nearby devices need an explicit confirmation; nothing reaches the
	// gateway without it.
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, authenticatedJSONRequest(http.MethodPut, "/api/v1/wifi-visibility", `{"nearby":true}`, session, ""))
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "acknowledge_nearby") {
		t.Fatalf("unconfirmed nearby returned %d: %s", recorder.Code, recorder.Body.String())
	}
	for _, body := range []string{`{}`, `{"channel_mode":"sometimes"}`} {
		recorder = httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, authenticatedJSONRequest(http.MethodPut, "/api/v1/wifi-visibility", body, session, ""))
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("%s returned %d", body, recorder.Code)
		}
	}
}

func TestWiFiRadioCoverageRow(t *testing.T) {
	pass := coverage.WiFiRadioResult(coverage.WiFiRadio{Enabled: true, Active: true, WorkerRunning: true, Available: true, Adapter: "wlan1", ChannelMode: "fixed", Channel: 6})
	if pass.Status != coverage.StatusPass || pass.ID != coverage.ResultWiFiRadio || !strings.Contains(pass.Summary, "channel 6") {
		t.Fatalf("pass = %+v", pass)
	}
	skip := coverage.WiFiRadioResult(coverage.WiFiRadio{Reason: "No Wi-Fi adapter is connected."})
	if skip.Status != coverage.StatusSkip || !strings.Contains(skip.Summary, "No Wi-Fi adapter") {
		t.Fatalf("skip = %+v", skip)
	}
	off := coverage.WiFiRadioResult(coverage.WiFiRadio{Available: true})
	if off.Status != coverage.StatusSkip || !strings.Contains(off.Summary, "shakerproxy wifi on") {
		t.Fatalf("off = %+v", off)
	}
}
