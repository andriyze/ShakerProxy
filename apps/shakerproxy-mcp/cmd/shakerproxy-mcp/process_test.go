package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"shakerproxy.dev/shakerproxy/internal/agentapi"
	"shakerproxy.dev/shakerproxy/internal/analyzer"
	"shakerproxy.dev/shakerproxy/internal/ingest"
)

const helperProcessEnvironment = "SHAKERPROXY_MCP_TEST_HELPER_PROCESS"

func TestShakerProxyMCPHelperProcess(t *testing.T) {
	if os.Getenv(helperProcessEnvironment) != "1" {
		return
	}
	if err := run(context.Background(), []string{"shakerproxy-mcp"}, io.Discard); err != nil {
		fmt.Fprintf(os.Stderr, "shakerproxy-mcp helper: %v\n", err)
		os.Exit(2)
	}
	os.Exit(0)
}

func TestCommandProcessNegotiatesStdioCallsHTTPActivityAndHonorsRevocation(t *testing.T) {
	anchor := time.Date(2026, 9, 3, 20, 0, 0, 0, time.UTC)
	deviceID := "device-0123456789abcdef0123456789abcdef"
	token := "lgt_" + strings.Repeat("p", 48)
	var revoked atomic.Bool
	var statusCalls atomic.Int32
	var activityCalls atomic.Int32
	var deniedCalls atomic.Int32
	var resolveCalls atomic.Int32

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if r.Header.Get("Authorization") != "Bearer "+token || r.Header.Get("Accept") != "application/json" {
			http.Error(w, `{"error":{"code":"unauthorized","message":"invalid test credential"}}`, http.StatusUnauthorized)
			return
		}
		if revoked.Load() {
			deniedCalls.Add(1)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":{"code":"token_revoked","message":"token is revoked"}}`))
			return
		}
		switch r.URL.Path {
		case "/api/v1/agent/system-overview":
			statusCalls.Add(1)
			if r.URL.RawQuery != "" {
				http.Error(w, `{"error":{"code":"invalid_query","message":"unexpected query"}}`, http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(agentapi.SystemOverview{
				Schema: 1, GeneratedAt: anchor, Overall: "READY", EvidenceReady: true,
				Gateway: agentapi.GatewayOverview{Available: true, OperatingMode: "SETUP_SAFE"},
				Ingest:  agentapi.IngestOverview{Available: true, GeneratedAt: anchor, DatabaseConfigured: true, DatabaseConnected: true},
				Analyzers: []agentapi.AnalyzerOverview{
					{Engine: string(analyzer.EngineZeek), Available: true, State: string(analyzer.HealthHealthy), Healthy: true},
					{Engine: string(analyzer.EngineSuricata), Available: true, State: string(analyzer.HealthHealthy), Healthy: true},
				},
				Capabilities: agentapi.CapabilityOverview{Features: []agentapi.CapabilityFeature{}},
				Limitations:  []string{},
			})
		case "/api/v1/devices/resolve":
			resolveCalls.Add(1)
			if r.URL.Query().Get("q") != "Bench camera" {
				http.Error(w, `{"error":{"code":"invalid_query","message":"unexpected device reference"}}`, http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(agentapi.DeviceResolution{Schema: 1, Query: "Bench camera", Unique: true, Matches: []agentapi.DeviceMatch{{
				DeviceID: deviceID, FriendlyName: "Bench camera", Addresses: []string{"10.77.0.30"}, HardwareAddresses: []string{"52:54:00:aa:bb:30"}, Online: true, Match: "name",
			}}})
		case "/api/v1/agent/http-activity":
			activityCalls.Add(1)
			values := r.URL.Query()
			if values.Get("window") != "1h" || values.Get("limit") != "1" || values.Get("device_id") != deviceID || values.Get("host") != "api.example.test" || values.Get("method") != "POST" || values.Get("cursor") != "" {
				http.Error(w, `{"error":{"code":"invalid_query","message":"unexpected canonical HTTP query"}}`, http.StatusBadRequest)
				return
			}
			decrypted := true
			requestBytes, responseBytes := int64(128), int64(2048)
			_ = json.NewEncoder(w).Encode(ingest.HTTPActivityPage{
				Schema: ingest.SchemaVersion, GeneratedAt: anchor.Add(time.Second), QueryAnchor: anchor,
				Events: []ingest.HTTPActivityEvent{{
					RecordID: strings.Repeat("a", 64), Source: ingest.SourceMitmproxy, Kind: "http_response",
					OccurredAt: anchor.Add(-time.Minute), ReceivedAt: anchor.Add(-30 * time.Second),
					FlowID: "flow-process-test-0001", DeviceID: deviceID,
					Method: "POST", Scheme: "https", Host: "api.example.test", Port: 443,
					Path: "/v1/orders", Status: 201, HTTPVersion: "HTTP/2.0",
					RequestBytes: &requestBytes, ResponseBytes: &responseBytes, Decrypted: &decrypted,
					ContentLocalOnly: true,
				}},
			})
		default:
			http.Error(w, `{"error":{"code":"not_found","message":"unexpected test route"}}`, http.StatusNotFound)
		}
	}))
	defer api.Close()

	tokenPath := filepath.Join(t.TempDir(), "mcp-token")
	if err := os.WriteFile(tokenPath, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestShakerProxyMCPHelperProcess$")
	command.Env = processEnvironment(map[string]string{
		helperProcessEnvironment:         "1",
		"SHAKERPROXY_API_URL":            api.URL,
		"SHAKERPROXY_API_TOKEN_FILE":     tokenPath,
		"SHAKERPROXY_MANAGEMENT_CA_FILE": "",
	})
	client := mcp.NewClient(&mcp.Implementation{Name: "shakerproxy-process-test", Version: "1"}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	session, err := client.Connect(ctx, &mcp.CommandTransport{Command: command}, nil)
	if err != nil {
		t.Fatalf("connect to real shakerproxy-mcp process: %v", err)
	}
	defer session.Close()

	listed, err := session.ListTools(ctx, nil)
	if err != nil || len(listed.Tools) != 21 {
		t.Fatalf("real MCP process tool discovery failed: tools=%d err=%v", len(listed.Tools), err)
	}
	for _, tool := range listed.Tools {
		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
			t.Fatalf("real MCP process exposes a tool without ReadOnlyHint: %s", tool.Name)
		}
	}
	statusResult, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "system_status", Arguments: json.RawMessage(`{}`)})
	if err != nil || statusResult.IsError || !toolTextContains(statusResult, `"operating_mode":"SETUP_SAFE"`) || !toolTextContains(statusResult, "ShakerProxy is ready") {
		t.Fatalf("real MCP status call failed: result=%#v err=%v", statusResult, err)
	}
	activityResult, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "http_requests",
		Arguments: json.RawMessage(`{"window":"1h","device":"Bench camera","host":"API.Example.Test.","method":"post","limit":1}`),
	})
	if err != nil || activityResult.IsError || !toolTextContains(activityResult, `"path":"/v1/orders"`) || !toolTextContains(activityResult, `"status":201`) || !toolTextContains(activityResult, `"plaintext_included":false`) || !toolTextContains(activityResult, "POST api.example.test/v1/orders") {
		t.Fatalf("real MCP HTTP activity call failed: result=%#v err=%v", activityResult, err)
	}
	for _, forbidden := range []string{"request_headers", "response_headers", "request_body", "response_body", "Authorization", "cookie", "52:54:00"} {
		if toolTextContains(activityResult, forbidden) {
			t.Fatalf("real MCP process leaked forbidden field %q", forbidden)
		}
	}

	revoked.Store(true)
	revokedResult, revokedErr := session.CallTool(ctx, &mcp.CallToolParams{Name: "system_status", Arguments: json.RawMessage(`{}`)})
	if revokedErr == nil && revokedResult != nil && !revokedResult.IsError {
		t.Fatalf("revoked token still returned MCP data: %#v", revokedResult)
	}
	if revokedErr == nil && !toolTextContains(revokedResult, "token is revoked") {
		t.Fatalf("revocation error does not carry the API message: %#v", revokedResult)
	}
	if statusCalls.Load() != 1 || resolveCalls.Load() != 1 || activityCalls.Load() != 1 || deniedCalls.Load() != 1 {
		t.Fatalf("unexpected process API calls: status=%d resolve=%d activity=%d denied=%d", statusCalls.Load(), resolveCalls.Load(), activityCalls.Load(), deniedCalls.Load())
	}
}

func toolTextContains(result *mcp.CallToolResult, value string) bool {
	if result == nil || len(result.Content) != 1 {
		return false
	}
	text, ok := result.Content[0].(*mcp.TextContent)
	return ok && strings.Contains(text.Text, value)
}

func processEnvironment(overrides map[string]string) []string {
	environment := make([]string, 0, len(os.Environ())+len(overrides))
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if _, replaced := overrides[name]; !replaced {
			environment = append(environment, entry)
		}
	}
	for name, value := range overrides {
		environment = append(environment, name+"="+value)
	}
	return environment
}
