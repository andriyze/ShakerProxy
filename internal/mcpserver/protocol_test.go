package mcpserver

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Protocol-level tests drive the server through a real MCP client session.

func connect(t *testing.T, backend Backend) *mcp.ClientSession {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	server, err := New(backend)
	if err != nil {
		t.Fatal(err)
	}
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = serverSession.Close() })
	client := mcp.NewClient(&mcp.Implementation{Name: "shakerproxy-mcp-test-client"}, nil)
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = clientSession.Close() })
	return clientSession
}

func TestToolSurfaceIsShortReadOnlyAndDescribedWithExamples(t *testing.T) {
	session := connect(t, newFakeBackend())
	listed, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, tool := range listed.Tools {
		names = append(names, tool.Name)
		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint || !tool.Annotations.IdempotentHint || tool.Annotations.OpenWorldHint == nil || *tool.Annotations.OpenWorldHint || tool.Annotations.Title == "" {
			t.Errorf("%s is not annotated read-only: %#v", tool.Name, tool.Annotations)
		}
		if !strings.Contains(tool.Description, "Example: {") || tool.InputSchema == nil {
			t.Errorf("%s lacks an example or schema: %q", tool.Name, tool.Description)
		}
		if tool.Name != toolSearchTraffic && strings.Count(strings.TrimSuffix(tool.Description, "."), ". ") > 1 {
			t.Errorf("%s description is longer than two sentences: %q", tool.Name, tool.Description)
		}
	}
	slices.Sort(names)
	want := []string{"compare_runs", "device_activity", "device_report", "dns_lookups", "find_device", "http_requests", "list_devices", "protocols", "search_traffic", "system_status", "test_sessions", "tls_issues", "visibility_coverage"}
	if !slices.Equal(names, want) {
		t.Fatalf("tool surface: got %v want %v", names, want)
	}
	for _, tool := range listed.Tools {
		if tool.Name == toolSearchTraffic {
			for _, fragment := range []string{"Query syntax", "AND, OR, NOT", "dns.query:", "tls.state:", "http.status:>=400", "device.name:"} {
				if !strings.Contains(tool.Description, fragment) {
					t.Errorf("search_traffic cheat sheet lacks %q", fragment)
				}
			}
		}
	}

	called, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: toolSystemStatus, Arguments: json.RawMessage(`{}`)})
	if err != nil || called.IsError {
		t.Fatalf("system_status over MCP: %#v err=%v", called, err)
	}
	var status systemStatusResult
	decodeToolResult(t, called, &status)
	if !strings.HasPrefix(status.Summary, "ShakerProxy is ready") || !strings.Contains(status.Summary, "Zeek and Suricata healthy") || status.Overview.Overall != "READY" {
		t.Fatalf("system status: %#v", status)
	}

	// Errors reach the agent as tool errors with guidance, not protocol failures.
	failed, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: toolDeviceReport, Arguments: json.RawMessage(`{"device":"bench"}`)})
	if err != nil || !failed.IsError || !strings.Contains(rawToolText(t, failed), "matches 2 devices") || !strings.Contains(rawToolText(t, failed), "Bench camera 2") {
		t.Fatalf("ambiguous device error: %#v err=%v", failed, err)
	}
}
