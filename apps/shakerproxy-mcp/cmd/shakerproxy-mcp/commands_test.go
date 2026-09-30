package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/agentapi"
)

func TestRunSetupStoresPrivateTokenAndNeverPrintsSecret(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", root)
	secret := "lgt_" + strings.Repeat("s", 48)
	var output bytes.Buffer
	if err := runSetup(strings.NewReader(secret+"\n"), &output, &output); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "shakerproxy", "mcp-token")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("unexpected token mode %o", info.Mode().Perm())
	}
	contents, err := os.ReadFile(path)
	if err != nil || strings.TrimSpace(string(contents)) != secret {
		t.Fatalf("saved token mismatch: err=%v", err)
	}
	if strings.Contains(output.String(), secret) {
		t.Fatal("setup output leaked display-once token")
	}
}

func TestStoreMCPTokenRejectsSymlinkDestination(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "shakerproxy")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "mcp-token")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if err := storeMCPToken(path, []byte("lgt_"+strings.Repeat("x", 48))); err == nil {
		t.Fatal("symlink token destination was accepted")
	}
	contents, _ := os.ReadFile(target)
	if string(contents) != "unchanged" {
		t.Fatal("symlink target was modified")
	}
}

func TestRunConfigProducesSecretFreeLocalAndSSHJSON(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", root)
	for _, test := range []struct {
		args        []string
		wantCommand string
	}{
		{[]string{"local"}, "/usr/bin/shakerproxy-mcp"},
		{[]string{"ssh", "analyst@shakerproxy-sensor"}, "ssh"},
	} {
		var output bytes.Buffer
		if err := runConfig(test.args, &output); err != nil {
			t.Fatal(err)
		}
		var config mcpClientConfig
		if err := json.Unmarshal(output.Bytes(), &config); err != nil {
			t.Fatal(err)
		}
		server := config.MCPServers["shakerproxy"]
		if server.Command != test.wantCommand {
			t.Fatalf("unexpected command %q", server.Command)
		}
		if strings.Contains(output.String(), "lgt_") {
			t.Fatal("client configuration contains a token")
		}
	}
	var output bytes.Buffer
	if err := runConfig([]string{"ssh", "bad target;touch /tmp/x"}, &output); err == nil {
		t.Fatal("unsafe SSH target was accepted")
	}
}

func TestRunDoctorAuthenticatesThroughAgentOverview(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	token := "lgt_" + strings.Repeat("d", 48)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent/system-overview" || r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "denied", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(agentapi.SystemOverview{
			Schema:        1,
			GeneratedAt:   now,
			Overall:       "DEGRADED",
			EvidenceReady: false,
			Gateway:       agentapi.GatewayOverview{Available: true, OperatingMode: "SETUP_SAFE"},
			Analyzers:     []agentapi.AnalyzerOverview{{Engine: "ZEEK"}, {Engine: "SURICATA"}},
			Capabilities:  agentapi.CapabilityOverview{Available: false, Features: []agentapi.CapabilityFeature{}},
			Limitations:   []string{"normalized event database is not ready"},
		})
	}))
	defer api.Close()
	root := t.TempDir()
	tokenPath := filepath.Join(root, "mcp-token")
	if err := os.WriteFile(tokenPath, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SHAKERPROXY_API_URL", api.URL)
	t.Setenv("SHAKERPROXY_API_TOKEN_FILE", tokenPath)
	t.Setenv("SHAKERPROXY_MANAGEMENT_CA_FILE", "")
	var output bytes.Buffer
	if err := runDoctor(context.Background(), &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "CONNECTED · EVIDENCE DEGRADED") || !strings.Contains(output.String(), "normalized event database is not ready") {
		t.Fatalf("unexpected doctor output: %s", output.String())
	}
}
