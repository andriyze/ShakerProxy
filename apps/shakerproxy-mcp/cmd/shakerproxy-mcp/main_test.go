package main

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestLocalAPIHTTPClientRejectsRemoteCleartextAndMalformedOrigins(t *testing.T) {
	for _, value := range []string{
		"http://example.com",
		"ftp://127.0.0.1",
		"https://user@example.com",
		"https://127.0.0.1/path",
		"https://127.0.0.1?query=yes",
	} {
		if _, err := localAPIHTTPClient(value, filepath.Join(t.TempDir(), "ca.pem")); err == nil {
			t.Fatalf("unsafe API origin %q was accepted", value)
		}
	}
}

func TestLocalAPIHTTPClientAllowsLoopbackHTTPWithoutEnvironmentProxy(t *testing.T) {
	client, err := localAPIHTTPClient("http://127.0.0.1:8080", "")
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil || client.Timeout <= 0 {
		t.Fatalf("unexpected MCP HTTP client: %#v", client)
	}
}

func TestLocalAPIHTTPClientRequiresManagementCAForHTTPS(t *testing.T) {
	if _, err := localAPIHTTPClient("https://127.0.0.1:8443", filepath.Join(t.TempDir(), "missing.pem")); err == nil {
		t.Fatal("HTTPS API client accepted a missing management CA")
	}
}

func TestLoadMCPTokenRequiresAbsolutePrivateRegularFile(t *testing.T) {
	root := t.TempDir()
	private := filepath.Join(root, "mcp-token")
	secret := []byte("lgt_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n")
	if err := os.WriteFile(private, secret, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadMCPToken(private)
	if err != nil || string(loaded) != "lgt_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("private MCP token was rejected: %q err=%v", loaded, err)
	}
	if err := os.Chmod(private, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := loadMCPToken(private); err == nil {
		t.Fatal("group-readable MCP token was accepted")
	}
	if _, err := loadMCPToken("relative-token"); err == nil {
		t.Fatal("relative MCP token path was accepted")
	}
	link := filepath.Join(root, "mcp-token-link")
	if err := os.Symlink(private, link); err != nil {
		t.Fatal(err)
	}
	if _, err := loadMCPToken(link); err == nil {
		t.Fatal("symlink MCP token was accepted")
	}
}

func TestDefaultMCPTokenPathUsesUserConfigurationDirectory(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", root)
	path, err := defaultMCPTokenPath()
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(root, "shakerproxy", "mcp-token") {
		t.Fatalf("unexpected default MCP token path %q", path)
	}
}
