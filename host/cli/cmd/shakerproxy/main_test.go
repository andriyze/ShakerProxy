package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	"shakerproxy.dev/shakerproxy/internal/capture"
	"shakerproxy.dev/shakerproxy/internal/gatewayclient"
	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/managementpki"
)

const cliCaptureID = "capture-0123456789abcdef0123456789abcdef"

func TestBypassMethod(t *testing.T) {
	if got := bypassMethod("enable"); got != "EnableEmergencyBypass" {
		t.Fatalf("enable selected %q", got)
	}
	if got := bypassMethod("disable"); got != "DisableEmergencyBypass" {
		t.Fatalf("disable selected %q", got)
	}
}

func TestManagementCAExportDoesNotOverwrite(t *testing.T) {
	root := t.TempDir()
	status, err := managementpki.Ensure(managementpki.Options{EtcRoot: filepath.Join(root, "etc"), DataRoot: filepath.Join(root, "data"), EdgeGID: -1, Testing: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SHAKERPROXY_MANAGEMENT_CA_PATH", filepath.Join(root, "data", "public", "management-ca.crt"))
	t.Setenv("SHAKERPROXY_MANAGEMENT_PKI_STATUS_PATH", filepath.Join(root, "data", "public", "management-pki.json"))
	destination := filepath.Join(root, "exported-management-ca.crt")
	c, _, _ := testCLI()
	if err := c.managementCACommand([]string{"export", destination}); err != nil {
		t.Fatal(err)
	}
	if err := c.managementCACommand([]string{"export", destination}); err == nil {
		t.Fatal("export overwrote an existing file")
	}
	certificate, exportedStatus, err := managementpki.LoadPublic(destination, filepath.Join(root, "data", "public", "management-pki.json"))
	if err != nil || len(certificate) == 0 || exportedStatus.SHA256Fingerprint != status.SHA256Fingerprint {
		t.Fatalf("invalid export: %v", err)
	}
}

func TestExportCaptureStreamsAndVerifiesWithoutOverwrite(t *testing.T) {
	directory := t.TempDir()
	socketPath := filepath.Join(directory, "gateway.sock")
	destination := filepath.Join(directory, "case.pcapng")
	content := []byte("pcapng-test-content")
	digest := sha256.Sum256(content)
	hash := fmt.Sprintf("%x", digest[:])
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	go serveCLIExport(t, listener, content, hash)
	client := gatewayclient.Client{SocketPath: socketPath}
	result, err := exportCaptureFile(context.Background(), client, cliCaptureID, "capture_00001.pcapng", destination)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Verified || result.SizeBytes != int64(len(content)) || result.SHA256 != hash {
		t.Fatalf("unexpected export result: %+v", result)
	}
	actual, err := os.ReadFile(destination)
	if err != nil || string(actual) != string(content) {
		t.Fatalf("unexpected exported content %q, %v", actual, err)
	}
	info, err := os.Stat(destination)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("unexpected export mode: %v, %v", info, err)
	}
	if _, err := exportCaptureFile(context.Background(), gatewayclient.Client{SocketPath: filepath.Join(directory, "absent.sock")}, cliCaptureID, "capture_00001.pcapng", destination); err == nil {
		t.Fatal("export overwrote an existing destination")
	}
}

func serveCLIExport(t *testing.T, listener net.Listener, content []byte, hash string) {
	t.Helper()
	defer listener.Close()
	for index := 0; index < 2; index++ {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		var request gatewayprotocol.Request
		if json.NewDecoder(connection).Decode(&request) != nil {
			connection.Close()
			return
		}
		var result any = capture.View{Session: capture.Session{ID: cliCaptureID}, State: capture.StateCompleted, Manifest: &capture.Manifest{Schema: 1, SessionID: cliCaptureID, Files: []capture.CaptureFile{{Name: "capture_00001.pcapng", SizeBytes: int64(len(content)), SHA256: hash}}}}
		if request.Method == "ReadCaptureArtifact" {
			var params gatewayprotocol.ReadCaptureArtifactParams
			if gatewayprotocol.DecodeParams(request.Params, &params) != nil {
				connection.Close()
				return
			}
			end := min(int64(len(content)), params.Offset+int64(params.Length))
			result = capture.ArtifactChunk{SessionID: cliCaptureID, FileName: params.FileName, FileSHA256: hash, Offset: params.Offset, TotalBytes: int64(len(content)), Data: content[params.Offset:end], EOF: end == int64(len(content))}
		}
		_ = json.NewEncoder(connection).Encode(gatewayprotocol.Response{JSONRPC: gatewayprotocol.JSONRPCVersion, ID: request.ID, Result: result})
		connection.Close()
	}
}
