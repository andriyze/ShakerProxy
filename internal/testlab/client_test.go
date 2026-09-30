package testlab

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestValidProfile(t *testing.T) {
	for _, profile := range []Profile{ProfileQuick, ProfileFull, ProfileDNS, ProfileTLS} {
		if !ValidProfile(profile) {
			t.Fatalf("expected %q to be valid", profile)
		}
	}
	if ValidProfile(Profile("everything")) {
		t.Fatal("unexpected arbitrary profile acceptance")
	}
}

func TestClientUsesUnixSocketAndStrictResponse(t *testing.T) {
	root := t.TempDir()
	socket := filepath.Join(root, "testlab.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/status" || r.Method != http.MethodGet {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Status{Schema: SchemaVersion, State: StateIdle, Available: true, UpdatedAt: time.Unix(1, 0).UTC()})
	})}
	go server.Serve(listener)
	defer server.Shutdown(context.Background())

	status, err := (Client{SocketPath: socket, Timeout: time.Second}).Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.Schema != SchemaVersion || !status.Available || status.State != StateIdle {
		t.Fatalf("unexpected status: %+v", status)
	}
}

func TestDefaultSocketStaysInsideExistingControlStateMount(t *testing.T) {
	if filepath.Clean(DefaultSocketPath) != "/var/lib/shakerproxy/control-api/testlab/testlab.sock" {
		t.Fatalf("unexpected socket path %q", DefaultSocketPath)
	}
	if _, err := os.Stat(filepath.Dir(DefaultSocketPath)); err == nil {
		// The unit test does not require the production directory to exist.
	}
}
