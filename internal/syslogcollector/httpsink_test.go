package syslogcollector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/ingest"
)

func TestHTTPSinkPostsAuthenticatedEventsAndTreatsDuplicatesAsDelivered(t *testing.T) {
	var seen int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/events" || r.Header.Get("Authorization") != "Bearer secret" || r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		seen++
		if seen == 2 {
			w.WriteHeader(http.StatusConflict) // duplicate
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	sink, err := NewHTTPSink(server.URL, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := ingest.NormalizeNetworkGearEvent(ingest.NetworkGearDHCPKind, time.Now(), map[string]any{"mac": "62:bc:f1:bc:1d:8d", "assigned_addr": "192.168.10.130", "host_name": "iPhone"})
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Deliver(context.Background(), envelope); err != nil {
		t.Fatalf("first deliver: %v", err)
	}
	if err := sink.Deliver(context.Background(), envelope); err != nil {
		t.Fatalf("duplicate should count as delivered: %v", err)
	}
}

func TestHTTPSinkReportsServerErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInsufficientStorage)
	}))
	defer server.Close()
	sink, _ := NewHTTPSink(server.URL, []byte("secret"))
	envelope, _ := ingest.NormalizeNetworkGearEvent(ingest.NetworkGearSystemKind, time.Now(), map[string]any{"event": "link_up", "message": "WAN up"})
	if err := sink.Deliver(context.Background(), envelope); err == nil {
		t.Fatal("a 5xx should be reported as an error")
	}
}

func TestNewHTTPSinkRejectsBadInput(t *testing.T) {
	if _, err := NewHTTPSink("://bad", []byte("x")); err == nil {
		t.Fatal("bad origin accepted")
	}
	if _, err := NewHTTPSink("http://host", nil); err == nil {
		t.Fatal("empty token accepted")
	}
}

func TestParseAllowedSources(t *testing.T) {
	addresses, err := ParseAllowedSources("192.168.10.1, 192.168.10.1 10.0.0.2")
	if err != nil || len(addresses) != 2 || addresses[0].String() != "192.168.10.1" || addresses[1].String() != "10.0.0.2" {
		t.Fatalf("parsed = %v err=%v", addresses, err)
	}
	if _, err := ParseAllowedSources("not-an-ip"); err == nil {
		t.Fatal("a non-IP entry should be rejected")
	}
	if addresses, err := ParseAllowedSources(""); err != nil || len(addresses) != 0 {
		t.Fatalf("empty = %v err=%v", addresses, err)
	}
}

func TestWriteStatusFileIsAtomicAndPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "syslog-status.json")
	status := Status{Enabled: true, BindAddress: ":1514", TCP: true, AllowedSources: []string{"192.168.10.1"}, Stats: Stats{Received: 3, Parsed: 2}}
	if err := WriteStatusFile(path, status); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("mode = %v, want 0640", info.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(string(raw), `"schema":1`) || !contains(string(raw), `"received":3`) {
		t.Fatalf("status content: %s", raw)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (indexOf(haystack, needle) >= 0)
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
