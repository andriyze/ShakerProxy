package syslogcollector

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/ingest"
)

func spoolTestEnvelope(t *testing.T) ingest.Envelope {
	t.Helper()
	envelope, err := Normalize(Record{Kind: "netgear.dhcp_lease", Payload: map[string]any{"client_mac": "62:bc:f1:bc:1d:8d", "client_ip": "192.168.10.130", "hostname": "iPhone"}}, "192.168.10.1", time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func TestSpoolSinkWritesOneCompleteEventFile(t *testing.T) {
	directory := t.TempDir()
	sink, err := NewSpoolSink(directory)
	if err != nil {
		t.Fatal(err)
	}
	envelope := spoolTestEnvelope(t)
	if err := sink.Deliver(context.Background(), envelope); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 1 {
		t.Fatalf("spool holds %d entries (%v); want exactly one event and no temporary files", len(entries), err)
	}
	name := entries[0].Name()
	if !strings.HasPrefix(name, "evt_") || !strings.HasSuffix(name, ".json") {
		t.Fatalf("spooled file %q is not one the forwarder picks up (evt_*.json)", name)
	}
	info, err := entries[0].Info()
	if err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("spooled file mode = %v (%v); the forwarder reads it through the group, so want 0640", info.Mode().Perm(), err)
	}
	data, err := os.ReadFile(filepath.Join(directory, name))
	if err != nil {
		t.Fatal(err)
	}
	var stored ingest.Envelope
	if err := json.Unmarshal(data, &stored); err != nil || stored.EventID != envelope.EventID || stored.Source != ingest.SourceNetworkGear || stored.Kind != "netgear.dhcp_lease" {
		t.Fatalf("spooled event = %#v (%v); want the delivered envelope", stored, err)
	}
}

func TestSpoolSinkRefusesWhenTheForwarderFallsBehind(t *testing.T) {
	sink, err := NewSpoolSink(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sink.MaxPending = 2
	envelope := spoolTestEnvelope(t)
	for index := 0; index < 2; index++ {
		if err := sink.Deliver(context.Background(), envelope); err != nil {
			t.Fatalf("delivery %d: %v", index, err)
		}
	}
	if err := sink.Deliver(context.Background(), envelope); !errors.Is(err, ErrSpoolFull) {
		t.Fatalf("third delivery = %v; want ErrSpoolFull so a stopped forwarder cannot fill the disk", err)
	}
}

func TestSpoolSinkNeedsAWritableAbsoluteDirectory(t *testing.T) {
	if _, err := NewSpoolSink("relative/pending"); err == nil {
		t.Fatal("a relative spool path was accepted")
	}
	if _, err := NewSpoolSink(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("a missing spool directory was accepted")
	}
}
