package forwarder

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/ingest"
)

func TestJSONLForwarderIsOffByDefaultAndNeverCopiesPayload(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	manager := &Manager{Root: t.TempDir(), Now: func() time.Time { return now }}
	created, err := manager.Create(CreateRequest{Name: "local SIEM drop", Kind: KindJSONL, Classes: []EventClass{ClassAlert}, Actor: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if created.Integration.Enabled || created.Integration.Destination != "local://"+created.Integration.ID+".jsonl" || created.HMACSecret != "" {
		t.Fatalf("unsafe creation defaults: %#v", created)
	}
	event := ingest.Envelope{Schema: ingest.SchemaVersion, EventID: "suricata-0123456789abcdef0123456789abcdef", Source: ingest.SourceSuricata, Kind: "suricata.alert", OccurredAt: now, SourceVersion: "8.0.6", ParserVersion: ingest.SuricataParserVersion, Confidence: 85, Payload: json.RawMessage(`{"src_ip":"10.77.0.5","dest_ip":"1.1.1.1","body":"NEVER_FORWARD_BODY","keylog":"NEVER_FORWARD_KEYLOG","administrator_password":"NEVER_FORWARD_PASSWORD","ca_private_key":"NEVER_FORWARD_CA"}`)}
	if err := manager.Enqueue(event); err != nil {
		t.Fatal(err)
	}
	status, err := manager.Status()
	if err != nil || len(status) != 1 || status[0].Queued != 0 {
		t.Fatalf("disabled integration queued data: %#v %v", status, err)
	}
	enabled, err := manager.SetEnabled(created.Integration.ID, 1, true, "admin", "authorized local export")
	if err != nil || !enabled.Enabled || enabled.Revision != 2 {
		t.Fatalf("enable failed: %#v %v", enabled, err)
	}
	if err := manager.Enqueue(event); err != nil {
		t.Fatal(err)
	}
	stateBytes, err := os.ReadFile(filepath.Join(manager.Root, "state", created.Integration.ID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"NEVER_FORWARD_BODY", "NEVER_FORWARD_KEYLOG", "NEVER_FORWARD_PASSWORD", "NEVER_FORWARD_CA", `\"payload\"`} {
		if strings.Contains(string(stateBytes), forbidden) {
			t.Fatalf("queue leaked forbidden payload material %q: %s", forbidden, stateBytes)
		}
	}
	if err := manager.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	output, err := os.ReadFile(filepath.Join(manager.Root, "output", created.Integration.ID+".jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(output), `"sequence":1`) || !strings.Contains(string(output), `"class":"ALERT"`) || !strings.Contains(string(output), `"source_ip":"10.77.0.5"`) {
		t.Fatalf("safe event projection is incomplete: %s", output)
	}
	for _, forbidden := range []string{"NEVER_FORWARD_", `"payload"`, `"body"`, `"keylog"`, `"administrator_password"`, `"ca_private_key"`} {
		if strings.Contains(string(output), forbidden) {
			t.Fatalf("output leaked forbidden field %q: %s", forbidden, output)
		}
	}
	status, err = manager.Status()
	if err != nil || status[0].Queued != 0 || status[0].Delivered != 1 || status[0].Dropped != 0 {
		t.Fatalf("unexpected delivery status: %#v %v", status, err)
	}
	for _, path := range []string{filepath.Join(manager.Root, "config.json"), filepath.Join(manager.Root, "state", created.Integration.ID+".json"), filepath.Join(manager.Root, "output", created.Integration.ID+".jsonl")} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("unsafe forwarder file %s: %v %v", path, info, err)
		}
	}
}

func TestWebhookRequiresPublicTLSAndReturnsSecretOnce(t *testing.T) {
	manager := &Manager{Root: t.TempDir()}
	for _, destination := range []string{"http://hooks.example.com/events", "https://127.0.0.1/events", "https://localhost/events", "https://user@hooks.example.com/events", "https://hooks.example.com:8443/events", "https://hooks.example.com/events?secret=x"} {
		if _, err := manager.Create(CreateRequest{Name: "unsafe target", Kind: KindWebhook, Destination: destination, Actor: "admin"}); err == nil {
			t.Fatalf("accepted unsafe webhook destination %q", destination)
		}
	}
	created, err := manager.Create(CreateRequest{Name: "SOC webhook", Kind: KindWebhook, Destination: "https://hooks.example.com/events", Actor: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if len(created.HMACSecret) < 40 {
		t.Fatal("webhook did not return its display-once HMAC secret")
	}
	status, err := manager.Status()
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(status)
	if strings.Contains(string(encoded), created.HMACSecret) || strings.Contains(string(encoded), "hmac_secret") {
		t.Fatalf("public status leaked HMAC secret: %s", encoded)
	}
}

func TestForwarderConfigurationAuditTamperingFailsClosed(t *testing.T) {
	manager := &Manager{Root: t.TempDir()}
	created, err := manager.Create(CreateRequest{Name: "local export", Kind: KindJSONL, Actor: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.SetEnabled(created.Integration.ID, 1, true, "admin", "enable integration"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(manager.Root, "config.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data = []byte(strings.Replace(string(data), `"action": "enabled"`, `"action": "forged"`, 1))
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Status(); err == nil {
		t.Fatal("tampered forwarder audit chain was accepted")
	}
}

func TestSeparateProcessesSerializeSharedQueue(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	managerA := &Manager{Root: root, Now: func() time.Time { return now }}
	managerB := &Manager{Root: root, Now: func() time.Time { return now }}
	created, err := managerA.Create(CreateRequest{Name: "shared queue", Kind: KindJSONL, Actor: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := managerA.SetEnabled(created.Integration.ID, 1, true, "admin", "enable shared queue"); err != nil {
		t.Fatal(err)
	}
	const perWriter = 50
	var writers sync.WaitGroup
	for writer, manager := range []*Manager{managerA, managerB} {
		writers.Add(1)
		go func(writer int, manager *Manager) {
			defer writers.Done()
			for sequence := 0; sequence < perWriter; sequence++ {
				eventID := fmt.Sprintf("event-%d-%058d", writer, sequence)
				event := ingest.Envelope{Schema: ingest.SchemaVersion, EventID: eventID, Source: ingest.SourceHost, Kind: "host.health", OccurredAt: now, SourceVersion: "1", ParserVersion: "1", Confidence: 100, Payload: json.RawMessage(`{}`)}
				if err := manager.Enqueue(event); err != nil {
					t.Errorf("writer %d enqueue %d: %v", writer, sequence, err)
					return
				}
			}
		}(writer, manager)
	}
	writers.Wait()
	status, err := managerA.Status()
	if err != nil {
		t.Fatal(err)
	}
	if len(status) != 1 || status[0].Queued != 2*perWriter || status[0].Dropped != 0 {
		t.Fatalf("cross-process serialization lost queue entries: %#v", status)
	}
}
