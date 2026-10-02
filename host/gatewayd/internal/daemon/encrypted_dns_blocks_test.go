package daemon

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/nflog"
	"shakerproxy.dev/shakerproxy/internal/trafficpolicy"
)

func loggedTCP(prefix, source, destination string, port uint16, at time.Time) nflog.Packet {
	packet := make([]byte, 40)
	packet[0] = 0x45
	packet[9] = 6
	copy(packet[12:16], netip.MustParseAddr(source).AsSlice())
	copy(packet[16:20], netip.MustParseAddr(destination).AsSlice())
	binary.BigEndian.PutUint16(packet[20:22], 40123)
	binary.BigEndian.PutUint16(packet[22:24], port)
	return nflog.Packet{Prefix: prefix, Payload: packet, Time: at}
}

func spooledEvents(t *testing.T, directory string) []map[string]any {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	events := []map[string]any{}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "evt_") || !strings.HasSuffix(entry.Name(), ".json") {
			t.Fatalf("unexpected spool entry %s", entry.Name())
		}
		data, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var event map[string]any
		if err := json.Unmarshal(data, &event); err != nil {
			t.Fatal(err)
		}
		events = append(events, event)
	}
	return events
}

func TestBlockedEncryptedDNSAttemptsBecomeTrafficEvents(t *testing.T) {
	spool := t.TempDir()
	monitor := NewEncryptedDNSBlockMonitor(spool, nil)
	at := time.Date(2026, 10, 2, 4, 0, 0, 0, time.UTC)
	monitor.Handle(loggedTCP("SHAKERPROXY_EDNS_DOH_TCP ", "192.168.10.201", "8.8.8.8", 443, at))
	// A retry storm of the same attempt is recorded once a minute.
	for second := 1; second < 30; second++ {
		monitor.Handle(loggedTCP("SHAKERPROXY_EDNS_DOH_TCP ", "192.168.10.201", "8.8.8.8", 443, at.Add(time.Duration(second)*time.Second)))
	}
	monitor.Handle(loggedTCP("SHAKERPROXY_EDNS_DOT ", "192.168.10.201", "1.1.1.1", 853, at.Add(time.Second)))
	monitor.Handle(loggedTCP("SHAKERPROXY_EDNS_DOH_TCP ", "192.168.10.201", "8.8.8.8", 443, at.Add(61*time.Second)))
	// Packets from other rules are not encrypted-DNS blocks.
	monitor.Handle(loggedTCP("SOMETHING_ELSE ", "192.168.10.201", "8.8.8.8", 443, at))
	events := spooledEvents(t, spool)
	if len(events) != 3 {
		t.Fatalf("recorded %d events, want 3: %v", len(events), events)
	}
	reasons := map[string]int{}
	for _, event := range events {
		if event["source"] != "HOST" || event["kind"] != BlockedEventKind || event["schema"] != float64(1) || !strings.HasPrefix(event["event_id"].(string), "evt_") {
			t.Fatalf("event envelope = %v", event)
		}
		payload := event["payload"].(map[string]any)
		if payload["source_ip"] != "192.168.10.201" || payload["blocked"] != true || payload["service"] != "dns" {
			t.Fatalf("event payload = %v", payload)
		}
		reasons[payload["reason"].(string)]++
		if payload["reason"] == trafficpolicy.BlockReasonDoHAddress && (payload["destination_ip"] != "8.8.8.8" || payload["destination_port"] != float64(443) || payload["resolver"] != "Google Public DNS") {
			t.Fatalf("DoH block payload = %v", payload)
		}
	}
	if reasons[trafficpolicy.BlockReasonDoHAddress] != 2 || reasons[trafficpolicy.BlockReasonDoT] != 1 {
		t.Fatalf("reasons = %v", reasons)
	}
}

func TestBlockedEventReasonsMatchTheRenderedRules(t *testing.T) {
	rules, err := trafficpolicy.RenderFirewall(trafficpolicy.BlockingPolicy(), trafficpolicy.RenderContext{LabInterface: "ens18", LabCIDR: "192.168.10.0/24", LabGatewayIPv4: "192.168.10.177"})
	if err != nil {
		t.Fatal(err)
	}
	prefixes := map[string]bool{}
	for _, rule := range rules.FilterRules {
		if _, after, found := strings.Cut(rule, `--nflog-prefix "`); found {
			prefixes[strings.TrimSpace(strings.SplitN(after, `"`, 2)[0])] = true
		}
	}
	if len(prefixes) == 0 {
		t.Fatal("the blocking policy logs no blocked attempts")
	}
	for prefix := range prefixes {
		if blockReasons[prefix] == "" {
			t.Fatalf("rule prefix %q has no Traffic reason", prefix)
		}
	}
}

func TestAnUntouchedObserveDefaultMovesToVisibilityAtStartup(t *testing.T) {
	root := t.TempDir()
	store := &trafficpolicy.Store{Path: filepath.Join(root, "policy.json")}
	if _, err := store.Apply(trafficpolicy.LegacyDefaultPolicy(), 0); err != nil {
		t.Fatal(err)
	}
	manager := &TrafficPolicyManager{
		NetworkState: routedTrafficState(),
		PolicyStore:  store,
		RuntimePath:  filepath.Join(root, "traffic", "policy.json"),
		Runner:       &fakeTrafficRunner{},
		Probe:        func(context.Context, int) error { return nil },
	}
	if err := manager.Ensure(t.Context()); err != nil {
		t.Fatal(err)
	}
	document, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if document.Policy.Revision != 2 || document.Policy.Name != trafficpolicy.DefaultPolicyName || !document.Policy.EncryptedDNS.ForcePlainDNS() || document.Policy.EncryptedDNS.BlockEncryptedDNS() || document.Previous == nil {
		t.Fatalf("policy after startup = %+v", document.Policy)
	}
	// An administrator's own choice, here observe-only again, is kept.
	observe := document.Policy
	observe.Revision = 3
	observe.EncryptedDNS = observe.EncryptedDNS.WithSwitches(false, false)
	if _, err := store.Apply(observe, 2); err != nil {
		t.Fatal(err)
	}
	if err := manager.Ensure(t.Context()); err != nil {
		t.Fatal(err)
	}
	document, _ = store.Load()
	if document.Policy.Revision != 3 || document.Policy.EncryptedDNS.ForcePlainDNS() || document.Policy.EncryptedDNS.BlockEncryptedDNS() {
		t.Fatalf("an administrator's observe-only policy was changed: %+v", document.Policy)
	}
}
