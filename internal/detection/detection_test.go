package detection

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/ingest"
	"shakerproxy.dev/shakerproxy/internal/resourcepressure"
)

func TestNetworkIntegrityDetectionsAndResolutionPersist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "detections.json")
	manager, err := New(path, Config{})
	if err != nil {
		t.Fatal(err)
	}
	at := time.Unix(1_700_000_000, 0).UTC()
	unauthorized := Observation{Schema: 1, Kind: ObserveDHCP, OccurredAt: at, Interface: "lab0", VLANID: 20, SourceIdentity: "aa:bb:cc:dd:ee:ff"}
	events, err := manager.Observe(unauthorized)
	if err != nil || len(events) != 1 || events[0].Type != RogueDHCP || events[0].State != StateOpen {
		t.Fatalf("rogue DHCP transition missing: events=%#v err=%v", events, err)
	}
	if events, err = manager.Observe(unauthorized); err != nil || len(events) != 0 {
		t.Fatalf("duplicate open transition was emitted: events=%#v err=%v", events, err)
	}
	restarted, err := New(path, Config{})
	if err != nil {
		t.Fatal(err)
	}
	unauthorized.Authorized = true
	unauthorized.OccurredAt = at.Add(time.Minute)
	events, err = restarted.Observe(unauthorized)
	if err != nil || len(events) != 1 || events[0].State != StateResolved || events[0].FirstSeenAt != at || events[0].Revision != 2 {
		t.Fatalf("durable resolution transition missing: events=%#v err=%v", events, err)
	}
}

func TestBuiltInDetectionFamilies(t *testing.T) {
	at := time.Unix(1_700_000_000, 0).UTC()
	checks := []struct {
		observation Observation
		want        Type
	}{
		{Observation{Schema: 1, Kind: ObserveRA, OccurredAt: at, Interface: "lab0", SourceIdentity: "fe80::1"}, RogueRA},
		{Observation{Schema: 1, Kind: ObserveGateway, OccurredAt: at, Interface: "lab0", SourceIdentity: "aa:bb:cc:dd:ee:ff", ClaimedAddress: "10.0.0.1"}, GatewaySpoofSuspected},
		{Observation{Schema: 1, Kind: ObserveClock, OccurredAt: at, ClockOffsetMillis: 6000}, ClockDrift},
		{Observation{Schema: 1, Kind: ObserveCapture, OccurredAt: at, CaptureState: "RUNNING", PacketDrops: 1}, CaptureDegraded},
	}
	for _, check := range checks {
		candidates, err := Evaluate(check.observation)
		if err != nil || len(candidates) != 1 || candidates[0].Type != check.want || !candidates[0].Active {
			t.Fatalf("%s detector missing: candidates=%#v err=%v", check.want, candidates, err)
		}
	}
	pressure := resourcepressure.Evaluate(resourcepressure.Evidence{CPUKnown: true, CPUStallPercent: 65, MemoryKnown: true, MemoryAvailableBytes: 4, MemoryTotalBytes: 100, DiskKnown: true, DiskAvailableBytes: 512, DiskReserveBytes: 1024}, at)
	candidates, err := Evaluate(Observation{Schema: 1, Kind: ObserveResource, OccurredAt: at, Pressure: &pressure})
	if err != nil || len(candidates) != 3 || !candidates[0].Active || !candidates[1].Active || !candidates[2].Active {
		t.Fatalf("resource detector family missing: candidates=%#v err=%v", candidates, err)
	}
}

func TestEnvelopeAdaptersRequireExplicitAuthorizationBaselines(t *testing.T) {
	at := time.Unix(1_700_000_000, 0).UTC()
	payload := json.RawMessage(`{"dhcp":{"type":"OFFER","server_id":"10.20.0.1"},"src_mac":"aa:bb:cc:dd:ee:ff","interface":"lab0"}`)
	envelope := ingest.Envelope{Schema: 1, EventID: "event-1234567890abcdef", Source: ingest.SourceSuricata, Kind: "suricata.dhcp", OccurredAt: at, SourceVersion: "test", ParserVersion: "test", Payload: payload}
	manager, err := New(filepath.Join(t.TempDir(), "state.json"), Config{})
	if err != nil {
		t.Fatal(err)
	}
	if observations := manager.ObservationsFromEnvelope(envelope); len(observations) != 0 {
		t.Fatalf("detector guessed an authorization baseline: %#v", observations)
	}
	manager.config.AuthorizedDHCPServers = SortedSet("10.20.0.2")
	observations := manager.ObservationsFromEnvelope(envelope)
	if len(observations) != 1 || observations[0].Authorized || observations[0].OccurredAt != at {
		t.Fatalf("explicit rogue DHCP baseline was not applied: %#v", observations)
	}

	inner := Observation{Schema: 1, Kind: ObserveClock, OccurredAt: at.Add(-time.Hour), ClockSynchronized: false}
	innerPayload, _ := json.Marshal(inner)
	envelope = ingest.Envelope{Schema: 1, EventID: "event-abcdef1234567890", Source: ingest.SourceHost, Kind: "shakerproxy.observation", OccurredAt: at, SourceVersion: "test", ParserVersion: "test", Payload: innerPayload}
	observations = manager.ObservationsFromEnvelope(envelope)
	if len(observations) != 1 || observations[0].OccurredAt != at {
		t.Fatalf("nested timestamp was not bound to authenticated envelope: %#v", observations)
	}
}

func TestAuthorizationParsersRejectMalformedEntries(t *testing.T) {
	if got := SortedSet("10.0.0.1, bad value,AA:BB:CC:DD:EE:FF"); !got["10.0.0.1"] || !got["aa:bb:cc:dd:ee:ff"] || len(got) != 2 {
		t.Fatalf("unexpected sorted set: %#v", got)
	}
	if got := GatewayBindingSet("10.0.0.1=AA:BB:CC:DD:EE:FF,bad,also bad=value"); got["10.0.0.1"] != "aa:bb:cc:dd:ee:ff" || len(got) != 1 {
		t.Fatalf("unexpected gateway bindings: %#v", got)
	}
}
