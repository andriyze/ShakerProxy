package detection

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/ingest"
)

func TestCleartextExposureIsAHighFindingWithoutTheSecret(t *testing.T) {
	at := time.Unix(1_700_000_000, 0).UTC()
	candidates, err := Evaluate(Observation{Schema: 1, Kind: ObserveCleartext, OccurredAt: at, SourceIdentity: "192.168.10.130", DestinationHost: "example.com", ExposureKind: "token-in-url"})
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 {
		t.Fatalf("candidates = %#v", candidates)
	}
	candidate := candidates[0]
	if candidate.Type != CleartextCredential || candidate.Severity != SeverityHigh || !candidate.Active {
		t.Fatalf("unexpected candidate %#v", candidate)
	}
	if candidate.Scope != "192.168.10.130/example.com/token-in-url" {
		t.Fatalf("scope = %q", candidate.Scope)
	}
	if !strings.Contains(candidate.Summary, "example.com") || len(candidate.Summary) > 256 {
		t.Fatalf("summary = %q", candidate.Summary)
	}
}

func TestCleartextExposureRejectsBadInput(t *testing.T) {
	at := time.Unix(1_700_000_000, 0).UTC()
	bad := []Observation{
		{Schema: 1, Kind: ObserveCleartext, OccurredAt: at, SourceIdentity: "1.2.3.4", DestinationHost: "example.com", ExposureKind: "nonsense"},
		{Schema: 1, Kind: ObserveCleartext, OccurredAt: at, SourceIdentity: "1.2.3.4", ExposureKind: "token-in-url"},
		{Schema: 1, Kind: ObserveCleartext, OccurredAt: at, DestinationHost: "a b c", SourceIdentity: "1.2.3.4", ExposureKind: "token-in-url"},
	}
	for index, observation := range bad {
		if _, err := Evaluate(observation); err == nil {
			t.Fatalf("case %d was accepted", index)
		}
	}
}

func TestCleartextExposureLifecycleOpensAndResolves(t *testing.T) {
	at := time.Unix(1_700_000_000, 0).UTC()
	manager, err := New(filepath.Join(t.TempDir(), "state.json"), Config{})
	if err != nil {
		t.Fatal(err)
	}
	observation := Observation{Schema: 1, Kind: ObserveCleartext, OccurredAt: at, SourceIdentity: "192.168.10.130", DestinationHost: "example.com", ExposureKind: "token-in-url"}
	events, err := manager.Observe(observation)
	if err != nil || len(events) != 1 || events[0].State != StateOpen {
		t.Fatalf("first observation: %#v %v", events, err)
	}
	// The same exposure again does not create a duplicate.
	again, err := manager.Observe(observation)
	if err != nil || len(again) != 0 {
		t.Fatalf("duplicate exposure emitted an event: %#v %v", again, err)
	}
}

// A cleartext HTTP event whose URL carries a credential becomes a detection
// observation at ingest, with no packet replay. The secret value never
// reaches the observation.
func TestCleartextHTTPObservationFromEnvelope(t *testing.T) {
	at := time.Unix(1_700_000_000, 0).UTC()
	manager, err := New(filepath.Join(t.TempDir(), "state.json"), Config{})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		source  string
		kind    string
		payload string
		want    bool
	}{
		{"zeek with token", string(ingest.SourceZeek), "zeek.http", `{"id.orig_h":"192.168.10.130","host":"example.com:80","uri":"/login?api_key=s3cr3t&p=2"}`, true},
		{"suricata with token", string(ingest.SourceSuricata), "suricata.http", `{"src_ip":"192.168.10.131","http":{"hostname":"api.example.com","url":"/v1?access_token=abc"}}`, true},
		{"zeek no credential", string(ingest.SourceZeek), "zeek.http", `{"id.orig_h":"192.168.10.130","host":"example.com","uri":"/search?q=cats"}`, false},
		{"not http", string(ingest.SourceZeek), "zeek.conn", `{"id.orig_h":"192.168.10.130","uri":"/x?token=a"}`, false},
	}
	for _, test := range cases {
		envelope := ingest.Envelope{Schema: 1, EventID: "event-0000000000000001", Source: ingest.Source(test.source), Kind: test.kind, OccurredAt: at, SourceVersion: "t", ParserVersion: "t", Payload: json.RawMessage(test.payload)}
		observations := manager.ObservationsFromEnvelope(envelope)
		if test.want != (len(observations) == 1) {
			t.Fatalf("%s: observations = %#v", test.name, observations)
		}
		for _, observation := range observations {
			if observation.Kind != ObserveCleartext || observation.ExposureKind != "token-in-url" {
				t.Fatalf("%s: wrong observation %#v", test.name, observation)
			}
			blob, _ := json.Marshal(observation)
			for _, secret := range []string{"s3cr3t", "abc"} {
				if strings.Contains(string(blob), secret) {
					t.Fatalf("%s: observation leaked a secret: %s", test.name, blob)
				}
			}
		}
	}
}
