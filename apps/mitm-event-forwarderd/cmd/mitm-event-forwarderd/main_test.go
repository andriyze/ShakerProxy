package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/conntrack"
	"shakerproxy.dev/shakerproxy/internal/dnsproxy"
	"shakerproxy.dev/shakerproxy/internal/ingest"
)

func validEvent() string {
	return fmt.Sprintf(`{"schema":1,"event_id":"evt_0123456789abcdef0123456789abcdef","source":"MITMPROXY","kind":"http_request","occurred_at":%q,"source_version":"12.2.3","parser_version":"shakerproxy-addon-1.0.0","confidence":100,"payload":{"source_ip":"10.0.0.5"}}`, time.Now().UTC().Format(time.RFC3339Nano))
}

func validTLSEvent() string {
	return fmt.Sprintf(`{"schema":1,"event_id":"evt_abcdef0123456789abcdef0123456789","source":"MITMPROXY","kind":"tls_intercepted","occurred_at":%q,"source_version":"12.2.3","parser_version":"shakerproxy-addon-1.0.0","device_id":"device-0123456789abcdef0123456789abcdef","confidence":100,"payload":{"source_ip":"10.0.0.5","destination_ip":"192.0.2.10","destination_port":443,"sni":"api.example.test"}}`, time.Now().UTC().Format(time.RFC3339Nano))
}

func TestForwardOneDeletesOnlyAfterAccepted(t *testing.T) {
	root := t.TempDir()
	tokenPath := filepath.Join(root, "token")
	if err := os.WriteFile(tokenPath, []byte(strings.Repeat("t", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Header.Get("Authorization") != "Bearer "+strings.Repeat("t", 32) {
			t.Fatalf("missing bearer token")
		}
		if requests == 1 {
			http.Error(w, "temporary", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	instance := &forwarder{
		configuration: configuration{SpoolRoot: root, IngestURL: server.URL, TokenFile: tokenPath, Timeout: time.Second},
		client:        server.Client(),
		token:         []byte(strings.Repeat("t", 32)),
	}
	path := filepath.Join(root, "evt_0123456789abcdef0123456789abcdef.json")
	if err := os.WriteFile(path, []byte(validEvent()), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := instance.forwardOne(t.Context(), path); err == nil {
		t.Fatal("temporary ingest rejection was treated as success")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("unacknowledged event was removed: %v", err)
	}
	if err := instance.forwardOne(t.Context(), path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("acknowledged event remains: %v", err)
	}
}

func TestValidateEnvelopeRejectsSecretsAndUnknownFieldsBySchemaBoundary(t *testing.T) {
	bad := strings.TrimSuffix(validEvent(), "}") + `,"authorization":"Bearer stolen"}`
	if err := validateEnvelope([]byte(bad)); err == nil {
		t.Fatal("unknown secret-bearing top-level field was accepted")
	}
}

// The DNS spool carries what shakerproxy-dnsd writes and nothing else: an
// event from a dnsd lookup reaches ingest unchanged and is a valid ingest
// envelope, while interception events and HOST detections are quarantined.
func TestHostSpoolDeliversOnlyDNSLookups(t *testing.T) {
	root := t.TempDir()
	tokenPath := filepath.Join(root, "token")
	if err := os.WriteFile(tokenPath, []byte(strings.Repeat("t", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	spool := filepath.Join(root, "pending")
	if err := os.Mkdir(spool, 0o700); err != nil {
		t.Fatal(err)
	}
	query := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	lookup, err := dnsproxy.NewLookup(time.Now(), "udp", netip.MustParseAddrPort("192.168.10.201:40000"), query, nil)
	if err != nil {
		t.Fatal(err)
	}
	lookupEvent, err := dnsproxy.LookupEvent("evt_00000000000000000001_00000001_abcdefabcdef", lookup)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ingest.DecodeEnvelope(lookupEvent); err != nil {
		t.Fatalf("dnsd's event is not a valid ingest envelope: %v", err)
	}
	connectionEvent, err := conntrack.EncodeEvent("evt_00000000000000000004_00000001_abcdefabcdef", time.Now(), conntrack.Event{Protocol: "tcp", Source: netip.MustParseAddrPort("192.168.10.201:37064"), Destination: netip.MustParseAddrPort("140.82.121.4:443")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ingest.DecodeEnvelope(connectionEvent); err != nil {
		t.Fatalf("gatewayd's connection event is not a valid ingest envelope: %v", err)
	}
	detection := strings.Replace(strings.Replace(validEvent(), `"source":"MITMPROXY"`, `"source":"HOST"`, 1), `"kind":"http_request"`, `"kind":"shakerproxy.detection.beaconing"`, 1)
	files := map[string]string{
		"evt_00000000000000000001_00000001_abcdefabcdef.json": string(lookupEvent),
		"evt_00000000000000000004_00000001_abcdefabcdef.json": string(connectionEvent),
		"evt_00000000000000000002_interception.json":          validEvent(),
		"evt_00000000000000000003_detection.json":             detection,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(spool, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	delivered := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var envelope struct {
			Kind string `json:"kind"`
		}
		_ = json.NewDecoder(r.Body).Decode(&envelope)
		delivered = append(delivered, envelope.Kind)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	instance := &forwarder{
		configuration: configuration{SpoolRoot: spool, IngestURL: server.URL, TokenFile: tokenPath, Timeout: time.Second, Source: sourceHost},
		client:        server.Client(),
		token:         []byte(strings.Repeat("t", 32)),
	}
	if err := instance.drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	sort.Strings(delivered)
	if len(delivered) != 2 || delivered[0] != "shakerproxy.conn" || delivered[1] != "shakerproxy.dns" {
		t.Fatalf("delivered %v, want the DNS lookup and the connection", delivered)
	}
	quarantined, _ := os.ReadDir(filepath.Join(root, "quarantine"))
	if remaining, _ := os.ReadDir(spool); len(remaining) != 0 || len(quarantined) != 2 {
		t.Fatalf("spool left %d files, quarantined %d", len(remaining), len(quarantined))
	}
	if _, err := newForwarder(configuration{SpoolRoot: spool, IngestURL: "http://ingestd:8081/v1/events", TokenFile: tokenPath, Source: "ZEEK"}, nil); err == nil {
		t.Fatal("an unsupported spool source was accepted")
	}
}

func TestDrainIgnoresUntrustedFileNames(t *testing.T) {
	root := t.TempDir()
	tokenPath := filepath.Join(root, "token")
	if err := os.WriteFile(tokenPath, []byte(strings.Repeat("t", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "not-an-event.json"), []byte(validEvent()), 0o600); err != nil {
		t.Fatal(err)
	}
	instance := &forwarder{
		configuration: configuration{SpoolRoot: root, IngestURL: "http://ingestd:8081/v1/events", TokenFile: tokenPath, Timeout: time.Second},
		client:        &http.Client{Timeout: time.Millisecond},
		token:         []byte(strings.Repeat("t", 32)),
	}
	if err := instance.drain(t.Context()); err != nil {
		t.Fatal(err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestForwardOneKeepsLocalSpoolMovingWhenCloudQueueRejects(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "evt_abcdef0123456789abcdef0123456789.json")
	if err := os.WriteFile(path, []byte(validTLSEvent()), 0o600); err != nil {
		t.Fatal(err)
	}
	ingest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK) // duplicate acknowledgement is still durable
	}))
	defer ingest.Close()
	cloudAttempts := 0
	instance := &forwarder{
		configuration: configuration{SpoolRoot: root, IngestURL: ingest.URL, Timeout: time.Second, ConnectorSocket: "/run/shakerproxy-cloud/connector.sock"},
		client:        ingest.Client(), token: []byte(strings.Repeat("t", 32)),
		connectorClient: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			cloudAttempts++
			var body struct {
				Events []struct {
					EventID string         `json:"event_id"`
					Type    string         `json:"type"`
					Payload map[string]any `json:"payload"`
				} `json:"events"`
			}
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if len(body.Events) != 1 || body.Events[0].EventID != "evt_abcdef0123456789abcdef0123456789" || body.Events[0].Type != "tls.event" {
				t.Fatalf("unexpected cloud metadata: %#v", body)
			}
			if body.Events[0].Payload["local_device_id"] != "device-0123456789abcdef0123456789abcdef" {
				t.Fatalf("cloud metadata lost the device identity: %#v", body.Events[0].Payload)
			}
			return &http.Response{StatusCode: http.StatusServiceUnavailable, Body: http.NoBody, Header: make(http.Header)}, nil
		})},
	}
	if err := instance.forwardOne(t.Context(), path); err != nil {
		t.Fatalf("a cloud connector outage stalled the local spool: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("locally acknowledged event remains: %v", err)
	}
	if cloudAttempts != 1 || instance.cloudFailures != 1 {
		t.Fatalf("cloud metadata was not attempted exactly once: attempts=%d failures=%d", cloudAttempts, instance.cloudFailures)
	}
}

func spoolForwarder(t *testing.T, handler http.HandlerFunc) (*forwarder, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "pending")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return &forwarder{
		configuration: configuration{SpoolRoot: root, IngestURL: server.URL, Timeout: time.Second},
		client:        server.Client(),
		token:         []byte(strings.Repeat("t", 32)),
	}, root
}

func writeSpooled(t *testing.T, root, name, content string) string {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDrainQuarantinesPoisonEventsAndContinues(t *testing.T) {
	accepted := 0
	instance, root := spoolForwarder(t, func(w http.ResponseWriter, _ *http.Request) {
		accepted++
		w.WriteHeader(http.StatusAccepted)
	})
	poison := writeSpooled(t, root, "evt_000000000001_poison.json", `{"schema":1,"broken":`)
	valid := writeSpooled(t, root, "evt_000000000002_valid.json", validEvent())
	if err := instance.drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	if accepted != 1 {
		t.Fatalf("valid event behind a poison file was not forwarded: %d", accepted)
	}
	for _, path := range []string{poison, valid} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("%s is still pending", filepath.Base(path))
		}
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(root), "quarantine", filepath.Base(poison))); err != nil {
		t.Fatalf("poison event was not quarantined: %v", err)
	}
}

func TestDrainRetriesRejectedEventsBeforeQuarantine(t *testing.T) {
	instance, root := spoolForwarder(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "rejected", http.StatusUnprocessableEntity)
	})
	path := writeSpooled(t, root, "evt_000000000001_rejected.json", validEvent())
	for attempt := 1; attempt <= maximumAttempts; attempt++ {
		if err := instance.drain(t.Context()); err != nil {
			t.Fatalf("attempt %d: a rejected event stopped the drain: %v", attempt, err)
		}
		_, err := os.Stat(path)
		if attempt < maximumAttempts && err != nil {
			t.Fatalf("attempt %d: event quarantined too early", attempt)
		}
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(root), "quarantine", filepath.Base(path))); err != nil {
		t.Fatalf("repeatedly rejected event was not quarantined: %v", err)
	}
}

func TestDrainPausesWhileIngestIsUnavailable(t *testing.T) {
	instance, root := spoolForwarder(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "starting", http.StatusServiceUnavailable)
	})
	first := writeSpooled(t, root, "evt_000000000001_a.json", validEvent())
	second := writeSpooled(t, root, "evt_000000000002_b.json", validEvent())
	for range maximumAttempts + 1 {
		if err := instance.drain(t.Context()); err == nil {
			t.Fatal("an ingest outage was not reported")
		}
	}
	for _, path := range []string{first, second} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("event lost during an ingest outage: %v", err)
		}
	}
}

func TestForwardOneAcceptsMaximumEventWithTrailingNewline(t *testing.T) {
	instance, root := spoolForwarder(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) })
	base := validEvent()
	padding := maximumEventBytes - len(base) - len(`,"pad":""`)
	event := strings.Replace(base, `"payload":{`, `"payload":{"pad":"`+strings.Repeat("x", padding)+`",`, 1)
	if len(event) != maximumEventBytes {
		t.Fatalf("fixture is %d bytes, want %d", len(event), maximumEventBytes)
	}
	path := writeSpooled(t, root, "evt_000000000001_max.json", event+"\n")
	if err := instance.forwardOne(t.Context(), path); err != nil {
		t.Fatalf("maximum-size event with trailing newline was rejected: %v", err)
	}
}

func TestCloudMetadataClassifiesProbablePinningWithoutClaimingBypass(t *testing.T) {
	envelope, err := decodeEnvelope([]byte(fmt.Sprintf(`{"schema":1,"event_id":"evt_abcdef0123456789abcdef0123456789","source":"MITMPROXY","kind":"tls_interception_failed","occurred_at":%q,"source_version":"12.2.3","parser_version":"shakerproxy-addon-1.0.0","confidence":85,"payload":{"source_ip":"10.0.0.5","destination_ip":"192.0.2.10","destination_port":443,"sni":"pinned.example.test","reason":"probable_certificate_pinning_or_custom_trust_store","dynamic_bypass_added":false}}`, time.Now().UTC().Format(time.RFC3339Nano))))
	if err != nil {
		t.Fatal(err)
	}
	event, ok := cloudMetadataEvent(envelope)
	if !ok {
		t.Fatal("probable pinning event was not projected")
	}
	var payload map[string]any
	if err := json.Unmarshal(event.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["pinning_suspected"] != true {
		t.Fatalf("probable pinning depended on successful bypass persistence: %#v", payload)
	}
}
