package ingest

import (
	"encoding/json"
	"testing"
	"time"
)

func zeekConnEnvelope(uid, captureSessionID, proto, history string, sourcePort int, serverName string, occurredAt time.Time) Envelope {
	payload := map[string]any{
		"ts": float64(occurredAt.UnixNano()) / 1e9, "uid": uid, "_path": "conn", "proto": proto,
		"id.orig_h": "192.168.10.201", "id.orig_p": sourcePort, "id.resp_h": "13.33.52.208", "id.resp_p": 443,
		"orig_ip_bytes": 52, "resp_ip_bytes": 0,
	}
	if history != "" {
		payload["history"] = history
	}
	if serverName != "" {
		payload["server_name"] = serverName
	}
	encoded, _ := json.Marshal(payload)
	return Envelope{
		Schema: SchemaVersion, EventID: "zeek-conn-" + uid, Source: SourceZeek, Kind: "zeek.conn", OccurredAt: occurredAt,
		SourceVersion: "zeek-test", ParserVersion: "shakerproxy-test-v1", CaptureSessionID: captureSessionID,
		FlowID: "flow-zeek-" + uid, Confidence: 100, Payload: encoded,
	}
}

func TestSplitConnectionLookbackOnlyForContinuations(t *testing.T) {
	now := time.Date(2026, 10, 2, 0, 28, 20, 0, time.UTC)
	capture := "capture-49b166b089e01ba02a6383e32287b082"
	for _, test := range []struct {
		name     string
		envelope Envelope
		want     time.Duration
	}{
		{"TCP handshake starts a connection", zeekConnEnvelope("CDStDS3JdzMOd0IFVb", capture, "tcp", "ShADadtt", 38320, "www.amazon.com", now), 0},
		{"TCP SYN-ACK only still has a SYN", zeekConnEnvelope("C2", capture, "tcp", "s", 38320, "", now), 0},
		{"TCP data without a SYN continues", zeekConnEnvelope("CeUbWM27bHWicMaNM5", capture, "tcp", "DadtAt", 38320, "", now), splitTCPLookback},
		{"TCP reset alone continues", zeekConnEnvelope("CQwaNO2wZCkzW2Eted", capture, "tcp", "R", 38320, "", now), splitTCPLookback},
		{"UDP may continue", zeekConnEnvelope("C3", capture, "udp", "Dd", 37829, "", now), splitUDPLookback},
		{"outside a capture", zeekConnEnvelope("C4", "", "tcp", "DadtAt", 38320, "", now), 0},
		{"ICMP", zeekConnEnvelope("C5", capture, "icmp", "", 3, "", now), 0},
	} {
		envelope := test.envelope
		got, ok := splitConnectionLookback(envelope, ProjectNetworkFields(envelope))
		if got != test.want || ok != (test.want != 0) {
			t.Errorf("%s: lookback=%v ok=%v, want %v", test.name, got, ok, test.want)
		}
	}
	ssl := zeekConnEnvelope("C6", capture, "tcp", "DadtAt", 38320, "", now)
	ssl.Kind = "zeek.ssl"
	if _, ok := splitConnectionLookback(ssl, ProjectNetworkFields(ssl)); ok {
		t.Error("only conn.log records are linked")
	}
}
