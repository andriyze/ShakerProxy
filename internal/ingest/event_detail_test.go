package ingest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

// storedConnPayload is a zeek.conn payload exactly as PostgreSQL rendered it
// (payload::text) on a beta.7 appliance, with spaces after ':' and ','.
const storedConnPayload = `{"ts": 1790900985.864005, "uid": "CQwaNO2wZCkzW2Eted", "_path": "conn", "proto": "tcp", "history": "R", "ip_proto": 6, "id.orig_h": "192.168.10.201", "id.orig_p": 38320, "id.resp_h": "13.33.52.208", "id.resp_p": 443, "orig_pkts": 1, "resp_pkts": 0, "conn_state": "OTH", "local_orig": true, "local_resp": false, "community_id": "1:/SDanSlUikVABZEdrAHT1ZrQWbk=", "missed_bytes": 0, "orig_l2_addr": "72:58:49:e8:e4:00", "resp_l2_addr": "bc:24:11:43:c2:5e", "orig_ip_bytes": 52, "resp_ip_bytes": 0}`

// storedHTTPPayload has the characters encoding/json escapes inside a
// response (<, > and &), which also change the payload's length.
const storedHTTPPayload = `{"ts": 1790901000.1, "uid": "C1", "uri": "/generate_204?a=1&b=<x>", "host": "connectivitycheck.grapheneos.network", "_path": "http", "method": "GET"}`

// serveEventDetail answers like ingestd and control-api (json.NewEncoder).
func serveEventDetail(t *testing.T, detail EventDetail) *QueryClient {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(detail)
	}))
	t.Cleanup(server.Close)
	client, err := NewQueryClient(server.URL, []byte(strings.Repeat("t", 32)), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func sameJSON(t *testing.T, a, b []byte) bool {
	t.Helper()
	var left, right any
	if err := json.Unmarshal(a, &left); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &right); err != nil {
		t.Fatal(err)
	}
	return reflect.DeepEqual(left, right)
}

// Every event detail failed with "event detail service returned an invalid or
// oversized response": payload_bytes counted PostgreSQL's spaced jsonb text,
// but the response carries the payload compacted (and HTML-escaped).
func TestEventDetailSurvivesTheWireForStoredPayloads(t *testing.T) {
	event := RecentEvent{RecordID: strings.Repeat("1f", 32), Source: SourceZeek, Kind: "zeek.conn", OccurredAt: time.Unix(1790900985, 0).UTC()}
	for name, stored := range map[string]string{"conn": storedConnPayload, "http": storedHTTPPayload} {
		t.Run(name, func(t *testing.T) {
			detail, err := newEventDetail(event, []byte(stored))
			if err != nil {
				t.Fatal(err)
			}
			got, err := serveEventDetail(t, detail).GetEventDetail(context.Background(), event.RecordID)
			if err != nil {
				t.Fatalf("event detail was rejected: %v", err)
			}
			if got.PayloadBytes != len(got.Payload) || !sameJSON(t, got.Payload, []byte(stored)) {
				t.Fatalf("payload changed: bytes=%d payload=%s", got.PayloadBytes, got.Payload)
			}
		})
	}
}

func TestEventDetailWithStoredTextLengthIsRejected(t *testing.T) {
	// The detail as beta.7 built it; this documents why the fix is needed.
	event := RecentEvent{RecordID: strings.Repeat("1f", 32), Source: SourceZeek, Kind: "zeek.conn"}
	old := EventDetail{Schema: EventDetailSchemaVersion, Event: event, Payload: json.RawMessage(storedConnPayload), PayloadBytes: len(storedConnPayload)}
	if _, err := serveEventDetail(t, old).GetEventDetail(context.Background(), event.RecordID); err == nil {
		t.Fatal("a payload_bytes that does not match the sent payload was accepted")
	}
}

func TestNewEventDetailRejectsInvalidStoredPayloads(t *testing.T) {
	event := RecentEvent{RecordID: strings.Repeat("1f", 32)}
	for _, stored := range []string{"", "{", strings.Repeat(" ", 4)} {
		if _, err := newEventDetail(event, []byte(stored)); err == nil {
			t.Fatalf("stored payload %q was accepted", stored)
		}
	}
}
