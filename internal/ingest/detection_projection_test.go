package ingest

import (
	"testing"
	"time"
)

func TestDetectionProjectionIsBoundedAndSchemaSpecific(t *testing.T) {
	at := time.Unix(1_700_000_000, 0).UTC()
	event := Envelope{Schema: 1, EventID: "detection-1234567890abcdef", Source: SourceHost, Kind: "shakerproxy.detection.rogue_dhcp", OccurredAt: at, SourceVersion: "native-v1", ParserVersion: "native-v1", Payload: []byte(`{"schema":1,"id":"detection-1234567890abcdef","type":"ROGUE_DHCP","severity":"HIGH","state":"OPEN","summary":"Unapproved DHCP server response observed on the lab segment","scope":"lab0/vlan=20/aa:bb:cc:dd:ee:ff","first_seen_at":"2023-11-14T22:13:20Z","last_seen_at":"2023-11-14T22:13:20Z","revision":1}`)}
	got := ProjectDetectionFields(event)
	if got.Type != "ROGUE_DHCP" || got.Severity != "HIGH" || got.State != "OPEN" || got.Scope != "lab0/vlan=20/aa:bb:cc:dd:ee:ff" {
		t.Fatalf("unexpected detection projection: %#v", got)
	}
	event.Payload = []byte(`{"schema":1,"id":"detection-1234567890abcdef","type":"MADE_UP","severity":"HIGH","state":"OPEN","summary":"unsafe","scope":"lab0","first_seen_at":"2023-11-14T22:13:20Z","last_seen_at":"2023-11-14T22:13:20Z","revision":1}`)
	if got := ProjectDetectionFields(event); got != (DetectionProjection{}) {
		t.Fatalf("unknown detection escaped projection: %#v", got)
	}
}
