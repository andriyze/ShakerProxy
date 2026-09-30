package ingest

import (
	"strings"
	"testing"
)

const validEvent = `{"schema":1,"event_id":"zeek-event-00000001","source":"ZEEK","kind":"connection","occurred_at":"2026-09-01T12:00:00.123456789Z","source_version":"7.2.2","parser_version":"shakerproxy-zeek-v1","capture_session_id":"capture-0123456789abcdef0123456789abcdef","flow_id":"flow-00000000001","confidence":90,"payload":{"proto":"tcp","src_ip":"10.77.0.111"}}`

func TestDecodeEnvelopeAcceptsVersionedBoundedEvent(t *testing.T) {
	event, err := DecodeEnvelope([]byte(validEvent))
	if err != nil {
		t.Fatal(err)
	}
	if event.Source != SourceZeek || event.Kind != "connection" || string(event.Payload) != `{"proto":"tcp","src_ip":"10.77.0.111"}` {
		t.Fatalf("unexpected normalized event: %#v", event)
	}
}

func TestDecodeEnvelopeRejectsUnknownFieldsAndOversizedPayload(t *testing.T) {
	unknown := strings.Replace(validEvent, `"schema":1`, `"schema":1,"command":"rm"`, 1)
	if _, err := DecodeEnvelope([]byte(unknown)); err == nil {
		t.Fatal("unknown envelope field was accepted")
	}
	oversized := strings.Replace(validEvent, `{"proto":"tcp","src_ip":"10.77.0.111"}`, `"`+strings.Repeat("x", MaxPayloadBytes)+`"`, 1)
	if _, err := DecodeEnvelope([]byte(oversized)); err == nil {
		t.Fatal("oversized payload was accepted")
	}
}
