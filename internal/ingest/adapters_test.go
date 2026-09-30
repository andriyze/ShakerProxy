package ingest

import "testing"

func TestNormalizeZeekJSONCreatesDeterministicEnvelope(t *testing.T) {
	raw := []byte(`{"ts":1788278400.123456,"uid":"Cabc123","id.orig_h":"10.77.0.111","id.orig_p":51234,"id.resp_h":"1.1.1.1","id.resp_p":443,"proto":"tcp","_path":"conn"}`)
	event, err := NormalizeZeekJSON(raw, "7.2.2", "capture-0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	if event.Source != SourceZeek || event.Kind != "zeek.conn" || event.FlowID != "flow-zeek-Cabc123" || event.ParserVersion != ZeekParserVersion || event.OccurredAt.Unix() != 1788278400 {
		t.Fatalf("unexpected Zeek envelope: %#v", event)
	}
	again, err := NormalizeZeekJSON(raw, "7.2.2", "capture-0123456789abcdef0123456789abcdef")
	if err != nil || again.EventID != event.EventID {
		t.Fatal("Zeek normalization is not deterministic")
	}
}

func TestNormalizeSuricataEVEHandlesNativeTimestampAndFlow(t *testing.T) {
	raw := []byte(`{"timestamp":"2026-09-01T12:00:00.123456+0000","flow_id":123456789,"event_type":"alert","src_ip":"10.77.0.111","dest_ip":"1.1.1.1","alert":{"severity":1}}`)
	event, err := NormalizeSuricataEVE(raw, "7.0.10", "")
	if err != nil {
		t.Fatal(err)
	}
	if event.Source != SourceSuricata || event.Kind != "suricata.alert" || event.FlowID != "flow-suricata-123456789" || event.ParserVersion != SuricataParserVersion {
		t.Fatalf("unexpected Suricata envelope: %#v", event)
	}
}

func TestAdaptersRejectMissingRequiredFieldsAndUnsafeCaptureID(t *testing.T) {
	if _, err := NormalizeZeekJSON([]byte(`{"_path":"conn"}`), "7.2.2", ""); err == nil {
		t.Fatal("Zeek event without timestamp was accepted")
	}
	if _, err := NormalizeSuricataEVE([]byte(`{"timestamp":"2026-09-01T12:00:00Z","event_type":"alert"}`), "7.0.10", "../../capture"); err == nil {
		t.Fatal("unsafe capture session ID was accepted")
	}
}
