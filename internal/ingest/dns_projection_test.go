package ingest

import (
	"encoding/json"
	"testing"
)

func TestProjectDNSFieldsUsesOnlyKnownDNSSchemas(t *testing.T) {
	zeek := Envelope{Source: SourceZeek, Kind: "zeek.dns", Payload: json.RawMessage(`{"query":"Example.COM.","qtype_name":"a","rcode_name":"noerror","answers":["192.0.2.1"]}`)}
	if got := ProjectDNSFields(zeek); got.Query != "example.com" || got.RecordType != "A" || got.ResponseCode != "NOERROR" || got.AnswerCount == nil || *got.AnswerCount != 1 {
		t.Fatalf("unexpected Zeek DNS projection: %#v", got)
	}
	suricata := Envelope{Source: SourceSuricata, Kind: "suricata.dns", Payload: json.RawMessage(`{"dns":{"type":"answer","rrname":"device.lab.","rrtype":"aaaa","rcode":"nxdomain","answers":[]}}`)}
	if got := ProjectDNSFields(suricata); got.Query != "device.lab" || got.RecordType != "AAAA" || got.ResponseCode != "NXDOMAIN" || got.AnswerCount == nil || *got.AnswerCount != 0 {
		t.Fatalf("unexpected Suricata DNS projection: %#v", got)
	}
	nondns := suricata
	nondns.Kind = "suricata.flow"
	if got := ProjectDNSFields(nondns); got != (DNSProjection{}) {
		t.Fatalf("port/payload-like non-DNS event was mislabeled: %#v", got)
	}
}

func TestProjectDNSFieldsRejectsInjectionAndBounds(t *testing.T) {
	event := Envelope{Source: SourceZeek, Kind: "zeek.dns", Payload: json.RawMessage(`{"query":"evil.example\nforged","qtype_name":"A\nHELP","rcode_name":"NOERROR","answers":[]}`)}
	got := ProjectDNSFields(event)
	if got.Query != "" || got.RecordType != "" || got.ResponseCode != "NOERROR" {
		t.Fatalf("unsafe DNS text escaped projection: %#v", got)
	}
}
