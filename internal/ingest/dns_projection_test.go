package ingest

import (
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
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
	if got := ProjectDNSFields(nondns); !reflect.DeepEqual(got, DNSProjection{}) {
		t.Fatalf("port/payload-like non-DNS event was mislabeled: %#v", got)
	}
}

// Real answer shapes from the test VM: the DNS forwarder's answer objects,
// Zeek's answer strings, and Suricata EVE v3 answers and grouped answers.
func TestProjectDNSFieldsKeepsTheAnswers(t *testing.T) {
	cases := []struct {
		name     string
		envelope Envelope
		want     []string
	}{
		{"forwarder", Envelope{Source: SourceHost, Kind: "shakerproxy.dns", Payload: json.RawMessage(`{"query":"www.gstatic.com","query_type":"A","response_code":"NOERROR","answer_count":3,"answers":[{"name":"www.gstatic.com","type":"CNAME","ttl":60,"data":"gstatic.l.Google.com."},{"name":"gstatic.l.google.com","type":"A","ttl":220,"data":"192.178.194.94"},{"name":"x","type":"TXT","ttl":1,"data":"v=spf1 include:example"}]}`)}, []string{"gstatic.l.google.com", "192.178.194.94"}},
		{"zeek", Envelope{Source: SourceZeek, Kind: "zeek.dns", Payload: json.RawMessage(`{"query":"maps.google.com","qtype_name":"AAAA","rcode_name":"NOERROR","answers":["2A00:1450:4001:80b::200e","2a00:1450:4001:80b::200e"]}`)}, []string{"2a00:1450:4001:80b::200e"}},
		{"suricata answers", Envelope{Source: SourceSuricata, Kind: "suricata.dns", Payload: json.RawMessage(`{"dns":{"type":"response","rrname":"fonts.gstatic.com","rrtype":"A","rcode":"NOERROR","answers":[{"ttl":50,"rdata":"192.178.194.94","rrname":"fonts.gstatic.com","rrtype":"A"}],"grouped":{"A":["10.0.0.1"]}}}`)}, []string{"192.178.194.94"}},
		{"suricata grouped", Envelope{Source: SourceSuricata, Kind: "suricata.dns", Payload: json.RawMessage(`{"dns":{"type":"answer","rrname":"a.example","rrtype":"A","rcode":"NOERROR","grouped":{"A":["192.0.2.1","192.0.2.2"],"CNAME":["edge.example."]}}}`)}, []string{"edge.example", "192.0.2.1", "192.0.2.2"}},
		{"no answers", Envelope{Source: SourceZeek, Kind: "zeek.dns", Payload: json.RawMessage(`{"query":"missing.example","qtype_name":"A","rcode_name":"NXDOMAIN","answers":[]}`)}, nil},
	}
	for _, test := range cases {
		if got := ProjectDNSFields(test.envelope).Answers; !reflect.DeepEqual(got, test.want) {
			t.Errorf("%s: answers = %q, want %q", test.name, got, test.want)
		}
	}
}

func TestDNSAnswersAreBoundedAndValidated(t *testing.T) {
	answers := []any{}
	for index := 0; index < 20; index++ {
		answers = append(answers, "192.0.2."+strconv.Itoa(index+1))
	}
	answers = append(answers, "bad\nvalue", strings.Repeat("a", 300), 42)
	got := dnsAnswers(answers, "")
	if len(got) != MaxDNSAnswers || got[0] != "192.0.2.1" {
		t.Fatalf("answers = %q, want the first %d", got, MaxDNSAnswers)
	}
	if !validEventDNSAnswers(got) || validEventDNSAnswers(append(got, "192.0.2.250")) || validEventDNSAnswers([]string{"Upper.Example"}) || validEventDNSAnswers([]string{"a b"}) || validEventDNSAnswers([]string{""}) {
		t.Fatal("stored answer validation is wrong")
	}
}

func TestProjectDNSFieldsRejectsInjectionAndBounds(t *testing.T) {
	event := Envelope{Source: SourceZeek, Kind: "zeek.dns", Payload: json.RawMessage(`{"query":"evil.example\nforged","qtype_name":"A\nHELP","rcode_name":"NOERROR","answers":[]}`)}
	got := ProjectDNSFields(event)
	if got.Query != "" || got.RecordType != "" || got.ResponseCode != "NOERROR" {
		t.Fatalf("unsafe DNS text escaped projection: %#v", got)
	}
}
