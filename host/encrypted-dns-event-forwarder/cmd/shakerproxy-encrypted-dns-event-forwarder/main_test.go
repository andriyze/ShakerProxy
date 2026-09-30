package main

import (
	"encoding/json"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/cloudconnector"
)

func TestParseLineProjectsBlockedEncryptedDNSMetadata(t *testing.T) {
	now := time.Date(2026, 9, 3, 14, 0, 0, 0, time.UTC)
	event, ok := parseLine("kernel: SHAKERPROXY_EDNS_DOT IN=lab0 OUT=eth0 SRC=10.44.0.15 DST=1.1.1.1 PROTO=TCP SPT=50123 DPT=853", now)
	if !ok || event.Type != cloudconnector.MetadataDNSEvent || !event.ObservedAt.Equal(now) {
		t.Fatalf("encrypted DNS log was not projected: %#v %t", event, ok)
	}
	var payload map[string]any
	if err := json.Unmarshal(event.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["client_ip"] != "10.44.0.15" || payload["resolver_ip"] != "1.1.1.1" || payload["transport"] != "dot" || payload["query_name"] != "encrypted-query" || payload["blocked"] != true {
		t.Fatalf("unexpected encrypted DNS payload: %#v", payload)
	}
}

func TestParseLineRejectsUnclassifiedOrAddresslessLogs(t *testing.T) {
	for _, line := range []string{
		"kernel: ordinary packet SRC=10.44.0.15 DST=1.1.1.1",
		"kernel: SHAKERPROXY_EDNS_DOQ SRC=not-an-ip DST=1.1.1.1",
	} {
		if _, ok := parseLine(line, time.Now().UTC()); ok {
			t.Fatalf("unsafe kernel log was accepted: %s", line)
		}
	}
}
