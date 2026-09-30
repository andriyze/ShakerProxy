package ingest

import (
	"strings"
	"testing"
)

func TestPlainLanguageProjectionValidation(t *testing.T) {
	valid := RecentEvent{
		Source: SourceMitmproxy, Kind: "http_response",
		AppProtocol: "tls", ProtocolCategory: "web", ProtocolVisibility: "DECRYPTED", ProtocolEvidence: "ANALYZER",
		HTTPMethod: "GET", HTTPHost: "api.example.com", HTTPPath: "/v1/status", HTTPStatus: 200,
		Summary: "GET api.example.com/v1/status → 200",
	}
	if !validProtocolProjection(valid) || !validEventHTTPColumns(valid) || !validEventAlert(valid) || !validEventSummary(valid.Summary) {
		t.Fatalf("valid plain-language projection was rejected: %#v", valid)
	}
	// A stored classification stays valid when the catalog later changes.
	evolved := valid
	evolved.AppProtocol, evolved.ProtocolCategory, evolved.ProtocolExotic = "future-protocol", "future-category", true
	if !validProtocolProjection(evolved) {
		t.Fatal("classification from an older or newer catalog was rejected")
	}
	for name, mutate := range map[string]func(*RecentEvent){
		"visibility":       func(event *RecentEvent) { event.ProtocolVisibility = "SOMEWHAT" },
		"evidence":         func(event *RecentEvent) { event.ProtocolEvidence = "GUESS" },
		"category missing": func(event *RecentEvent) { event.ProtocolCategory = "" },
		"orphan category": func(event *RecentEvent) {
			event.AppProtocol, event.ProtocolVisibility, event.ProtocolEvidence = "", "", ""
		},
		"protocol id": func(event *RecentEvent) { event.AppProtocol = "TLS; DROP" },
	} {
		event := valid
		mutate(&event)
		if validProtocolProjection(event) {
			t.Fatalf("%s: invalid protocol projection accepted: %#v", name, event)
		}
	}
	for name, mutate := range map[string]func(*RecentEvent){
		"query string": func(event *RecentEvent) { event.HTTPPath = "/v1/status?token=secret" },
		"long path":    func(event *RecentEvent) { event.HTTPPath = "/" + strings.Repeat("a", MaxEventHTTPPathBytes) },
		"host":         func(event *RecentEvent) { event.HTTPHost = "API.Example.com" },
		"method":       func(event *RecentEvent) { event.HTTPMethod = "GET\nX" },
		"status":       func(event *RecentEvent) { event.HTTPStatus = 700 },
	} {
		event := valid
		mutate(&event)
		if validEventHTTPColumns(event) {
			t.Fatalf("%s: invalid HTTP columns accepted: %#v", name, event)
		}
	}
	if validEventAlert(RecentEvent{AlertSignature: "two\nlines"}) || validEventAlert(RecentEvent{AlertSeverity: 9}) {
		t.Fatal("invalid alert projection accepted")
	}
	if validEventSummary("line\nbreak") || validEventSummary(strings.Repeat("x", MaxEventSummaryRunes+1)) || validEventSummary(" padded") {
		t.Fatal("invalid summary accepted")
	}
}
