package ingest

import (
	"encoding/json"
	"testing"
)

func TestProjectTLSFieldsSurfacesTrustAndProbablePinning(t *testing.T) {
	success := Envelope{Source: SourceMitmproxy, Kind: "tls_intercepted", Payload: json.RawMessage(`{"sni":"API.Example.Test.","decrypted":true}`)}
	if got := ProjectTLSFields(success); got.InterceptionState != "INTERCEPTED" || got.ServerName != "api.example.test" || got.PinningSuspected || got.ClientRecentSuccess != nil {
		t.Fatalf("unexpected successful TLS projection: %#v", got)
	}
	recent := true
	failure := Envelope{Source: SourceMitmproxy, Kind: "tls_interception_failed", Payload: json.RawMessage(`{"sni":"pinned.example.test","reason":"probable_certificate_pinning_or_custom_trust_store","client_has_recent_successful_interception":true,"dynamic_bypass_added":true,"platform":"android-tv"}`)}
	got := ProjectTLSFields(failure)
	if got.InterceptionState != "FAILED" || got.ServerName != "pinned.example.test" || got.FailureReason != "probable_certificate_pinning_or_custom_trust_store" || !got.PinningSuspected || !got.DynamicBypassActivated || got.ClientRecentSuccess == nil || *got.ClientRecentSuccess != recent || got.Platform != "android-tv" {
		t.Fatalf("unexpected failed TLS projection: %#v", got)
	}
}

func TestTLSProjectionValidationRejectsCrossSourceOrContradictoryClaims(t *testing.T) {
	valid := RecentEvent{Source: SourceMitmproxy, Kind: "tls_interception_failed", TLSServerName: "pinned.example.test", TLSInterceptionState: "FAILED", TLSFailureReason: "probable_certificate_pinning_or_custom_trust_store", TLSPinningSuspected: true}
	if !validTLSProjection(valid) {
		t.Fatal("valid probable-pinning projection was rejected")
	}
	forged := valid
	forged.Source = SourceZeek
	if validTLSProjection(forged) {
		t.Fatal("non-MITM source supplied a TLS interception claim")
	}
	forged = valid
	forged.TLSFailureReason = "ca_not_trusted_or_pinning"
	if validTLSProjection(forged) {
		t.Fatal("ambiguous failure was upgraded to probable pinning")
	}
}

func TestProjectTLSFieldsRejectsUntrustedOrUnrelatedValues(t *testing.T) {
	bad := Envelope{Source: SourceMitmproxy, Kind: "tls_interception_failed", Payload: json.RawMessage(`{"sni":"bad host\nheader","reason":"Bad Reason!","platform":"windows","client_has_recent_successful_interception":"yes","dynamic_bypass_added":true}`)}
	if got := ProjectTLSFields(bad); got != (TLSProjection{}) {
		t.Fatalf("invalid TLS payload was partially projected: %#v", got)
	}
	unrelated := Envelope{Source: SourceMitmproxy, Kind: "http_response", Payload: json.RawMessage(`{"sni":"api.example.test"}`)}
	if got := ProjectTLSFields(unrelated); got != (TLSProjection{}) {
		t.Fatalf("non-TLS outcome was projected: %#v", got)
	}
}
