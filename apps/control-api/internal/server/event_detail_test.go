package server

import (
	"encoding/json"
	"testing"
)

func TestMetadataOnlyEventPayloadDropsPlaintextAndQueryBearingURL(t *testing.T) {
	raw := json.RawMessage(`{
		"hostname":"api.example.test",
		"http_method":"POST",
		"http_path":"/v1/login",
		"http_status":200,
		"http_url":"https://api.example.test/v1/login?token=secret",
		"request_headers":{"items":[{"name":"Authorization","value":"Bearer secret"}]},
		"request_body":{"preview":"password=secret"},
		"response_headers":{"items":[{"name":"Set-Cookie","value":"sid=secret"}]},
		"response_body":{"preview":"private response"},
		"content_local_only":true
	}`)

	projected, err := metadataOnlyEventPayload(raw)
	if err != nil {
		t.Fatalf("metadata projection failed: %v", err)
	}
	var value map[string]json.RawMessage
	if err := json.Unmarshal(projected, &value); err != nil {
		t.Fatalf("decode projection: %v", err)
	}
	for _, forbidden := range []string{"http_url", "request_headers", "request_body", "response_headers", "response_body"} {
		if _, ok := value[forbidden]; ok {
			t.Fatalf("sensitive field %q survived API-token metadata projection: %s", forbidden, projected)
		}
	}
	for _, required := range []string{"hostname", "http_method", "http_path", "http_status", "content_local_only"} {
		if _, ok := value[required]; !ok {
			t.Fatalf("safe metadata field %q was removed: %s", required, projected)
		}
	}
	if len(projected) >= len(raw) {
		t.Fatalf("metadata projection did not reduce payload: raw=%d projected=%d", len(raw), len(projected))
	}
}

func TestMetadataOnlyEventPayloadKeepsTLSAndDNSInvestigationEvidence(t *testing.T) {
	raw := json.RawMessage(`{
		"sni":"pinned.example.test",
		"classification":"probable_pinning_or_custom_trust",
		"failure_count":4,
		"pinning_threshold":3,
		"client_has_recent_successful_interception":true,
		"dynamic_bypass_added":true,
		"upstream_certificate_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"query_name":"resolver.example.test",
		"query_type":"A",
		"resolver_provider":"Example Resolver",
		"blocked":false
	}`)
	projected, err := metadataOnlyEventPayload(raw)
	if err != nil {
		t.Fatalf("metadata projection failed: %v", err)
	}
	var value map[string]json.RawMessage
	if err := json.Unmarshal(projected, &value); err != nil {
		t.Fatalf("decode projection: %v", err)
	}
	for _, required := range []string{"sni", "classification", "failure_count", "pinning_threshold", "client_has_recent_successful_interception", "dynamic_bypass_added", "upstream_certificate_sha256", "query_name", "query_type", "resolver_provider", "blocked"} {
		if _, ok := value[required]; !ok {
			t.Fatalf("investigation field %q was removed: %s", required, projected)
		}
	}
}
