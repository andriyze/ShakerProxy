package agentapi

import (
	"encoding/json"
	"testing"
)

func TestValidateMetadataOnlyPayloadAcceptsBoundedInvestigationMetadata(t *testing.T) {
	payload := json.RawMessage(`{"http_method":"GET","http_url":"https://api.example.test/v1/profile","http_path":"/v1/profile","http_status":200,"tls_version":"TLSv1.3","upstream_certificate_subject":"CN=api.example.test","dns_query":"example.test"}`)
	if err := validateMetadataOnlyPayload(payload); err != nil {
		t.Fatalf("safe metadata was rejected: %v", err)
	}
}

func TestValidateMetadataOnlyPayloadRejectsPlaintextSecretsAndQueryURLs(t *testing.T) {
	for name, payload := range map[string]string{
		"request body":       `{"request_body":{"preview":"password=secret"}}`,
		"nested headers":     `{"nested":{"response_headers":{"items":[]}}}`,
		"authorization":      `{"Authorization":"Bearer secret"}`,
		"query-bearing URL":  `{"http_url":"https://api.example.test/path?token=secret"}`,
		"credential-bearing": `{"http_url":"https://user:pass@api.example.test/path"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateMetadataOnlyPayload(json.RawMessage(payload)); err == nil {
				t.Fatal("unsafe metadata payload was accepted")
			}
		})
	}
}
