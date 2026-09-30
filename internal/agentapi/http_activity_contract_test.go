package agentapi

import (
	"os"
	"strings"
	"testing"
)

func TestHTTPActivityOpenAPIContractMatchesBoundedAgentSurface(t *testing.T) {
	contents, err := os.ReadFile("../../schemas/api/agent-mcp.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	contract := string(contents)
	for _, required := range []string{
		"/agent/http-activity:",
		"operationId: listAgentHTTPActivity",
		"Requires traffic:read",
		"maximum: 100",
		"maxLength: 1024",
		"HTTPActivityPage:",
		"HTTPActivityEvent:",
		"metadata_incomplete: {type: boolean}",
		"url_truncated: {type: boolean}",
	} {
		if !strings.Contains(contract, required) {
			t.Fatalf("HTTP activity OpenAPI contract is missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"request_headers:",
		"response_headers:",
		"request_body:",
		"response_body:",
		"authorization:",
		"cookie:",
		"body_preview:",
		"full_url:",
		"include_plaintext:",
	} {
		if strings.Contains(strings.ToLower(contract), forbidden) {
			t.Fatalf("HTTP activity OpenAPI contract exposes forbidden property %q", forbidden)
		}
	}
}
