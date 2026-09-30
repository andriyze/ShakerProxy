package agentapi

import (
	"os"
	"strings"
	"testing"
)

func TestSystemOverviewOpenAPIContractIsBoundedAndErrorMinimized(t *testing.T) {
	contents, err := os.ReadFile("../../schemas/api/agent-system-overview.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	contract := string(contents)
	for _, required := range []string{
		"/agent/system-overview:",
		"operationId: getAgentSystemOverview",
		"Requires system:read",
		"overall: {type: string, enum: [READY, DEGRADED, UNAVAILABLE]}",
		"evidence_ready:",
		"maxItems: 16",
		"minItems: 2",
		"maxItems: 2",
		"const: ZEEK",
		"const: SURICATA",
		"maxItems: 7",
	} {
		if !strings.Contains(contract, required) {
			t.Fatalf("system overview contract is missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"last_error:",
		"error_message:",
		"diagnostics:",
		"filesystem:",
		"packet:",
		"request_body:",
		"response_body:",
		"private_key:",
		"password:",
	} {
		if strings.Contains(strings.ToLower(contract), forbidden) {
			t.Fatalf("system overview contract exposes forbidden property %q", forbidden)
		}
	}
}
