package trafficpolicy

import (
	"strings"
	"testing"
	"time"
)

// Audit #15: Fleet blocks use reject and were never logged. The log rule must
// be separate from the block so rate limiting never stops blocking.
func TestFleetEncryptedDNSBlocksAreLoggedWithoutRateLimitingTheBlock(t *testing.T) {
	document := EnforcementDocument{
		SchemaVersion: SchemaVersion,
		Enabled:       true,
		EncryptedDNS:  EnforcementDNSPolicy{Mode: "strict", BlockDoT: true, BlockDoQ: true, BlockKnownDoH: true, BlockQUICForScope: true},
		TLS:           TLSInterceptionPolicy{Mode: "off"},
		Resolvers:     []ResolverPolicyTarget{{Provider: "Example", IPv4: []string{"192.0.2.53"}, Transports: []string{"doh"}, Dedicated: true, SafeToBlockByIP: true}},
	}
	digest, err := document.Digest()
	if err != nil {
		t.Fatal(err)
	}
	request := ApplyRequest{PolicyID: "fleet-1", Revision: 1, Digest: digest, Policy: document, Runtime: Runtime{TestInterfaces: []string{"lab0"}}}
	compiled, err := Compile(request, CompileOptions{TLSBackendAvailable: true}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	script := string(compiled.NFTables)
	lines := strings.Split(script, "\n")
	for _, prefix := range []string{"SHAKERPROXY_EDNS_DOT ", "SHAKERPROXY_EDNS_DOQ ", "SHAKERPROXY_EDNS_DOH_TCP ", "SHAKERPROXY_EDNS_DOH_UDP ", "SHAKERPROXY_EDNS_QUIC "} {
		found := false
		for index, line := range lines {
			if !strings.Contains(line, `log prefix "`+prefix+`"`) {
				continue
			}
			found = true
			if strings.Contains(line, "reject") || strings.Contains(line, " drop") || index+1 >= len(lines) || !strings.Contains(lines[index+1], "reject") {
				t.Fatalf("log rule for %q must precede, not replace, its block:\n%s", prefix, script)
			}
		}
		if !found {
			t.Fatalf("no log rule for %q:\n%s", prefix, script)
		}
	}
	for _, line := range lines {
		if strings.Contains(line, "reject") && strings.Contains(line, "limit rate") {
			t.Fatalf("blocking rule is rate limited: %s", line)
		}
	}
	if again := string(InstrumentDetectionLogs(compiled.NFTables)); again != script {
		t.Fatal("instrumenting twice added duplicate log rules")
	}
}
