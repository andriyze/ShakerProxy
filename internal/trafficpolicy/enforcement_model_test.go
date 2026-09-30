package trafficpolicy

import (
	"strings"
	"testing"
	"time"
)

func validEnforcementDocument() EnforcementDocument {
	return EnforcementDocument{
		SchemaVersion: SchemaVersion,
		Enabled:       true,
		EncryptedDNS: EnforcementDNSPolicy{
			Mode:             "BLOCK",
			RedirectPlainDNS: true,
			BlockDoT:         true,
			FailMode:         "PASSTHROUGH",
		},
		TLS: TLSInterceptionPolicy{Mode: "OFF", FailMode: "PASSTHROUGH", PinningThreshold: 3},
		Resolvers: []ResolverPolicyTarget{{
			Provider: " Test resolver ", Hostnames: []string{"DNS.Example.NET.", "dns.example.net"},
			IPv4: []string{"192.0.2.53"}, Transports: []string{"DOH", "doh"}, Dedicated: true, SafeToBlockByIP: true,
		}},
	}
}

func TestEnforcementDocumentNormalizesAndDigestsDeterministically(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	document := validEnforcementDocument()
	if err := document.NormalizeAndValidate(now); err != nil {
		t.Fatal(err)
	}
	if document.EncryptedDNS.Mode != "block" || document.EncryptedDNS.FailMode != "passthrough" || document.TLS.Mode != "off" || len(document.Resolvers[0].Hostnames) != 1 || document.Resolvers[0].Hostnames[0] != "dns.example.net" {
		t.Fatalf("enforcement document was not normalized: %+v", document)
	}
	first, err := document.Digest()
	if err != nil {
		t.Fatal(err)
	}
	second := document
	second.Resolvers[0].Transports = []string{"doh", "DOH"}
	if err := second.NormalizeAndValidate(now); err != nil {
		t.Fatal(err)
	}
	secondDigest, err := second.Digest()
	if err != nil || first != secondDigest {
		t.Fatalf("equivalent policy changed digest: %q %q %v", first, secondDigest, err)
	}
}

func TestApplyRequestValidatesDigestScopeAndListenerOwnership(t *testing.T) {
	document := validEnforcementDocument()
	if err := document.NormalizeAndValidate(time.Now()); err != nil {
		t.Fatal(err)
	}
	digest, err := document.Digest()
	if err != nil {
		t.Fatal(err)
	}
	request := ApplyRequest{
		PolicyID: "policy-1", Revision: 1, Digest: digest, Policy: document,
		Runtime: Runtime{TestInterfaces: []string{"lab0"}, ScopeIPv4: []string{"10.77.0.9/24"}, LocalDNSPort: 1053},
	}
	if err := request.NormalizeAndValidate(time.Now()); err != nil {
		t.Fatal(err)
	}
	if request.Runtime.ScopeIPv4[0] != "10.77.0.0/24" {
		t.Fatalf("runtime scope was not canonicalized: %+v", request.Runtime)
	}

	badDigest := request
	badDigest.Digest = strings.Repeat("0", 64)
	if err := badDigest.NormalizeAndValidate(time.Now()); err == nil {
		t.Fatal("mismatched enforcement digest was accepted")
	}
	badInterface := request
	badInterface.Runtime.TestInterfaces = []string{"lab0;reboot"}
	if err := badInterface.NormalizeAndValidate(time.Now()); err == nil {
		t.Fatal("injected interface name was accepted")
	}
	sharedAddress := validEnforcementDocument()
	sharedAddress.Resolvers[0].Dedicated = false
	if err := sharedAddress.NormalizeAndValidate(time.Now()); err == nil {
		t.Fatal("shared resolver address was declared safe for IP blocking")
	}
}
