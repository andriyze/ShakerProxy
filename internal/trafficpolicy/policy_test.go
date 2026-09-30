package trafficpolicy

import (
	"strings"
	"testing"
	"time"
)

func TestNormalizeAndDigestAreDeterministic(t *testing.T) {
	policy := DefaultPolicy()
	policy.Revision = 2
	policy.Name = "  Lab policy  "
	policy.EncryptedDNS.Mode = EncryptedDNSEnforceLocal
	policy.EncryptedDNS.RedirectPlainDNS = true
	policy.EncryptedDNS.BlockDoT = true
	policy.EncryptedDNS.BlockDoQ = true
	policy.EncryptedDNS.BlockKnownDoH = true
	policy.EncryptedDNS.UpstreamServers = []string{"8.8.8.8:53", "1.1.1.1:53", "8.8.8.8:53"}
	policy.TLS.Enabled = true
	policy.TLS.ExcludeHosts = []string{"*.Example.com", "api.example.com", "*.example.com"}
	policy.TLS.ExcludeCIDRs = []string{"10.0.0.8/24"}

	normalized, err := Normalize(policy)
	if err != nil {
		t.Fatal(err)
	}
	if normalized.Name != "Lab policy" || len(normalized.EncryptedDNS.UpstreamServers) != 2 || normalized.TLS.ExcludeCIDRs[0] != "10.0.0.0/24" {
		t.Fatalf("unexpected normalization: %#v", normalized)
	}
	first, err := Digest(policy)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Digest(normalized)
	if err != nil || first != second {
		t.Fatalf("digest changed after normalization: %q %q %v", first, second, err)
	}
}

func TestEnforceLocalRequiresRedirectAndUpstream(t *testing.T) {
	policy := DefaultPolicy()
	policy.EncryptedDNS.Mode = EncryptedDNSEnforceLocal
	if err := Validate(policy); err == nil {
		t.Fatal("ENFORCE_LOCAL without redirect/upstream was accepted")
	}
}

func TestMobilePinningScopeAcceptsOnlyCanonicalMobileIPv4(t *testing.T) {
	policy := DefaultPolicy()
	policy.TLS.MobileClients = []TLSMobileClient{{CIDR: "10.44.0.15/24", Platform: " iOS "}}
	normalized, err := Normalize(policy)
	if err != nil {
		t.Fatal(err)
	}
	if len(normalized.TLS.MobileClients) != 1 || normalized.TLS.MobileClients[0].CIDR != "10.44.0.0/24" || normalized.TLS.MobileClients[0].Platform != "ios" {
		t.Fatalf("unexpected mobile client normalization: %#v", normalized.TLS.MobileClients)
	}
	policy.TLS.MobileClients = []TLSMobileClient{{CIDR: "10.44.0.0/24", Platform: "windows"}}
	if _, err := Normalize(policy); err == nil {
		t.Fatal("non-mobile automatic pinning scope was accepted")
	}
	policy.TLS.MobileClients = []TLSMobileClient{{CIDR: "fd44::/64", Platform: "ios"}}
	if _, err := Normalize(policy); err == nil {
		t.Fatal("unqualified IPv6 mobile scope was accepted")
	}
}

func TestCatalogClassifiesKnownResolverAndPort(t *testing.T) {
	classification := Classify("1.1.1.1", "cloudflare-dns.com", 443, false, "/dns-query")
	if !classification.Detected || classification.Transport != TransportDoH || classification.Confidence != 100 || !classification.BlockSafe {
		t.Fatalf("unexpected DoH classification: %#v", classification)
	}
	classification = Classify("203.0.113.9", "", 853, true, "")
	if !classification.Detected || classification.Transport != TransportDoQ {
		t.Fatalf("unexpected DoQ classification: %#v", classification)
	}
}

func TestRenderFirewallOrdersBypassesBeforeTLSRedirect(t *testing.T) {
	policy := DefaultPolicy()
	policy.Revision = 2
	policy.Name = "Enforcement"
	policy.EncryptedDNS.Mode = EncryptedDNSEnforceLocal
	policy.EncryptedDNS.RedirectPlainDNS = true
	policy.EncryptedDNS.UpstreamServers = []string{"1.1.1.1:53"}
	policy.EncryptedDNS.BlockDoT = true
	policy.EncryptedDNS.BlockDoQ = true
	policy.EncryptedDNS.BlockKnownDoH = true
	policy.TLS.Enabled = true
	policy.TLS.ExcludeCIDRs = []string{"192.0.2.0/24"}

	rules, err := RenderFirewall(policy, RenderContext{LabInterface: "lab0", LabCIDR: "10.77.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(rules.NATRules, "\n")
	redirect := strings.Index(joined, "--dport 443 -j REDIRECT")
	bypass := strings.Index(joined, "-d 192.0.2.0/24")
	resolverBypass := strings.Index(joined, "-d 1.1.1.1")
	if redirect < 0 || bypass < 0 || resolverBypass < 0 || bypass > redirect || resolverBypass > redirect {
		t.Fatalf("TLS redirect ordering is unsafe:\n%s", joined)
	}
	if !rules.NeedsDNSService || !rules.NeedsMITMService || !rules.NeedsInputHook || !rules.NeedsNATHook {
		t.Fatalf("missing runtime requirements: %#v", rules)
	}
	filter := strings.Join(rules.FilterRules, "\n")
	for _, prefix := range []string{"SHAKERPROXY_EDNS_DOT ", "SHAKERPROXY_EDNS_DOQ ", "SHAKERPROXY_EDNS_DOH_TCP "} {
		if !strings.Contains(filter, `--limit 10/second --limit-burst 20 -j LOG --log-prefix "`+prefix+`"`) {
			t.Fatalf("encrypted DNS block lacks bounded metadata logging for %q:\n%s", prefix, filter)
		}
	}
}

func TestStoreApplyAndRollbackUseMonotonicRevisions(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	store := Store{Path: t.TempDir() + "/policy.json", Now: func() time.Time { return now }}
	first := DefaultPolicy()
	first.Revision = 1
	if _, err := store.Apply(first, 0); err != nil {
		t.Fatal(err)
	}
	second := first
	second.Revision = 2
	second.Name = "Blocking"
	second.EncryptedDNS.Mode = EncryptedDNSBlockKnown
	second.EncryptedDNS.BlockDoT = true
	if _, err := store.Apply(second, 1); err != nil {
		t.Fatal(err)
	}
	rolledBack, err := store.Rollback(2)
	if err != nil {
		t.Fatal(err)
	}
	if rolledBack.Policy.Revision != 3 || rolledBack.Policy.Name != first.Name {
		t.Fatalf("unexpected rollback document: %#v", rolledBack)
	}
}
