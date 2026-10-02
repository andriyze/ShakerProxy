package trafficpolicy

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

func singleArmLab() RenderContext {
	return RenderContext{LabInterface: "ens18", LabCIDR: "192.168.10.0/24", LabGatewayIPv4: "192.168.10.177", IPv6Listeners: true}
}

func TestTheDefaultForcesPlainDNSAndBlocksEncryptedDNS(t *testing.T) {
	policy := DefaultPolicy()
	if !policy.EncryptedDNS.ForcePlainDNS() || !policy.EncryptedDNS.BlockEncryptedDNS() || policy.EncryptedDNS.EffectiveMode() != EncryptedDNSEnforceLocal {
		t.Fatalf("default DNS policy = %+v", policy.EncryptedDNS)
	}
	// Without upstream servers the forwarder uses the host's resolvers.
	if _, err := Normalize(policy); err != nil {
		t.Fatalf("default policy is invalid: %v", err)
	}
	if NeedsLabContext(policy) {
		t.Fatal("the DNS switches must not require a confirmed lab")
	}
	// Nothing is installed for clients until a lab is confirmed.
	baseline := mustRender(t, policy, RenderContext{})
	if len(baseline.NATRules) != 0 || len(baseline.NATRulesIPv6) != 0 || HasRuleForChain(baseline.FilterRules, "SHAKERPROXY-FORWARD") {
		t.Fatalf("default policy installed client rules without a lab: %+v", baseline)
	}
}

func TestBlockingEncryptedDNSRejectsDoTDoQAndKnownDoHButAnswersPlainDNS(t *testing.T) {
	rules := mustRender(t, DefaultPolicy(), singleArmLab())
	filter := strings.Join(rules.FilterRules, "\n")
	for _, want := range []string{
		"-A SHAKERPROXY-FORWARD -i ens18 -s 192.168.10.0/24 ! -d 192.168.10.0/24 -p tcp --dport 853 -j REJECT --reject-with tcp-reset",
		"-A SHAKERPROXY-FORWARD -i ens18 -s 192.168.10.0/24 ! -d 192.168.10.0/24 -p udp --dport 853 -j REJECT --reject-with icmp-port-unreachable",
		"-A SHAKERPROXY-FORWARD -i ens18 -s 192.168.10.0/24 -d 1.1.1.1 -p tcp --dport 443 -j REJECT --reject-with tcp-reset",
		"-A SHAKERPROXY-FORWARD -i ens18 -s 192.168.10.0/24 -d 8.8.8.8 -p tcp --dport 443 -j REJECT --reject-with tcp-reset",
		"-A SHAKERPROXY-FORWARD -i ens18 -s 192.168.10.0/24 -d 8.8.8.8 -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable",
		"-A SHAKERPROXY-FORWARD -i ens18 -s 192.168.10.0/24 -d 9.9.9.9 -p tcp --dport 443 -j REJECT --reject-with tcp-reset",
		"-A SHAKERPROXY-FORWARD -i ens18 -s 192.168.10.0/24 -d 194.242.2.2 -p tcp --dport 443 -j REJECT --reject-with tcp-reset",
		`-j NFLOG --nflog-group 853 --nflog-prefix "SHAKERPROXY_EDNS_DOH_TCP " --nflog-size 128`,
	} {
		if !strings.Contains(filter, want) {
			t.Fatalf("missing %q in:\n%s", want, filter)
		}
	}
	// Plain DNS to any resolver, 8.8.8.8 included, is answered by ShakerProxy.
	for _, rule := range rules.FilterRules {
		if strings.Contains(rule, "--dport 53 ") && strings.Contains(rule, "REJECT") {
			t.Fatalf("plain DNS is blocked instead of answered: %s", rule)
		}
	}
	nat := strings.Join(rules.NATRules, "\n")
	for _, want := range []string{
		"-A SHAKERPROXY-PREROUTING -i ens18 -s 192.168.10.0/24 ! -d 192.168.10.0/24 -p udp --dport 53 -j REDIRECT --to-ports 1053",
		"-A SHAKERPROXY-PREROUTING -i ens18 -s 192.168.10.0/24 ! -d 192.168.10.0/24 -p tcp --dport 53 -j REDIRECT --to-ports 1053",
	} {
		if !strings.Contains(nat, want) {
			t.Fatalf("missing %q in:\n%s", want, nat)
		}
	}
	filter6 := strings.Join(rules.FilterRulesIPv6, "\n")
	for _, want := range []string{"-d 2001:4860:4860::8888 -p tcp --dport 443 -j REJECT", "-d 2606:4700:4700::1111 -p udp --dport 443 -j REJECT", "-p tcp --dport 853 -j REJECT"} {
		if !strings.Contains(filter6, want) {
			t.Fatalf("missing IPv6 %q in:\n%s", want, filter6)
		}
	}
}

func TestEachSwitchWorksAlone(t *testing.T) {
	block := LegacyDefaultPolicy()
	block.EncryptedDNS = block.EncryptedDNS.WithSwitches(false, true)
	if block.EncryptedDNS.EffectiveMode() != EncryptedDNSBlockKnown {
		t.Fatalf("block-only mode = %s", block.EncryptedDNS.EffectiveMode())
	}
	rules := mustRender(t, block, singleArmLab())
	if strings.Contains(strings.Join(rules.NATRules, "\n"), "! -d 192.168.10.0/24 -p udp --dport 53") || !strings.Contains(strings.Join(rules.FilterRules, "\n"), "--dport 853 -j REJECT") {
		t.Fatalf("block-only rules: %+v", rules)
	}
	force := LegacyDefaultPolicy()
	force.EncryptedDNS = force.EncryptedDNS.WithSwitches(true, false)
	rules = mustRender(t, force, singleArmLab())
	if !strings.Contains(strings.Join(rules.NATRules, "\n"), "! -d 192.168.10.0/24 -p udp --dport 53 -j REDIRECT") || strings.Contains(strings.Join(rules.FilterRules, "\n"), "REJECT") {
		t.Fatalf("force-only rules: %+v", rules)
	}
	off := LegacyDefaultPolicy()
	off.EncryptedDNS = off.EncryptedDNS.WithSwitches(false, false)
	if off.EncryptedDNS.Mode != EncryptedDNSObserve || off.EncryptedDNS.BlockEncryptedDNS() || off.EncryptedDNS.ForcePlainDNS() {
		t.Fatalf("both off = %+v", off.EncryptedDNS)
	}
}

func TestAnUntouchedObserveDefaultMigratesAndAnAdministratorChoiceStays(t *testing.T) {
	legacy, err := Normalize(LegacyDefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := Digest(legacy)
	untouched := Document{Schema: SchemaVersion, Policy: legacy, Digest: digest, AppliedAt: time.Now()}
	migrated, ok := MigrateUntouchedDefault(untouched)
	if !ok || migrated.Revision != 2 || migrated.Name != DefaultPolicyName || !migrated.EncryptedDNS.ForcePlainDNS() || !migrated.EncryptedDNS.BlockEncryptedDNS() {
		t.Fatalf("untouched default migrated to %+v ok=%v", migrated, ok)
	}
	// An administrator who applied anything, even observe-only again, has a
	// higher revision or a previous policy and keeps it.
	applied := untouched
	applied.Policy.Revision = 3
	withPrevious := untouched
	withPrevious.Previous = &legacy
	edited := untouched
	edited.Policy.EncryptedDNS.ResolverExclusions = []string{"google"}
	for name, document := range map[string]Document{"later revision": applied, "has previous": withPrevious, "edited": edited} {
		if _, ok := MigrateUntouchedDefault(document); ok {
			t.Fatalf("%s: an administrator's policy was migrated", name)
		}
	}
	if _, ok := MigrateUntouchedDefault(Document{Policy: DefaultPolicy()}); ok {
		t.Fatal("the new default was migrated again")
	}
}

func TestTheForwarderGetsTheResolverNamesToRefuse(t *testing.T) {
	runtime, err := ProjectStandaloneProxyRuntimeWithDevices(DefaultPolicy(), EmptyStandaloneDeviceRuntime())
	if err != nil {
		t.Fatal(err)
	}
	dns := runtime.EncryptedDNS
	if dns.Mode != "strict" || !dns.RedirectPlainDNS || !dns.BlockKnownDoH {
		t.Fatalf("runtime DNS = %+v", dns)
	}
	names := strings.Join(dns.BlockedResolverNames, " ")
	for _, want := range []string{"dns.google", "cloudflare-dns.com", "one.one.one.one", "dns.quad9.net", "doh.opendns.com", "dns.adguard-dns.com", "dns.nextdns.io", "doh.cleanbrowsing.org", "use-application-dns.net", "mask.icloud.com", "mask-h2.icloud.com"} {
		if !strings.Contains(" "+names+" ", " "+want+" ") {
			t.Fatalf("forwarder would not refuse %q: %s", want, names)
		}
	}
	excluded := DefaultPolicy()
	excluded.EncryptedDNS.ResolverExclusions = []string{"google"}
	runtime, err = ProjectStandaloneProxyRuntimeWithDevices(excluded, EmptyStandaloneDeviceRuntime())
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range runtime.EncryptedDNS.BlockedResolverNames {
		if name == "dns.google" {
			t.Fatal("an excluded resolver's name is still refused")
		}
	}
	off := DefaultPolicy()
	off.EncryptedDNS = off.EncryptedDNS.WithSwitches(true, false)
	runtime, _ = ProjectStandaloneProxyRuntimeWithDevices(off, EmptyStandaloneDeviceRuntime())
	if len(runtime.EncryptedDNS.BlockedResolverNames) != 0 {
		t.Fatal("names are refused while encrypted DNS blocking is off")
	}
}

func TestTheResolverCatalogIsWellFormed(t *testing.T) {
	seen := map[string]string{}
	for _, resolver := range BuiltinCatalog().Resolvers {
		for family, addresses := range map[string][]string{"IPv4": resolver.IPv4, "IPv6": resolver.IPv6} {
			for _, raw := range addresses {
				address, err := netip.ParseAddr(raw)
				if err != nil || (family == "IPv4") != address.Is4() || address.IsPrivate() || address.IsLoopback() || address.IsUnspecified() {
					t.Fatalf("%s: bad %s address %q", resolver.ID, family, raw)
				}
				if other, duplicate := seen[address.String()]; duplicate {
					t.Fatalf("%s and %s share %s", resolver.ID, other, raw)
				}
				seen[address.String()] = resolver.ID
			}
		}
		for _, hostname := range resolver.Hostnames {
			if hostname != strings.ToLower(hostname) || strings.TrimPrefix(hostname, "*.") == "" {
				t.Fatalf("%s: bad hostname %q", resolver.ID, hostname)
			}
		}
	}
	if names := BlockedResolverNames(DefaultPolicy()); len(names) == 0 || len(names) > MaxBlockedResolverNames {
		t.Fatalf("blocked resolver names = %d", len(names))
	}
	if !IsEncryptedDNSCanary("Mask.iCloud.com.") || IsEncryptedDNSCanary("icloud.com") {
		t.Fatal("canary matching is wrong")
	}
}
