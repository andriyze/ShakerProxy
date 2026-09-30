package trafficpolicy

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestCompileBlocksEncryptedDNSAndRedirectsTLS(t *testing.T) {
	now := time.Date(2026, 9, 2, 17, 0, 0, 0, time.UTC)
	document := EnforcementDocument{
		SchemaVersion: SchemaVersion,
		Enabled:       true,
		EncryptedDNS: EnforcementDNSPolicy{
			Mode:              "strict",
			RedirectPlainDNS:  true,
			BlockDoT:          true,
			BlockDoQ:          true,
			BlockKnownDoH:     true,
			BlockQUICForScope: true,
			FailMode:          "passthrough",
		},
		TLS: TLSInterceptionPolicy{
			Mode:              "all",
			FailMode:          "passthrough",
			AutoBypassPinning: true,
			PinningThreshold:  3,
			BypassRules: []TLSBypassRule{
				{
					ID:        "android-pin",
					Enabled:   true,
					Platform:  "android",
					MatchType: "host-suffix",
					Pattern:   "api.example.com",
					Reason:    "Certificate pinning confirmed",
					Source:    "manual",
				},
			},
		},
		Resolvers: []ResolverPolicyTarget{
			{
				Provider:        "Example Resolver",
				Hostnames:       []string{"dns.example.net"},
				IPv4:            []string{"192.0.2.53"},
				IPv6:            []string{"2001:db8::53"},
				Transports:      []string{"doh", "doh3", "dot", "doq"},
				Dedicated:       true,
				SafeToBlockByIP: true,
				Source:          "test",
			},
		},
	}
	if err := document.NormalizeAndValidate(now); err != nil {
		t.Fatal(err)
	}
	digest, err := document.Digest()
	if err != nil {
		t.Fatal(err)
	}
	request := ApplyRequest{
		PolicyID: "policy-1",
		Revision: 7,
		Digest:   digest,
		Policy:   document,
		Runtime: Runtime{
			TestInterfaces:    []string{"lab0"},
			ScopeIPv4:         []string{"10.44.0.0/24"},
			ScopeIPv6:         []string{"fd44::/64"},
			LocalDNSPort:      1053,
			MITMPort:          8080,
			TLSInterceptPorts: []int{443, 8443},
			DevicePlatforms:   map[string]string{"device-ios": "ios"},
			DeviceIPv4:        map[string][]string{"device-ios": {"10.44.0.15"}},
		},
	}
	compiled, err := Compile(request, CompileOptions{TLSBackendAvailable: true}, now)
	if err != nil {
		t.Fatal(err)
	}
	script := string(compiled.NFTables)
	for _, expected := range []string{
		"tcp dport 853",
		"udp dport 853",
		"ip daddr @resolver_doh4 tcp dport 443",
		"ip6 daddr @resolver_doh6 udp dport 443",
		"udp dport 443 reject",
		"udp dport 53 redirect to :1053",
		"tcp dport { 443, 8443 } redirect to :8080",
	} {
		if !strings.Contains(script, expected) {
			t.Fatalf("compiled nftables policy is missing %q:\n%s", expected, script)
		}
	}
	if compiled.ResolverIPv4 != 1 || compiled.ResolverIPv6 != 1 || compiled.TLSBypassRules != 1 {
		t.Fatalf("unexpected compilation summary: %#v", compiled)
	}
	if !strings.Contains(string(compiled.ProxyPolicy), "api.example.com") || !strings.Contains(string(compiled.ProxyPolicy), "dns.example.net") {
		t.Fatalf("MITM policy snapshot omitted host-based policy: %s", compiled.ProxyPolicy)
	}
	var snapshot ProxySnapshot
	if err := json.Unmarshal(compiled.ProxyPolicy, &snapshot); err != nil {
		t.Fatalf("decode MITM policy snapshot: %v", err)
	}
	if snapshot.SchemaVersion != 1 || snapshot.TLS.Mode != "all" || snapshot.DeviceByIP["10.44.0.15"] != "device-ios" || snapshot.DevicePlatforms["device-ios"] != "ios" {
		t.Fatalf("MITM policy contract is incomplete: %#v", snapshot)
	}
}

func TestCompileLimitsSelectiveTLSRedirectToKnownDeviceAddresses(t *testing.T) {
	now := time.Now().UTC()
	document := EnforcementDocument{
		SchemaVersion: SchemaVersion,
		Enabled:       true,
		EncryptedDNS:  EnforcementDNSPolicy{Mode: "observe", FailMode: "passthrough"},
		TLS: TLSInterceptionPolicy{
			Mode:              "selective",
			FailMode:          "passthrough",
			PinningThreshold:  3,
			SelectedDeviceIDs: []string{"device-tv"},
		},
	}
	digest, err := document.Digest()
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := Compile(ApplyRequest{
		PolicyID: "policy-selective",
		Revision: 1,
		Digest:   digest,
		Policy:   document,
		Runtime: Runtime{
			TestInterfaces:    []string{"lab0"},
			ScopeIPv4:         []string{"10.44.0.0/24"},
			DevicePlatforms:   map[string]string{"device-tv": "android-tv", "device-other": "unknown"},
			DeviceIPv4:        map[string][]string{"device-tv": {"10.44.0.15"}, "device-other": {"10.44.0.16"}},
			MITMPort:          8085,
			TLSInterceptPorts: []int{443},
		},
	}, CompileOptions{TLSBackendAvailable: true}, now)
	if err != nil {
		t.Fatal(err)
	}
	script := string(compiled.NFTables)
	if !strings.Contains(script, "elements = { 10.44.0.15 }") || !strings.Contains(script, "ip saddr @tls_selected4 tcp dport 443 redirect to :8085") || strings.Contains(script, "10.44.0.16") {
		t.Fatalf("selective TLS scope was not compiled safely:\n%s", script)
	}
}

func TestCompileDoesNotBlockSharedResolverAddress(t *testing.T) {
	now := time.Now().UTC()
	document := EnforcementDocument{
		SchemaVersion: SchemaVersion,
		Enabled:       true,
		EncryptedDNS: EnforcementDNSPolicy{
			Mode:          "block",
			BlockKnownDoH: true,
			FailMode:      "passthrough",
		},
		TLS: TLSInterceptionPolicy{Mode: "off", FailMode: "passthrough", PinningThreshold: 3},
		Resolvers: []ResolverPolicyTarget{
			{
				Provider:        "Shared Resolver",
				Hostnames:       []string{"shared.example.net"},
				IPv4:            []string{"198.51.100.10"},
				Transports:      []string{"doh"},
				Dedicated:       false,
				SafeToBlockByIP: false,
			},
		},
	}
	if err := document.NormalizeAndValidate(now); err != nil {
		t.Fatal(err)
	}
	digest, _ := document.Digest()
	compiled, err := Compile(ApplyRequest{
		PolicyID: "policy-shared",
		Revision: 1,
		Digest:   digest,
		Policy:   document,
		Runtime:  Runtime{TestInterfaces: []string{"lab0"}},
	}, CompileOptions{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(compiled.NFTables), "198.51.100.10") {
		t.Fatal("shared CDN address was compiled into a block set")
	}
	if !strings.Contains(string(compiled.ProxyPolicy), "shared.example.net") {
		t.Fatal("shared resolver hostname should remain available for detection")
	}
}

func TestCompileFailsClosedWhenMITMUnavailableAndRequested(t *testing.T) {
	now := time.Now().UTC()
	document := EnforcementDocument{
		SchemaVersion: SchemaVersion,
		Enabled:       true,
		EncryptedDNS:  EnforcementDNSPolicy{Mode: "observe", FailMode: "passthrough"},
		TLS: TLSInterceptionPolicy{
			Mode:             "all",
			FailMode:         "block",
			PinningThreshold: 3,
		},
	}
	if err := document.NormalizeAndValidate(now); err != nil {
		t.Fatal(err)
	}
	digest, _ := document.Digest()
	compiled, err := Compile(ApplyRequest{
		PolicyID: "policy-fail-closed",
		Revision: 1,
		Digest:   digest,
		Policy:   document,
		Runtime:  Runtime{TestInterfaces: []string{"lab0"}},
	}, CompileOptions{TLSBackendAvailable: false}, now)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(compiled.NFTables), "ShakerProxy TLS fail closed") || strings.Contains(string(compiled.NFTables), "TLS interception") {
		t.Fatalf("unexpected fail-closed compilation:\n%s", compiled.NFTables)
	}
}

func TestMatchTLSBypassIsPlatformAndDeviceAware(t *testing.T) {
	now := time.Now().UTC()
	document := EnforcementDocument{
		TLS: TLSInterceptionPolicy{
			BypassRules: []TLSBypassRule{
				{
					ID:        "ios-api",
					Enabled:   true,
					Platform:  "ios",
					DeviceID:  "device-1",
					MatchType: "host-suffix",
					Pattern:   "api.example.com",
					Reason:    "Pinned",
					Source:    "manual",
				},
			},
		},
	}
	match, err := MatchTLSBypass(document, "device-1", "ios", "v2.api.example.com", "203.0.113.10", now)
	if err != nil || match == nil || match.ID != "ios-api" {
		t.Fatalf("expected scoped TLS bypass, got %#v %v", match, err)
	}
	match, err = MatchTLSBypass(document, "device-2", "ios", "v2.api.example.com", "203.0.113.10", now)
	if err != nil || match != nil {
		t.Fatalf("device-scoped bypass leaked to another device: %#v %v", match, err)
	}
}
