package main

import (
	"fmt"
	"os"
	"time"

	"shakerproxy.dev/shakerproxy/internal/trafficpolicy"
)

func main() {
	now := time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC)
	document := trafficpolicy.EnforcementDocument{
		SchemaVersion: trafficpolicy.SchemaVersion,
		Enabled:       true,
		EncryptedDNS: trafficpolicy.EnforcementDNSPolicy{
			Mode:              "strict",
			RedirectPlainDNS:  true,
			BlockDoT:          true,
			BlockDoQ:          true,
			BlockKnownDoH:     true,
			BlockQUICForScope: true,
			FailMode:          "passthrough",
		},
		TLS: trafficpolicy.TLSInterceptionPolicy{
			Mode:              "all",
			AutoBypassPinning: true,
			PinningThreshold:  2,
			FailMode:          "passthrough",
			BypassRules: []trafficpolicy.TLSBypassRule{{
				ID:        "ios-pinned-api",
				Enabled:   true,
				Platform:  "ios",
				MatchType: "host-suffix",
				Pattern:   "pinned.example.test",
				Reason:    "certificate-pinning",
				Source:    "manual",
			}},
		},
		Resolvers: []trafficpolicy.ResolverPolicyTarget{{
			Provider:        "Cloudflare",
			Hostnames:       []string{"cloudflare-dns.com"},
			IPv4:            []string{"1.1.1.1", "1.0.0.1"},
			IPv6:            []string{"2606:4700:4700::1111"},
			Transports:      []string{"doh", "doh3", "dot"},
			Dedicated:       true,
			SafeToBlockByIP: true,
			Source:          "ci-fixture",
		}},
	}
	digest, err := document.Digest()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	request := trafficpolicy.ApplyRequest{
		PolicyID: "ci-policy",
		Revision: 1,
		Digest:   digest,
		Policy:   document,
		Runtime: trafficpolicy.Runtime{
			TestInterfaces:    []string{"lab0"},
			ScopeIPv4:         []string{"10.44.0.0/24"},
			ScopeIPv6:         []string{"fd44::/64"},
			LocalDNSPort:      53,
			MITMPort:          8080,
			TLSInterceptPorts: []int{443},
			DevicePlatforms:   map[string]string{"device-ios": "ios"},
			DeviceIPv4:        map[string][]string{"device-ios": {"10.44.0.15"}},
		},
	}
	compiled, err := trafficpolicy.Compile(request, trafficpolicy.CompileOptions{TLSBackendAvailable: true}, now)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	compiled.NFTables = trafficpolicy.InstrumentDetectionLogs(compiled.NFTables)
	if _, err := os.Stdout.Write(compiled.NFTables); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
