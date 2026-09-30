package querylang

import "testing"

func TestBetaTrafficPredicatesCanonicalize(t *testing.T) {
	cases := map[string]string{
		"dns.query:*.Example.COM":                   "dns.query:*.example.com",
		"dns.rcode:nxdomain":                        "dns.rcode:NXDOMAIN",
		"tls.sni:API.Example.COM":                   "tls.sni:api.example.com",
		"tls.state:bypassed":                        "tls.state:BYPASSED",
		"tls.pinning:true":                          "tls.pinning:true",
		"http.host:API.Example.COM":                 "http.host:api.example.com",
		"http.method:post":                          "http.method:POST",
		"http.status>=400":                          "http.status>=400",
		"http.path:/v1/orders/*":                    "http.path:/v1/orders/*",
		"time:last_15m AND dns.query:*.example.com": "time:last_15m AND dns.query:*.example.com",
		"tls.state:FAILED OR http.status>=500":      "tls.state:FAILED OR http.status>=500",
		"NOT tls.pinning:true AND http.method:GET":  "NOT tls.pinning:true AND http.method:GET",
	}
	for input, expected := range cases {
		query, err := Parse(input)
		if err != nil {
			t.Fatalf("Parse(%q): %v", input, err)
		}
		if query.Canonical != expected {
			t.Fatalf("Parse(%q) canonical = %q, want %q", input, query.Canonical, expected)
		}
	}
}

func TestBetaTrafficPredicatesRejectUnsafeOrInvalidValues(t *testing.T) {
	inputs := []string{
		"dns.query:bad/host",
		`tls.sni:"bad host"`,
		"tls.state:UNKNOWN",
		"tls.pinning:maybe",
		"http.method:GET*",
		"http.status:99",
		"http.status:600",
		"http.path:https://example.com/secret",
		"http.path:/v1/orders?token=secret",
	}
	for _, input := range inputs {
		if _, err := Parse(input); err == nil {
			t.Fatalf("Parse(%q) unexpectedly succeeded", input)
		}
	}
}

func TestBetaTrafficMetadataAdvertisesImplementedFields(t *testing.T) {
	metadata := AutocompleteMetadata()
	wanted := map[string]bool{
		"dns.query": false, "dns.rcode": false,
		"tls.sni": false, "tls.state": false, "tls.pinning": false,
		"http.host": false, "http.method": false, "http.status": false, "http.path": false,
	}
	for _, field := range metadata.Fields {
		if _, exists := wanted[field.Name]; exists {
			wanted[field.Name] = true
		}
	}
	for name, found := range wanted {
		if !found {
			t.Fatalf("autocomplete metadata is missing %s", name)
		}
	}
}
