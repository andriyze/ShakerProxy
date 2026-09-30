package ingest

import (
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/querylang"
)

func compileBetaFilterForTest(t *testing.T, raw string) (string, []any) {
	t.Helper()
	parsed, err := querylang.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	args := []any{}
	clause, err := compileEventFilter(parsed.Root, nil, nil, time.Date(2026, 9, 4, 1, 0, 0, 0, time.UTC), false, &args)
	if err != nil {
		t.Fatal(err)
	}
	return clause, args
}

func TestCompileBetaTrafficFiltersUseBoundedMetadataColumns(t *testing.T) {
	cases := []struct {
		query string
		want  string
	}{
		{"dns.query:*.example.com", "dns_query LIKE"},
		{"dns.rcode:NXDOMAIN", "dns_response_code ="},
		{"tls.sni:api.example.com", "COALESCE(tls_server_name, CASE"},
		{"tls.state:BYPASSED", "tls_interception_state ="},
		{"tls.pinning:true", "COALESCE(tls_pinning_suspected, FALSE)"},
		{"http.host:api.example.com", "WHEN source = 'MITMPROXY' THEN payload->>'http_host'"},
		{"http.method:POST", "WHEN source = 'MITMPROXY' THEN payload->>'http_method'"},
		{"http.path:/v1/orders/*", "WHEN source = 'MITMPROXY' THEN payload->>'http_path'"},
		{"http.status>=400", "payload->>'http_status'"},
	}
	for _, test := range cases {
		clause, args := compileBetaFilterForTest(t, test.query)
		if !strings.Contains(clause, test.want) {
			t.Fatalf("%s compiled to %q; expected %q", test.query, clause, test.want)
		}
		if len(args) != 1 {
			t.Fatalf("%s compiled with %d args, want 1", test.query, len(args))
		}
		if strings.Contains(clause, "request_headers") || strings.Contains(clause, "response_headers") || strings.Contains(clause, "request_body") || strings.Contains(clause, "response_body") {
			t.Fatalf("%s unexpectedly searches plaintext content: %q", test.query, clause)
		}
	}
}

func TestCompileHTTPStatusGuardsJSONCast(t *testing.T) {
	clause, _ := compileBetaFilterForTest(t, "http.status>=500")
	if !strings.Contains(clause, "CASE WHEN") || !strings.Contains(clause, "~ '^[0-9]{3}$'") {
		t.Fatalf("HTTP status cast is not fail-safe: %q", clause)
	}
}

func TestCompileHTTPPathNeverSearchesQueryOrFragmentText(t *testing.T) {
	clause, _ := compileBetaFilterForTest(t, "http.path:/v1/orders")
	if !strings.Contains(clause, "split_part(split_part") || strings.Contains(clause, "http_url") {
		t.Fatalf("HTTP path filter did not stay on the sanitized path projection: %q", clause)
	}
}

func TestCompileHTTPAndTLSFiltersCoverPassiveAnalyzers(t *testing.T) {
	for query, required := range map[string][]string{
		"http.host:example.com": {"payload->>'http_host'", "kind = 'zeek.http' THEN regexp_replace(payload->>'host'", "payload#>>'{http,hostname}'"},
		"http.method:GET":       {"payload->>'method'", "payload#>>'{http,http_method}'"},
		"http.path:/api/*":      {"payload->>'uri'", "payload#>>'{http,url}'", "'?', 1), '#', 1)"},
		"http.status>=400":      {"payload->>'status_code'", "payload#>>'{http,status}'"},
		"tls.sni:example.com":   {"payload->>'server_name'", "payload#>>'{tls,sni}'"},
	} {
		clause, _ := compileBetaFilterForTest(t, query)
		for _, fragment := range required {
			if !strings.Contains(clause, fragment) {
				t.Fatalf("%s compiled to %q; missing %q", query, clause, fragment)
			}
		}
	}
}

func TestCompileNegationMatchesEventsWithoutTheField(t *testing.T) {
	for query, required := range map[string]string{
		"NOT service:dns":          "(NOT COALESCE(service = $1, FALSE))",
		"service!=dns":             "NOT COALESCE(service = $1, FALSE)",
		"src.ip!=10.0.0.0/8":       "NOT COALESCE(source_ip <<= $1::cidr, FALSE)",
		"dns.query!=*.example.com": "NOT COALESCE(dns_query LIKE $1 ESCAPE",
		"NOT dst.port>=1024":       "(NOT COALESCE(destination_port >= $1, FALSE))",
		"tls.pinning:false":        "(CASE WHEN tls_interception_state IS NOT NULL THEN COALESCE(tls_pinning_suspected, FALSE) END) = $1",
	} {
		clause, _ := compileBetaFilterForTest(t, query)
		if !strings.Contains(clause, required) {
			t.Fatalf("%s compiled to %q; expected %q", query, clause, required)
		}
	}
}
