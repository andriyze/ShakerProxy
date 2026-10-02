package ingest

import (
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/querylang"
)

func TestCompileEventFilterSupportsProtocolDiscoveryFields(t *testing.T) {
	cases := map[string][]string{
		`proto:mqtt`:                 {"COALESCE(app_protocol = $1, FALSE)"},
		`app:ssl`:                    {"COALESCE(app_protocol = $1, FALSE)"},
		`app.protocol:unknown-*`:     {"COALESCE(app_protocol LIKE $1 ESCAPE E'\\\\', FALSE)"},
		`protocol.visibility:OPAQUE`: {"COALESCE(protocol_visibility = $1, FALSE)"},
		`protocol.category:web`:      {"COALESCE(protocol_category = $1, FALSE)"},
		`protocol.exotic:true`:       {"COALESCE(protocol_exotic = $1, FALSE)"},
		`protocol.exotic!=true`:      {"NOT COALESCE(protocol_exotic = $1, FALSE)"},
		`NOT proto:tls`:              {"(NOT COALESCE(app_protocol = $1, FALSE))"},
		`app.protocol:*`:             {"app_protocol IS NOT NULL"},
	}
	for input, required := range cases {
		filter, err := querylang.Parse(input)
		if err != nil {
			t.Fatalf("Parse(%q): %v", input, err)
		}
		args := []any{}
		statement, err := compileEventFilter(filter.Root, nil, nil, time.Time{}, false, &args)
		if err != nil {
			t.Fatalf("compile %q: %v", input, err)
		}
		for _, fragment := range required {
			if !strings.Contains(statement, fragment) {
				t.Fatalf("compiled %q as %q; missing %q", input, statement, fragment)
			}
		}
	}
	filter, _ := querylang.Parse(`protocol.exotic:true`)
	args := []any{}
	if _, err := compileEventFilter(filter.Root, nil, nil, time.Time{}, false, &args); err != nil || len(args) != 1 || args[0] != true {
		t.Fatalf("protocol.exotic was not bound as a boolean: %#v %v", args, err)
	}
}

func TestCompileEventFilterFreeTextSearchesNamesSafely(t *testing.T) {
	filter, err := querylang.Parse(`Netflix -ads_tracker`)
	if err != nil {
		t.Fatal(err)
	}
	args := []any{}
	statement, err := compileEventFilter(filter.Root, nil, nil, time.Time{}, false, &args)
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{"COALESCE(dns_query LIKE $1", "COALESCE(tls_server_name LIKE $1", "COALESCE(http_host LIKE $1", "(NOT (COALESCE(dns_query LIKE $2"} {
		if !strings.Contains(statement, fragment) {
			t.Fatalf("free-text filter %q missing %q", statement, fragment)
		}
	}
	if len(args) != 2 || args[0] != "%netflix%" || args[1] != `%ads\_tracker%` {
		t.Fatalf("free-text arguments were not escaped substrings: %#v", args)
	}
}

func TestCompileEventFilterBareAddressMatchesEitherEndpoint(t *testing.T) {
	for input, want := range map[string]struct {
		fragment string
		arg      string
	}{
		"192.168.10.201":  {"(COALESCE(source_ip = $1::inet, FALSE) OR COALESCE(destination_ip = $1::inet, FALSE))", "192.168.10.201"},
		"192.168.10.0/24": {"(COALESCE(source_ip <<= $1::cidr, FALSE) OR COALESCE(destination_ip <<= $1::cidr, FALSE))", "192.168.10.0/24"},
		"NOT 2001:db8::1": {"NOT (COALESCE(source_ip = $1::inet, FALSE) OR COALESCE(destination_ip = $1::inet, FALSE))", "2001:db8::1"},
	} {
		filter, err := querylang.Parse(input)
		if err != nil {
			t.Fatal(err)
		}
		args := []any{}
		statement, err := compileEventFilter(filter.Root, nil, nil, time.Time{}, false, &args)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(statement, want.fragment) || len(args) != 1 || args[0] != want.arg {
			t.Fatalf("%q compiled to %q with %#v", input, statement, args)
		}
		if strings.Contains(statement, "LIKE") {
			t.Fatalf("%q searched host names: %q", input, statement)
		}
	}
}
