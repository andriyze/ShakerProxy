package querylang

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParseCanonicalizesTypedBooleanQuery(t *testing.T) {
	query, err := Parse(`source:suricata protocol:UDP (dst.port:53 OR bytes:>10MB) NOT service:*`)
	if err != nil {
		t.Fatal(err)
	}
	expected := `source:SURICATA AND protocol:udp AND (dst.port:53 OR bytes>10485760) AND NOT service:*`
	if query.Canonical != expected {
		t.Fatalf("unexpected canonical query: %q", query.Canonical)
	}
	if query.Root == nil || query.Root.Type != NodeAnd {
		t.Fatalf("unexpected query tree: %#v", query.Root)
	}
}

func TestParseSupportsQuotedValuesIPv6CIDRAndNegatedExistence(t *testing.T) {
	query, err := Parse(`kind:"zeek.conn" src.ip:2001:db8::/32 -device.id:*`)
	if err != nil {
		t.Fatal(err)
	}
	if query.Canonical != `kind:zeek.conn AND src.ip:2001:db8::/32 AND NOT device.id:*` {
		t.Fatalf("unexpected canonical query: %q", query.Canonical)
	}
}

func TestParseCanonicalizesDeviceFriendlyNameAliases(t *testing.T) {
	query, err := Parse(`name:"Emma's iPhone" OR device:"Bench Camera" OR device.name:*`)
	if err != nil {
		t.Fatal(err)
	}
	if query.Canonical != `device.name:"Emma's iPhone" OR device.name:"Bench Camera" OR device.name:*` {
		t.Fatalf("unexpected friendly-name canonical query: %q", query.Canonical)
	}
	values := DeviceNameValues(query)
	if len(values) != 3 || values[0] != "Emma's iPhone" || values[1] != "Bench Camera" || values[2] != "*" {
		t.Fatalf("unexpected friendly-name operands: %#v", values)
	}
}

func TestParseCanonicalizesAndRewritesDeviceTags(t *testing.T) {
	query, err := Parse(`tag:Camera OR device.tag:"Lab Gear" OR device.tag:*`)
	if err != nil {
		t.Fatal(err)
	}
	if query.Canonical != `device.tag:camera OR device.tag:"lab gear" OR device.tag:*` {
		t.Fatalf("unexpected device-tag canonical query: %q", query.Canonical)
	}
	values := DeviceTagValues(query)
	if len(values) != 3 || values[0] != "camera" || values[1] != "lab gear" || values[2] != "*" {
		t.Fatalf("unexpected device-tag operands: %#v", values)
	}
	rewritten, err := RewriteDeviceTags(query, map[string]string{"camera": "tag-ref-01", "lab gear": "tag-ref-02", "*": "tag-ref-03"})
	if err != nil || rewritten.Canonical != `device.tag:tag-ref-01 OR device.tag:tag-ref-02 OR device.tag:tag-ref-03` {
		t.Fatalf("device-tag rewrite changed query semantics: %#v %v", rewritten, err)
	}
}

func TestParseCanonicalizesRelativeAndAbsoluteTime(t *testing.T) {
	query, err := Parse(`time:LAST_15M AND time>=2026-09-01T07:00:00-05:00`)
	if err != nil {
		t.Fatal(err)
	}
	if query.Canonical != `time:last_15m AND time>=2026-09-01T12:00:00Z` || !HasRelativeTime(query) {
		t.Fatalf("unexpected canonical time query: %#v", query)
	}
	left := query.Root.Children[0].Predicate
	right := query.Root.Children[1].Predicate
	if left == nil || !left.IsRelativeTime || left.RelativeNanos != int64(15*time.Minute) || right == nil || !right.IsTimestamp || !right.Timestamp.Equal(time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("time predicates lost their typed values: %#v %#v", left, right)
	}
}

func TestRewriteDeviceNamesPreservesBooleanStructure(t *testing.T) {
	query, err := Parse(`name:"Bench Camera" OR (protocol:tcp AND NOT device.name:*)`)
	if err != nil {
		t.Fatal(err)
	}
	rewritten, err := RewriteDeviceNames(query, map[string]string{"Bench Camera": "alias-ref-01", "*": "alias-ref-02"})
	if err != nil || rewritten.Canonical != `device.name:alias-ref-01 OR protocol:tcp AND NOT device.name:alias-ref-02` {
		t.Fatalf("device-name rewrite changed query semantics: %#v %v", rewritten, err)
	}
	if _, err := RewriteDeviceNames(query, map[string]string{"Bench Camera": "alias-ref-01"}); err == nil {
		t.Fatal("incomplete device-name rewrite was accepted")
	}
}

func TestParseRejectsUnsafeOrUnsupportedQueries(t *testing.T) {
	invalid := []string{
		`unknown:value`, `source:SQL`, `dst.port:0`, `confidence:101`, `bytes:>999999999999999999999TB`,
		`kind:"unterminated`, `kind:"bad\nescape"`, `src.ip:fe80::1%eth0`, `(source:ZEEK`, `source:ZEEK OR`,
		`device.name:Cam*`, `device.name>Camera`, `device.tag:cam*`, `device.tag>camera`,
		`time:last_0m`, `time:last_01m`, `time:last_31d`, `time>last_15m`, `time:yesterday`, `time:2026-02-30`,
		strings.Repeat("(", 14) + `source:ZEEK` + strings.Repeat(")", 14),
	}
	for _, input := range invalid {
		if _, err := Parse(input); err == nil {
			t.Fatalf("unsafe query was accepted: %q", input)
		}
	}
}

func TestParseEmptyQuery(t *testing.T) {
	query, err := Parse("")
	if err != nil || query.Root != nil || query.Canonical != "" {
		t.Fatalf("unexpected empty query: %#v %v", query, err)
	}
}

func TestCanonicalQueriesRoundTripToTheSameTree(t *testing.T) {
	cases := map[string]string{
		`source:ZEEK OR (kind:zeek.dns OR kind:zeek.conn)`: `source:ZEEK OR (kind:zeek.dns OR kind:zeek.conn)`,
		`(source:ZEEK OR kind:zeek.dns) OR kind:zeek.conn`: `source:ZEEK OR kind:zeek.dns OR kind:zeek.conn`,
		`dst.port:443 (src.ip:10.0.0.1 dns.query:a.com)`:   `dst.port:443 AND (src.ip:10.0.0.1 AND dns.query:a.com)`,
		`source:ZEEK OR (kind:zeek.dns kind:zeek.conn)`:    `source:ZEEK OR kind:zeek.dns AND kind:zeek.conn`,
		`name:"Cam=1" OR name:"TV<2>" OR http.path:"/x!y"`: `device.name:"Cam=1" OR device.name:"TV<2>" OR http.path:"/x!y"`,
		`http.path:"/a>=b"`: `http.path:"/a>=b"`,
		`-(kind:zeek.conn OR kind:zeek.dns) protocol:tcp`:                `NOT (kind:zeek.conn OR kind:zeek.dns) AND protocol:tcp`,
		`dns.query:_googlecast._tcp.local OR tls.sni:*._tcp.example.com`: `dns.query:_googlecast._tcp.local OR tls.sni:*._tcp.example.com`,
	}
	for input, expected := range cases {
		query, err := Parse(input)
		if err != nil {
			t.Fatalf("Parse(%q): %v", input, err)
		}
		if query.Canonical != expected {
			t.Fatalf("Parse(%q) canonical = %q, want %q", input, query.Canonical, expected)
		}
		reparsed, err := Parse(query.Canonical)
		if err != nil || reparsed.Canonical != query.Canonical || !reflect.DeepEqual(reparsed.Root, query.Root) {
			t.Fatalf("canonical %q did not round-trip: %#v err=%v", query.Canonical, reparsed, err)
		}
	}
}

func TestParseRejectsScopedIPAddresses(t *testing.T) {
	for _, input := range []string{`src.ip:fe80::1%eth0`, `dst.ip:fe80::1%25eth0`} {
		if _, err := Parse(input); err == nil {
			t.Fatalf("scoped address was accepted: %q", input)
		}
	}
}

// The Traffic page's Domains facet narrows the current filter with a bare
// domain word; it must stay a free-text search, not a field or a time value.
func TestParseKeepsAFacetDomainAsFreeText(t *testing.T) {
	query, err := Parse(`(device.id:device-0123456789abcdef0123456789abcdef AND time:last_1h) AND googleapis.com`)
	if err != nil {
		t.Fatal(err)
	}
	if query.Root == nil || query.Root.Type != NodeAnd || len(query.Root.Children) != 2 {
		t.Fatalf("unexpected query tree: %#v", query.Root)
	}
	domain := query.Root.Children[1].Predicate
	if domain == nil || domain.Field != TextField || domain.Value != "googleapis.com" || domain.Operator != OperatorEqual {
		t.Fatalf("the domain was not a free-text predicate: %#v", domain)
	}
}
