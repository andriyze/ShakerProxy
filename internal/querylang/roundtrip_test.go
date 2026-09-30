package querylang

import (
	"math/rand"
	"reflect"
	"strings"
	"testing"
)

var roundTripSeeds = []string{
	`device.name:"TV<1>"`,
	`name:"Cam=1"`,
	`device.name:"Kitchen!Display"`,
	`http.path:"/x!y"`,
	`http.path:"/a=b"`,
	`device.name:"Living room TV"`,
	"device.name:\"Bench Camera\"",
	"device.name:\"Tab Two\"",
	`device.name:"quote \" and \\ slash"`,
	`device.name:"(paren)"`,
	`source:ZEEK OR (kind:zeek.dns OR kind:zeek.conn)`,
	`dst.port:443 (src.ip:10.0.0.1 dns.query:a.com)`,
	`(a.com OR b.com) (c.com OR d.com)`,
	`NOT (source:ZEEK AND kind:zeek.conn)`,
	`-(source:ZEEK OR source:SURICATA)`,
	`NOT NOT source:ZEEK`,
	`source:ZEEK AND (kind:zeek.dns AND dst.port:53)`,
	`source:ZEEK OR kind:zeek.dns AND dst.port:53`,
	`(source:ZEEK OR kind:zeek.dns) AND dst.port:53`,
	`time:2026-09-01`,
	`time!=2026-09-01 OR source:ZEEK`,
	`time<=2026-09-01 time>2026-08-01`,
	`proto:mqtt protocol.exotic:true`,
	`app:ssl OR app.protocol:unknown-*`,
	`protocol.visibility:opaque NOT protocol.category:web`,
	`netflix`,
	`netflix OR youtube -googlevideo`,
	`dns.query:_googlecast._tcp.local`,
	`dns.query:.`,
	`src.ip:::ffff:10.77.0.23`,
	`dst.ip:2001:DB8::1`,
	`src.ip:10.77.0.23/24`,
	`http.status>=400 http.method:post`,
	`bytes:>10MB confidence<=50`,
	`tls.pinning:false OR tls.state:failed`,
}

func assertRoundTrip(t *testing.T, input string) {
	t.Helper()
	first, err := Parse(input)
	if err != nil {
		return
	}
	second, err := Parse(first.Canonical)
	if err != nil {
		t.Fatalf("canonical form of %q does not reparse: %q: %v", input, first.Canonical, err)
	}
	if second.Canonical != first.Canonical {
		t.Fatalf("canonical form of %q is not stable: %q then %q", input, first.Canonical, second.Canonical)
	}
	if !reflect.DeepEqual(first.Root, second.Root) {
		t.Fatalf("canonical form of %q changed the query tree: %q", input, first.Canonical)
	}
}

func TestCanonicalRoundTripSeeds(t *testing.T) {
	for _, input := range roundTripSeeds {
		if _, err := Parse(input); err != nil {
			t.Fatalf("seed %q does not parse: %v", input, err)
		}
		assertRoundTrip(t, input)
	}
}

func TestCanonicalQuotesOperatorAndSpaceCharacters(t *testing.T) {
	cases := map[string]string{
		`device.name:"TV<1>"`:          `device.name:"TV<1>"`,
		`name:"Cam=1"`:                 `device.name:"Cam=1"`,
		`http.path:"/x!y"`:             `http.path:"/x!y"`,
		"device.name:\"Bench Camera\"": "device.name:\"Bench Camera\"",
		`device.name:Plain`:            `device.name:Plain`,
	}
	for input, expected := range cases {
		query, err := Parse(input)
		if err != nil || query.Canonical != expected {
			t.Fatalf("Parse(%q) canonical = %q, %v; want %q", input, query.Canonical, err, expected)
		}
	}
}

func TestCanonicalKeepsExplicitRightGrouping(t *testing.T) {
	cases := map[string]string{
		`source:ZEEK OR (kind:zeek.dns OR kind:zeek.conn)`: `source:ZEEK OR (kind:zeek.dns OR kind:zeek.conn)`,
		`dst.port:443 (src.ip:10.0.0.1 dns.query:a.com)`:   `dst.port:443 AND (src.ip:10.0.0.1 AND dns.query:a.com)`,
		`(source:ZEEK OR kind:zeek.dns) OR dst.port:53`:    `source:ZEEK OR kind:zeek.dns OR dst.port:53`,
		`source:ZEEK OR kind:zeek.dns AND dst.port:53`:     `source:ZEEK OR kind:zeek.dns AND dst.port:53`,
		`-(source:ZEEK OR source:SURICATA)`:                `NOT (source:ZEEK OR source:SURICATA)`,
	}
	for input, expected := range cases {
		query, err := Parse(input)
		if err != nil || query.Canonical != expected {
			t.Fatalf("Parse(%q) canonical = %q, %v; want %q", input, query.Canonical, err, expected)
		}
	}
}

func FuzzCanonicalRoundTrip(f *testing.F) {
	for _, seed := range roundTripSeeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		assertRoundTrip(t, input)
	})
}

// TestCanonicalRoundTripRandomQueries is a deterministic fuzz-style table:
// it assembles thousands of queries from risky fragments and checks that
// every accepted query survives Parse -> Canonical -> Parse unchanged.
func TestCanonicalRoundTripRandomQueries(t *testing.T) {
	predicates := []string{
		`source:ZEEK`, `kind:zeek.conn`, `dst.port:443`, `src.port>=1024`, `bytes:>1KB`,
		`device.name:"TV<1>"`, `device.name:"a b"`, `device.name:"x=y"`, `device.name:"!bang"`,
		"device.name:\"nb sp\"", `device.tag:"lab gear"`, `http.path:"/a(b)"`, `http.path:/v1/*`,
		`dns.query:*.example.com`, `tls.sni:api.example.com`, `http.status>=500`, `time:last_15m`,
		`time:2026-09-01`, `time>2026-09-02`, `proto:mqtt`, `protocol.exotic:false`,
		`protocol.visibility:OPAQUE`, `src.ip:10.0.0.0/8`, `dst.ip:::ffff:1.2.3.4`, `netflix`,
		`tls.pinning:true`, `service:*`, `NOT device.id:*`,
	}
	connectors := []string{" ", " AND ", " OR ", " and ", " or "}
	random := rand.New(rand.NewSource(20260929))
	var build func(depth int) string
	build = func(depth int) string {
		if depth > 3 || random.Intn(3) == 0 {
			predicate := predicates[random.Intn(len(predicates))]
			switch random.Intn(5) {
			case 0:
				return "NOT " + predicate
			case 1:
				return "-" + predicate
			}
			return predicate
		}
		left := build(depth + 1)
		right := build(depth + 1)
		expression := left + connectors[random.Intn(len(connectors))] + right
		switch random.Intn(4) {
		case 0:
			return "(" + expression + ")"
		case 1:
			return "-(" + expression + ")"
		case 2:
			return "NOT (" + expression + ")"
		}
		return expression
	}
	accepted := 0
	for iteration := 0; iteration < 4000; iteration++ {
		input := build(0)
		if _, err := Parse(input); err == nil {
			accepted++
		}
		assertRoundTrip(t, input)
	}
	if accepted < 1000 {
		t.Fatalf("random query generator produced too few valid queries: %d", accepted)
	}
}

func TestProtocolFieldsCanonicalize(t *testing.T) {
	cases := map[string]string{
		`proto:MQTT`:                      `app.protocol:mqtt`,
		`app:ssl`:                         `app.protocol:tls`,
		`app.protocol:https`:              `app.protocol:tls`,
		`app.protocol:unknown-*`:          `app.protocol:unknown-*`,
		`protocol.category:IoT-Messaging`: `protocol.category:iot-messaging`,
		`protocol.visibility:opaque`:      `protocol.visibility:OPAQUE`,
		`protocol.exotic:TRUE`:            `protocol.exotic:true`,
		`-protocol.exotic:true`:           `NOT protocol.exotic:true`,
	}
	for input, expected := range cases {
		query, err := Parse(input)
		if err != nil || query.Canonical != expected {
			t.Fatalf("Parse(%q) canonical = %q, %v; want %q", input, query.Canonical, err, expected)
		}
	}
	for _, input := range []string{`proto:notaprotocol`, `protocol.category:gaming`, `protocol.visibility:MAYBE`, `protocol.exotic:yes`, `app.protocol>mqtt`} {
		if _, err := Parse(input); err == nil {
			t.Fatalf("Parse(%q) unexpectedly succeeded", input)
		}
	}
}

func TestParserGapsAreClosed(t *testing.T) {
	cases := map[string]string{
		`-(source:ZEEK OR source:SURICATA)`: `NOT (source:ZEEK OR source:SURICATA)`,
		`dns.query:_googlecast._tcp.local`:  `dns.query:_googlecast._tcp.local`,
		`dns.query:.`:                       `dns.query:.`,
		`src.ip:::ffff:10.77.0.23`:          `src.ip:10.77.0.23`,
		`dst.ip:2001:DB8::1`:                `dst.ip:2001:db8::1`,
		`dst.ip:2001:0db8::1`:               `dst.ip:2001:db8::1`,
		`src.ip:10.77.0.23/24`:              `src.ip:10.77.0.0/24`,
		`src.ip:::ffff:10.0.0.0/104`:        `src.ip:10.0.0.0/8`,
		`time:2026-09-01`:                   `time>=2026-09-01T00:00:00Z AND time<2026-09-02T00:00:00Z`,
		`time!=2026-09-01`:                  `time<2026-09-01T00:00:00Z OR time>=2026-09-02T00:00:00Z`,
		`time>2026-09-01`:                   `time>=2026-09-02T00:00:00Z`,
		`time<=2026-09-01`:                  `time<2026-09-02T00:00:00Z`,
		`netflix`:                           `text:netflix`,
		`Netflix.com youtube`:               `text:netflix.com AND text:youtube`,
		`source:ZEEK time:2026-09-01`:       `source:ZEEK AND (time>=2026-09-01T00:00:00Z AND time<2026-09-02T00:00:00Z)`,
	}
	for input, expected := range cases {
		query, err := Parse(input)
		if err != nil || query.Canonical != expected {
			t.Fatalf("Parse(%q) canonical = %q, %v; want %q", input, query.Canonical, err, expected)
		}
		assertRoundTrip(t, input)
	}
	for _, input := range []string{`src.ip:fe80::1%eth0`, `time:2026-13-01`, `bad/word`, `"quoted bare"`, `-`} {
		if _, err := Parse(input); err == nil {
			t.Fatalf("Parse(%q) unexpectedly succeeded", input)
		}
	}
	if query, err := Parse(`time:2026-09-01`); err != nil || strings.Contains(query.Canonical, "2026-09-01T00:00:00Z AND time<2026-09-01") {
		t.Fatalf("date-only time lost its day range: %#v %v", query, err)
	}
}
