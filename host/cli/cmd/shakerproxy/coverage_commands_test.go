package main

import (
	"strings"
	"testing"
)

const coverageOverview = `{"schema":1,"checked_at":"2026-10-02T04:05:00Z","gap_count":2,
 "last_run":{"schema":1,"run_id":"coverage-0123456789abcdef01234567","state":"COMPLETED","started_at":"2026-10-02T04:00:00Z",
  "results":[
   {"id":"dns-gateway","name":"DNS via ShakerProxy","category":"dns","status":"PASS","summary":"Seen","event_kinds":["shakerproxy.dns"],"latency_ms":2100,"attributed":false},
   {"id":"ssh","name":"SSH","category":"remote-access","status":"FAIL","summary":"Recorded but not identified as SSH","event_kinds":["zeek.conn"],"attributed":false,"missing":"SSH is not recognised"},
   {"id":"ipv6","name":"IPv6","category":"ip","status":"SKIP","summary":"The virtual test lab is IPv4-only.","event_kinds":[],"attributed":false}],
  "routing":[],"pass_count":1,"fail_count":1,"skip_count":1,"gap_count":2,"limitations":[]},
 "routing":[
  {"id":"device-to-device","title":"Device-to-device traffic","status":"GAP","detail":"Devices talk to each other directly.","fix":"Use ShakerProxy's Wi-Fi."},
  {"id":"ipv6-bypass","title":"IPv6","status":"OK","detail":"No IPv6 router was found."},
  {"id":"encrypted-dns","title":"Encrypted DNS","status":"GAP","detail":"DNS over TLS is allowed.","fix":"Block encrypted DNS."}]}`

func TestCoverageShowsWhatIsSeenAndEveryWayAround(t *testing.T) {
	api := newFakeAPI(t)
	api.json("GET /api/v1/coverage", 200, coverageOverview)
	c, _, _ := testCLI()
	code, stdout, stderr := runCLI(t, c, "coverage")
	if code != exitOK {
		t.Fatalf("coverage: %s", stderr)
	}
	for _, want := range []string{"1 seen, 1 missing or unidentified, 1 not probed", "DNS via ShakerProxy", "PASS", "shakerproxy.dns", "2.1 s",
		"SSH is not recognised", "IPv4-only", "Ways around ShakerProxy in this lab (2 gaps)", "[GAP] Device-to-device traffic", "Fix: Use ShakerProxy's Wi-Fi.", "[OK] IPv6"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("coverage output lacks %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "Fix: Block") && !strings.Contains(stdout, "[GAP] Encrypted DNS") {
		t.Fatal("fixes belong to gaps")
	}
	requests := api.find("GET", "/api/v1/coverage")
	if len(requests) != 1 || requests[0].Auth != "Bearer lgt_testtoken" {
		t.Fatalf("coverage request = %+v", requests)
	}
}

func TestCoverageRunNeedsThePassword(t *testing.T) {
	newFakeAPI(t)
	c, _, _ := testCLI()
	code, _, stderr := runCLI(t, c, "coverage", "run")
	if code == exitOK || !strings.Contains(stderr, "--password-file") {
		t.Fatalf("coverage run without a password: code %d %s", code, stderr)
	}
}
