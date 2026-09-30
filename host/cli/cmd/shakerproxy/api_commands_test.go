package main

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type recordedRequest struct {
	Method string
	Path   string
	Query  string
	Auth   string
	Header http.Header
	Body   []byte
}

type fakeAPI struct {
	t         *testing.T
	server    *httptest.Server
	tokenPath string
	mu        sync.Mutex
	requests  []recordedRequest
	handlers  map[string]func(http.ResponseWriter, recordedRequest)
}

func newFakeAPI(t *testing.T) *fakeAPI {
	t.Helper()
	api := &fakeAPI{t: t, handlers: map[string]func(http.ResponseWriter, recordedRequest){}}
	api.server = httptest.NewTLSServer(http.HandlerFunc(api.serve))
	t.Cleanup(api.server.Close)
	directory := t.TempDir()
	caPath := filepath.Join(directory, "management-ca.crt")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: api.server.Certificate().Raw}), 0o644); err != nil {
		t.Fatal(err)
	}
	api.tokenPath = filepath.Join(directory, "cli-api-token")
	if err := os.WriteFile(api.tokenPath, []byte("lgt_testtoken\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SHAKERPROXY_API_URL", api.server.URL)
	t.Setenv("SHAKERPROXY_MANAGEMENT_CA_PATH", caPath)
	t.Setenv("SHAKERPROXY_API_TOKEN_FILE", api.tokenPath)
	return api
}

func (a *fakeAPI) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	request := recordedRequest{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery, Auth: r.Header.Get("Authorization"), Header: r.Header.Clone(), Body: body}
	a.mu.Lock()
	a.requests = append(a.requests, request)
	handler := a.handlers[r.Method+" "+r.URL.Path]
	a.mu.Unlock()
	if handler == nil {
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/devices/") && strings.Count(r.URL.Path, "/") == 4 {
			// Like the real router: GET /devices/{deviceID} catches unknown
			// single segments such as "resolve" and rejects them.
			writeTestJSON(w, http.StatusBadRequest, `{"error":{"code":"invalid_device_id","message":"device ID is invalid"}}`)
			return
		}
		writeTestJSON(w, http.StatusNotFound, `{"error":{"code":"not_found","message":"No such API route."}}`)
		return
	}
	handler(w, request)
}

func (a *fakeAPI) handle(pattern string, handler func(http.ResponseWriter, recordedRequest)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.handlers[pattern] = handler
}

func (a *fakeAPI) json(pattern string, status int, body string) {
	a.handle(pattern, func(w http.ResponseWriter, _ recordedRequest) { writeTestJSON(w, status, body) })
}

func (a *fakeAPI) find(method, path string) []recordedRequest {
	a.mu.Lock()
	defer a.mu.Unlock()
	var result []recordedRequest
	for _, request := range a.requests {
		if request.Method == method && request.Path == path {
			result = append(result, request)
		}
	}
	return result
}

func writeTestJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

const tvID = "device-0123456789abcdef0123456789abcdef"
const camID = "device-fedcba9876543210fedcba9876543210"

const tvMatch = `{"device_id":"` + tvID + `","friendly_name":"Living room TV","vendor":"Samsung","addresses":["10.77.0.23"],"hardware_addresses":["aa:bb:cc:dd:ee:ff"],"online":true,"match":"name_prefix"}`

const tvDevice = `{"schema":1,"id":"` + tvID + `","friendly_name":"Living room TV","alias_revision":3,"category":"tv","vendor":{"name":"Samsung"},
 "identities":[{"kind":"MAC","value":"AA:BB:CC:DD:EE:FF"}],"addresses":[{"address":"10.77.0.23","family":"ipv4","active":true}],
 "hostnames":[],"first_seen":"2026-09-28T10:00:00Z","last_seen":"2026-09-29T11:55:00Z","online":true,"attribution_confidence":90}`

const camDevice = `{"schema":1,"id":"` + camID + `","friendly_name":"","vendor":{"name":"Hikvision"},
 "identities":[{"kind":"MAC","value":"11:22:33:44:55:66"}],"addresses":[{"address":"10.77.0.40","family":"ipv4","active":false}],
 "hostnames":[{"hostname":"ipcam-1"}],"first_seen":"2026-09-20T10:00:00Z","last_seen":"2026-09-27T12:00:00Z","online":false,"attribution_confidence":60}`

func TestAPICommandsExplainMissingOrUnsafeToken(t *testing.T) {
	api := newFakeAPI(t)
	c, _, _ := testCLI()
	if err := os.Remove(api.tokenPath); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runCLI(t, c, "devices")
	if code != exitFailure || !strings.Contains(stderr, "You are not logged in") || !strings.Contains(stderr, "Run `shakerproxy login` first.") {
		t.Fatalf("missing token: %d %s", code, stderr)
	}
	if err := os.WriteFile(api.tokenPath, []byte("lgt_x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, stderr = runCLI(t, c, "devices")
	if code != exitFailure || !strings.Contains(stderr, "readable by other users") || !strings.Contains(stderr, "chmod 600") {
		t.Fatalf("broad token permissions: %d %s", code, stderr)
	}
}

func TestDevicesListsHumanTableAndRawJSON(t *testing.T) {
	api := newFakeAPI(t)
	api.json("GET /api/v1/devices", 200, `{"schema":1,"generated_at":"2026-09-29T12:00:00Z","devices":[`+tvDevice+`,`+camDevice+`]}`)
	c, _, _ := testCLI()
	code, stdout, stderr := runCLI(t, c, "devices", "--online")
	if code != exitOK {
		t.Fatalf("devices: %s", stderr)
	}
	for _, want := range []string{"NAME", "Living room TV", "Samsung", "10.77.0.23", "aa:bb:cc:dd:ee:ff", "online", "5m ago", "ipcam-1", "offline", "2 devices."} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("devices output lacks %q:\n%s", want, stdout)
		}
	}
	requests := api.find("GET", "/api/v1/devices")
	if len(requests) != 1 || requests[0].Query != "view=online" || requests[0].Auth != "Bearer lgt_testtoken" {
		t.Fatalf("unexpected devices request %+v", requests)
	}
	code, stdout, _ = runCLI(t, c, "devices", "--json")
	var decoded map[string]any
	if code != exitOK || json.Unmarshal([]byte(stdout), &decoded) != nil || decoded["generated_at"] == nil {
		t.Fatalf("devices --json is not the raw API document:\n%s", stdout)
	}
}

func TestAmbiguousDeviceListsCandidates(t *testing.T) {
	api := newFakeAPI(t)
	kitchen := strings.NewReplacer(tvID, camID, "Living room TV", "Kitchen TV", "10.77.0.23", "10.77.0.31", "aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66").Replace(tvMatch)
	api.json("GET /api/v1/devices/resolve", 200, `{"schema":1,"query":"tv","unique":false,"matches":[`+tvMatch+`,`+kitchen+`]}`)
	c, _, _ := testCLI()
	code, _, stderr := runCLI(t, c, "device", "tv")
	if code != exitFailure {
		t.Fatalf("ambiguous device exited %d", code)
	}
	for _, want := range []string{`"tv" matches 2 devices`, "Living room TV", "Kitchen TV", "10.77.0.31", "e.g. 10.77.0.23"} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("ambiguous output lacks %q:\n%s", want, stderr)
		}
	}
	api.json("GET /api/v1/devices/tv/report", 409, `{"error":{"code":"device_ambiguous","message":"\"tv\" matches 2 devices.","candidates":[`+tvMatch+`,`+kitchen+`]}}`)
	code, _, stderr = runCLI(t, c, "report", "tv")
	if code != exitFailure || !strings.Contains(stderr, "Kitchen TV") || !strings.Contains(stderr, "NAME") {
		t.Fatalf("409 device_ambiguous rendering: %d\n%s", code, stderr)
	}
}

func TestDeviceDetailsCombineControlsTestAndFindings(t *testing.T) {
	api := newFakeAPI(t)
	api.json("GET /api/v1/devices/resolve", 200, `{"schema":1,"query":"tv","unique":true,"matches":[`+tvMatch+`]}`)
	api.json("GET /api/v1/devices/"+tvID, 200, tvDevice)
	api.json("GET /api/v1/devices/"+tvID+"/controls", 200, `{"schema":1,"device_id":"`+tvID+`","decrypt_https":true,"internet":"ALLOW","blocked_domains":["ads.example.com"],"effective":true}`)
	api.json("GET /api/v1/devices/"+tvID+"/report", 200, `{"schema":1,"device":{"device_id":"`+tvID+`"},"ca_trust":"INSTALLED","totals":{"events":10,"bytes":5000},
	  "findings":[{"id":"cleartext-http","severity":"MEDIUM","title":"Cleartext HTTP"},{"id":"accepts-untrusted-certificates","severity":"CRITICAL","title":"Device accepts untrusted certificates"}]}`)
	api.json("GET /api/v1/test-sessions", 200, `{"schema":1,"sessions":[{"id":"ts-0123456789abcdef01234567","device_id":"`+tvID+`","name":"Firmware 2.1","state":"RUNNING","started_at":"2026-09-29T11:00:00Z"}]}`)
	c, _, _ := testCLI()
	code, stdout, stderr := runCLI(t, c, "device", "tv")
	if code != exitOK {
		t.Fatalf("device: %s", stderr)
	}
	for _, want := range []string{"Living room TV", "Decrypt HTTPS", "on", "ads.example.com", "installed on the device", "Firmware 2.1", "CRITICAL", "Cleartext HTTP", "Next: shakerproxy watch tv"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("device output lacks %q:\n%s", want, stdout)
		}
	}
	if strings.Index(stdout, "CRITICAL") > strings.Index(stdout, "MEDIUM") {
		t.Fatalf("findings are not ordered by severity:\n%s", stdout)
	}
	if tests := api.find("GET", "/api/v1/test-sessions"); len(tests) != 1 || !strings.Contains(tests[0].Query, "state=RUNNING") {
		t.Fatalf("running test lookup: %+v", tests)
	}
}

func TestResolveFallsBackToDeviceListOnOlderControlAPI(t *testing.T) {
	api := newFakeAPI(t)
	api.json("GET /api/v1/devices", 200, `{"schema":1,"devices":[`+tvDevice+`,`+camDevice+`]}`)
	api.json("GET /api/v1/devices/"+tvID, 200, tvDevice)
	c, _, _ := testCLI()
	code, stdout, stderr := runCLI(t, c, "device", "AA-BB-CC-DD-EE-FF")
	if code != exitOK || !strings.Contains(stdout, "Living room TV") || !strings.Contains(stdout, "Findings: unavailable") {
		t.Fatalf("fallback by MAC: %d\n%s\n%s", code, stdout, stderr)
	}
	matches := matchDevicesLocally([]inventoryDevice{{ID: tvID, FriendlyName: "Living room TV"}, {ID: camID, FriendlyName: "Living room lamp"}}, "living room")
	if len(matches) != 2 {
		t.Fatalf("prefix matches should be ambiguous: %+v", matches)
	}
	if matches = matchDevicesLocally([]inventoryDevice{{ID: tvID, FriendlyName: "Living room TV"}, {ID: camID, FriendlyName: "TV"}}, "tv"); len(matches) != 1 || matches[0].DeviceID != camID {
		t.Fatalf("exact name must win over substring: %+v", matches)
	}
}

func TestWatchPrintsPlainLanguageLinesForOneDevice(t *testing.T) {
	api := newFakeAPI(t)
	api.json("GET /api/v1/devices/resolve", 200, `{"schema":1,"unique":true,"matches":[`+tvMatch+`]}`)
	api.json("GET /api/v1/events", 200, `{"schema":1,"events":[
	  {"record_id":"b","occurred_at":"2026-09-29T11:59:02Z","summary":"HTTPS api.samsungcloud.com — decrypted"},
	  {"record_id":"a","occurred_at":"2026-09-29T11:59:01Z","dns_query":"api.samsungcloud.com","dns_record_type":"A","dns_answer_count":3},
	  {"record_id":"c","occurred_at":"2026-09-29T11:59:03Z","detection_severity":"HIGH","detection_summary":"ET POLICY telnet"}]}`)
	c, _, _ := testCLI()
	c.maxPolls = 1
	code, stdout, stderr := runCLI(t, c, "watch", "Living room TV")
	if code != exitOK {
		t.Fatalf("watch: %s", stderr)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 3 || !strings.Contains(lines[0], "DNS lookup api.samsungcloud.com (A) → 3 answers") || !strings.Contains(lines[1], "HTTPS api.samsungcloud.com — decrypted") || !strings.Contains(lines[2], "Alert (HIGH): ET POLICY telnet") {
		t.Fatalf("unexpected watch output:\n%s", stdout)
	}
	events := api.find("GET", "/api/v1/events")
	if len(events) != 1 || !strings.Contains(events[0].Query, "device_id="+tvID) || !strings.Contains(events[0].Query, "limit=50") {
		t.Fatalf("watch did not filter by device: %+v", events)
	}
	if !strings.Contains(stderr, "Watching Living room TV") {
		t.Fatalf("watch banner missing: %s", stderr)
	}
}

func TestSearchAddsTimeWindowAndExplainsBadQueries(t *testing.T) {
	api := newFakeAPI(t)
	api.json("GET /api/v1/events", 200, `{"schema":1,"events":[{"record_id":"a","occurred_at":"2026-09-29T11:00:00Z","device_friendly_name":"Living room TV","summary":"DNS lookup api.example.com (A) → 1 answer"}],"next_cursor":"x"}`)
	c, _, _ := testCLI()
	code, stdout, stderr := runCLI(t, c, "search", "dns.query:*.example.com", "--window", "24h")
	if code != exitOK || !strings.Contains(stdout, "Living room TV") || !strings.Contains(stdout, "DNS lookup api.example.com") || !strings.Contains(stdout, "Narrow the query") {
		t.Fatalf("search: %d\n%s\n%s", code, stdout, stderr)
	}
	query := api.find("GET", "/api/v1/events")[0].Query
	if !strings.Contains(query, "q=%28dns.query%3A%2A.example.com%29+AND+time%3Alast_24h") {
		t.Fatalf("search query did not add the window: %s", query)
	}
	api.json("GET /api/v1/events", 400, `{"error":{"code":"invalid_query","message":"event query language is invalid: unknown field"}}`)
	code, _, stderr = runCLI(t, c, "search", "bogus:field")
	if code != exitFailure || !strings.Contains(stderr, "unknown field") || !strings.Contains(stderr, "shakerproxy help search") {
		t.Fatalf("bad query: %d %s", code, stderr)
	}
}

func TestTestRunLifecycle(t *testing.T) {
	api := newFakeAPI(t)
	session := `{"schema":1,"id":"ts-0123456789abcdef01234567","device_id":"` + tvID + `","device_name":"Living room TV","name":"Firmware 2.1 first boot","state":"RUNNING","started_at":"2026-09-29T11:30:00Z","ended_at":null,"capture_session_id":null,"warnings":["Capture is unavailable; the test started without recording."]}`
	api.json("POST /api/v1/test-sessions", 201, session)
	c, _, _ := testCLI()
	code, stdout, stderr := runCLI(t, c, "test", "start", "Living room TV", "--name", "Firmware 2.1 first boot", "--capture")
	if code != exitOK || !strings.Contains(stdout, `Started test "Firmware 2.1 first boot" on Living room TV`) || !strings.Contains(stdout, "! Capture is unavailable") || !strings.Contains(stdout, `shakerproxy test stop "Living room TV"`) {
		t.Fatalf("test start: %d\n%s\n%s", code, stdout, stderr)
	}
	var body map[string]any
	if err := json.Unmarshal(api.find("POST", "/api/v1/test-sessions")[0].Body, &body); err != nil || body["device"] != "Living room TV" || body["capture"] != true || body["name"] != "Firmware 2.1 first boot" {
		t.Fatalf("unexpected start body %v %v", body, err)
	}
	api.json("GET /api/v1/test-sessions", 200, `{"sessions":[`+session+`]}`)
	stopped := strings.Replace(strings.Replace(session, `"RUNNING"`, `"STOPPED"`, 1), `"ended_at":null`, `"ended_at":"2026-09-29T11:42:00Z"`, 1)
	api.json("POST /api/v1/test-sessions/ts-0123456789abcdef01234567/stop", 200, stopped)
	code, stdout, stderr = runCLI(t, c, "test", "stop")
	if code != exitOK || !strings.Contains(stdout, `Stopped test "Firmware 2.1 first boot" after 12m.`) || !strings.Contains(stdout, "--session ts-0123456789abcdef01234567") {
		t.Fatalf("test stop: %d\n%s\n%s", code, stdout, stderr)
	}
	second := strings.Replace(session, "ts-0123456789abcdef01234567", "ts-aaaaaaaaaaaaaaaaaaaaaaaa", 1)
	api.json("GET /api/v1/test-sessions", 200, `[`+session+`,`+second+`]`)
	code, _, stderr = runCLI(t, c, "test", "stop")
	if code != exitFailure || !strings.Contains(stderr, "2 tests are running") || !strings.Contains(stderr, "ts-aaaaaaaaaaaaaaaaaaaaaaaa") {
		t.Fatalf("ambiguous stop: %d %s", code, stderr)
	}
	code, stdout, _ = runCLI(t, c, "test", "list")
	if code != exitOK || !strings.Contains(stdout, "Firmware 2.1 first boot") || !strings.Contains(stdout, "RUNNING") {
		t.Fatalf("test list: %d\n%s", code, stdout)
	}
}

const sampleReport = `{"schema":1,"generated_at":"2026-09-29T12:00:00Z",
 "device":{"device_id":"` + tvID + `","friendly_name":"Living room TV","vendor":"Samsung","addresses":["10.77.0.23"],"hardware_addresses":["aa:bb:cc:dd:ee:ff"],"online":true},
 "window_start":"2026-09-28T12:00:00Z","window_end":"2026-09-29T12:00:00Z","session":null,"ca_trust":"NOT_INSTALLED",
 "totals":{"events":1234,"flows":456,"bytes":12300000,"dns_queries":89,"tls_connections":34,"http_requests":12,"alerts":1},
 "domains":[{"domain":"<script>alert(1)</script>.evil.example","organization":"Evil <b>Inc</b>","category":"telemetry","sources":["dns","tls"],"events":12,"first_seen":"2026-09-28T13:00:00Z","last_seen":"2026-09-29T11:00:00Z"}],
 "tls":{"intercepted":10,"bypassed":3,"failed":1,"pinning_suspected":1,"failed_hosts":["pinned.example.com"],"old_versions":[{"version":"TLSv1.0","hosts":["old.example.com"]}]},
 "http":{"requests":12,"hosts":3,"cleartext_requests":2,"status_classes":{"2xx":10,"4xx":2}},
 "findings":[{"id":"cleartext-http","severity":"MEDIUM","title":"Cleartext HTTP","detail":"2 requests were sent without encryption.","recommendation":"Use HTTPS.","evidence":["GET http://x.example/ at 2026-09-29T10:00:00Z"]},
  {"id":"accepts-untrusted-certificates","severity":"CRITICAL","title":"Device accepts untrusted certificates","detail":"TLS was intercepted without the CA installed.","recommendation":"Fix certificate validation.","evidence":["api.example.com at 2026-09-29T10:00:00Z"]}],
 "truncated":false}`

func TestReportTextAndSelfContainedHTML(t *testing.T) {
	api := newFakeAPI(t)
	api.json("GET /api/v1/devices/Living room TV/report", 200, sampleReport)
	c, _, _ := testCLI()
	code, stdout, stderr := runCLI(t, c, "report", "Living room TV", "--session", "ts-0123456789abcdef01234567")
	if code != exitOK {
		t.Fatalf("report: %s", stderr)
	}
	for _, want := range []string{"Device report: Living room TV", "Findings (2)", "CRITICAL", "→ Fix certificate validation.", "1,234 events", "12.3 MB", "10 decrypted, 3 not decrypted, 1 failed (pinning suspected on 1)", "TLSv1.0: old.example.com", "2xx 10 · 4xx 2", "not installed"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("report text lacks %q:\n%s", want, stdout)
		}
	}
	if query := api.find("GET", "/api/v1/devices/Living room TV/report")[0].Query; query != "session=ts-0123456789abcdef01234567" {
		t.Fatalf("report query %q", query)
	}
	output := filepath.Join(t.TempDir(), "tv-report.html")
	code, stdout, stderr = runCLI(t, c, "report", "Living room TV", "--html", output)
	if code != exitOK || !strings.Contains(stdout, "Wrote "+output+" (2 findings") {
		t.Fatalf("report --html: %d\n%s\n%s", code, stdout, stderr)
	}
	page, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	html := string(page)
	for _, want := range []string{"<!doctype html>", "Content-Security-Policy", "Living room TV", "Device accepts untrusted certificates", "&lt;script&gt;alert(1)&lt;/script&gt;.evil.example", "Evil &lt;b&gt;Inc&lt;/b&gt;", "sev-critical", "pinned.example.com"} {
		if !strings.Contains(html, want) {
			t.Fatalf("HTML report lacks %q", want)
		}
	}
	if strings.Contains(html, "<script>") || strings.Contains(html, "<b>Inc") || strings.Contains(html, "http://") && strings.Contains(html, "src=\"http") {
		t.Fatal("HTML report contains unescaped or external content")
	}
	if strings.Index(html, "Device accepts untrusted certificates") > strings.Index(html, "Cleartext HTTP") {
		t.Fatal("HTML findings are not sorted by severity")
	}
	// A second run replaces the file instead of failing.
	if code, _, stderr := runCLI(t, c, "report", "Living room TV", "--html", output); code != exitOK {
		t.Fatalf("report --html could not replace its file: %s", stderr)
	}
}

func TestCompareShowsDifferences(t *testing.T) {
	api := newFakeAPI(t)
	api.json("GET /api/v1/test-sessions/ts-aaaaaaaaaaaaaaaaaaaaaaaa", 200, `{"id":"ts-aaaaaaaaaaaaaaaaaaaaaaaa","device_id":"`+tvID+`"}`)
	api.json("GET /api/v1/devices/"+tvID+"/compare", 200, `{"schema":1,"device_id":"`+tvID+`","base":{"totals":{"events":10}},"compare":{"totals":{"events":20}},
	  "domains":{"added":["new.example.com"],"removed":["old.example.com"]},"protocols":{"added":["mqtt"],"removed":[]},
	  "findings":{"new":[{"severity":"HIGH","title":"Telnet exposed"}],"resolved":[]},"tls":{"newly_failed_hosts":["pinned.example.com"],"newly_intercepted_hosts":[]}}`)
	c, _, _ := testCLI()
	code, stdout, stderr := runCLI(t, c, "compare", "ts-aaaaaaaaaaaaaaaaaaaaaaaa", "ts-bbbbbbbbbbbbbbbbbbbbbbbb")
	if code != exitOK {
		t.Fatalf("compare: %s", stderr)
	}
	for _, want := range []string{"+ new.example.com", "- old.example.com", "+ mqtt", "new HIGH", "Telnet exposed", "TLS newly failing: pinned.example.com"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("compare lacks %q:\n%s", want, stdout)
		}
	}
	if query := api.find("GET", "/api/v1/devices/"+tvID+"/compare")[0].Query; query != "base=ts-aaaaaaaaaaaaaaaaaaaaaaaa&compare=ts-bbbbbbbbbbbbbbbbbbbbbbbb" {
		t.Fatalf("compare query %q", query)
	}
}

func TestDeviceControlsWriteFullDesiredState(t *testing.T) {
	api := newFakeAPI(t)
	var current = map[string]any{"schema": 1, "device_id": tvID, "decrypt_https": false, "internet": "ALLOW", "blocked_domains": []string{"ads.example.com"}, "effective": true}
	var mu sync.Mutex
	api.handle("GET /api/v1/devices/tv/controls", func(w http.ResponseWriter, _ recordedRequest) {
		mu.Lock()
		defer mu.Unlock()
		encoded, _ := json.Marshal(current)
		writeTestJSON(w, 200, string(encoded))
	})
	api.handle("PUT /api/v1/devices/tv/controls", func(w http.ResponseWriter, request recordedRequest) {
		mu.Lock()
		defer mu.Unlock()
		var body map[string]any
		_ = json.Unmarshal(request.Body, &body)
		for key, value := range body {
			current[key] = value
		}
		current["effective"] = body["internet"] != "BLOCK"
		current["notes"] = []string{"Domain blocking needs ShakerProxy DNS enforcement; it was enabled for this device."}
		encoded, _ := json.Marshal(current)
		writeTestJSON(w, 200, string(encoded))
	})
	c, _, _ := testCLI()
	code, stdout, stderr := runCLI(t, c, "decrypt", "tv", "on")
	if code != exitOK || !strings.Contains(stdout, "HTTPS decryption is on for tv.") || !strings.Contains(stdout, "shakerproxy ca") {
		t.Fatalf("decrypt on: %d\n%s\n%s", code, stdout, stderr)
	}
	code, stdout, _ = runCLI(t, c, "block", "tv", "*.Tracker.Example.COM.")
	if code != exitOK || !strings.Contains(stdout, "Blocked tracker.example.com and its subdomains for tv.") || !strings.Contains(stdout, "ShakerProxy DNS enforcement") {
		t.Fatalf("block domain: %d\n%s", code, stdout)
	}
	code, stdout, _ = runCLI(t, c, "block", "tv", "internet")
	if code != exitOK || !strings.Contains(stdout, "Not fully in effect yet") {
		t.Fatalf("block internet: %d\n%s", code, stdout)
	}
	puts := api.find("PUT", "/api/v1/devices/tv/controls")
	var last map[string]any
	if err := json.Unmarshal(puts[len(puts)-1].Body, &last); err != nil || last["decrypt_https"] != true || last["internet"] != "BLOCK" || fmt.Sprint(last["blocked_domains"]) != "[ads.example.com tracker.example.com]" {
		t.Fatalf("PUT did not carry the full desired state: %v %v", last, err)
	}
	code, stdout, _ = runCLI(t, c, "unblock", "tv", "--all")
	puts = api.find("PUT", "/api/v1/devices/tv/controls")
	if err := json.Unmarshal(puts[len(puts)-1].Body, &last); code != exitOK || err != nil || last["internet"] != "ALLOW" || fmt.Sprint(last["blocked_domains"]) != "[]" || last["decrypt_https"] != true {
		t.Fatalf("unblock --all: %d %v %s", code, last, stdout)
	}
}

func TestProtocolsTableAndUnsupportedRoute(t *testing.T) {
	api := newFakeAPI(t)
	c, _, _ := testCLI()
	code, _, stderr := runCLI(t, c, "protocols")
	if code != exitFailure || !strings.Contains(stderr, "does not support GET /api/v1/protocols yet") || !strings.Contains(stderr, "sudo shakerproxy update") {
		t.Fatalf("unsupported route: %d %s", code, stderr)
	}
	api.json("GET /api/v1/protocols", 200, `{"schema":1,"window":"24h","protocols":[{"protocol":"mqtt","label":"MQTT","category":"iot-messaging","visibility":"CLEARTEXT","exotic":true,"novel":true,"flows":12,"bytes":3456,"device_count":1,"devices":[{"device_id":"`+camID+`","device_name":"Bench camera"}]}],
	  "coverage":{"total_bytes":10000,"decrypted_bytes":5000,"cleartext_bytes":3456,"encrypted_metadata_bytes":1000,"opaque_bytes":544,"opaque_percent":5.4}}`)
	// The protocols route accepts device IDs, so the CLI resolves the name first.
	api.json("GET /api/v1/devices/resolve", 200, `{"schema":1,"unique":true,"matches":[{"device_id":"`+camID+`","friendly_name":"Bench camera"}]}`)
	code, stdout, stderr := runCLI(t, c, "protocols", "Bench camera", "--exotic", "--window", "7d")
	if code != exitOK || !strings.Contains(stdout, "MQTT") || !strings.Contains(stdout, "cleartext") || !strings.Contains(stdout, "new, unusual") || !strings.Contains(stdout, "(5%)") {
		t.Fatalf("protocols: %d\n%s\n%s", code, stdout, stderr)
	}
	query := api.find("GET", "/api/v1/protocols")[1].Query
	if !strings.Contains(query, "device="+camID) || !strings.Contains(query, "exotic=true") || !strings.Contains(query, "window=7d") {
		t.Fatalf("protocols query %q", query)
	}
}

func TestBareAPICommandShowsIndexAndAdminSessionsAreSignedOut(t *testing.T) {
	api := newFakeAPI(t)
	api.json("GET /api/v1", 200, `{"schema":1,"resources":[{"path":"/api/v1/devices","description":"Devices on the lab network"}]}`)
	c, _, _ := testCLI()
	code, stdout, stderr := runCLI(t, c, "api")
	if code != exitOK || !strings.Contains(stdout, "/api/v1/devices") || !strings.Contains(stderr, "openapi.yaml") {
		t.Fatalf("api index: %d\n%s\n%s", code, stdout, stderr)
	}
	if index := api.find("GET", "/api/v1"); len(index) != 1 || index[0].Auth != "" {
		t.Fatalf("index should be fetched anonymously: %+v", index)
	}
	loginHandlers(api, true)
	api.json("POST /api/v1/auth/logout", 200, `{"schema":1,"logged_out":true}`)
	c.stdin = strings.NewReader("correct horse\n")
	if code, _, stderr := runCLI(t, c, "login", "--password-stdin"); code != exitOK {
		t.Fatal(stderr)
	}
	if logouts := api.find("POST", "/api/v1/auth/logout"); len(logouts) != 1 || logouts[0].Auth != "Bearer session-1" {
		t.Fatalf("admin session was not signed out: %+v", logouts)
	}
}

func TestCAShowsURLQRCodeAndFingerprint(t *testing.T) {
	api := newFakeAPI(t)
	api.json("GET /api/v1/interception-ca/onboarding", 200, `{"schema":1,"available":true,"sha256_fingerprint":"AB:CD:EF","common_name":"ShakerProxy Interception CA","not_after":"2027-09-29T00:00:00Z",
	  "urls":[{"label":"Lab network","url":"http://10.77.0.1/"}],
	  "instructions":[{"platform":"ios","title":"iPhone / iPad","steps":["Open http://10.77.0.1/ in Safari","Install the profile"],"limitations":["Apps may pin certificates."]}]}`)
	c, _, _ := testCLI()
	code, stdout, stderr := runCLI(t, c, "ca")
	if code != exitOK {
		t.Fatalf("ca: %s", stderr)
	}
	for _, want := range []string{"http://10.77.0.1/", "█", "AB:CD:EF", "valid until 2027-09-29", "iPhone / iPad", "shakerproxy decrypt <device> on"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("ca output lacks %q:\n%s", want, stdout)
		}
	}
	code, stdout, _ = runCLI(t, c, "ca", "--platform", "ios")
	if code != exitOK || !strings.Contains(stdout, "2. Install the profile") || !strings.Contains(stdout, "Apps may pin certificates.") {
		t.Fatalf("ca --platform: %d\n%s", code, stdout)
	}
	api.json("GET /api/v1/interception-ca/onboarding", 200, `{"schema":1,"available":false,"reason":"Apply a routed network plan first."}`)
	code, _, stderr = runCLI(t, c, "ca")
	if code != exitFailure || !strings.Contains(stderr, "Apply a routed network plan first.") {
		t.Fatalf("unavailable CA: %d %s", code, stderr)
	}
}

func TestCATrustIsRecordedPerDevice(t *testing.T) {
	api := newFakeAPI(t)
	api.json("PUT /api/v1/devices/Living room TV/ca-trust", 200, `{"schema":1,"device_id":"`+tvID+`","ca_trust":"NOT_INSTALLED","updated_at":"2026-09-29T12:00:00Z"}`)
	c, _, _ := testCLI()
	code, stdout, stderr := runCLI(t, c, "ca", "Living room TV", "not-installed")
	if code != exitOK || !strings.Contains(stdout, "does not trust the ShakerProxy CA") {
		t.Fatalf("ca trust: %d\n%s\n%s", code, stdout, stderr)
	}
	if body := string(api.find("PUT", "/api/v1/devices/Living room TV/ca-trust")[0].Body); body != `{"state":"NOT_INSTALLED"}` {
		t.Fatalf("unexpected ca-trust body %s", body)
	}
	if code, _, stderr := runCLI(t, c, "ca", "tv", "maybe"); code != exitUsage || !strings.Contains(stderr, "installed, not-installed or unknown") {
		t.Fatalf("bad ca trust state: %d %s", code, stderr)
	}
}

func TestWatchOrdersMixedPrecisionTimestamps(t *testing.T) {
	early := eventRecord{OccurredAt: "2026-09-29T11:59:01Z"}
	late := eventRecord{OccurredAt: "2026-09-29T11:59:01.5Z"}
	if !eventBefore(early, late) || eventBefore(late, early) {
		t.Fatal("events with different fractional precision are misordered")
	}
}

func TestExpiredTokenSuggestsLoginAgain(t *testing.T) {
	api := newFakeAPI(t)
	api.json("GET /api/v1/devices", 401, `{"error":{"code":"invalid_api_token","message":"API token is invalid, expired, or revoked"}}`)
	c, _, _ := testCLI()
	code, _, stderr := runCLI(t, c, "devices")
	if code != exitFailure || !strings.Contains(stderr, "rejected the stored token") || !strings.Contains(stderr, "shakerproxy login") {
		t.Fatalf("expired token: %d %s", code, stderr)
	}
}

func loginHandlers(api *fakeAPI, supportLabWrite bool) {
	api.handle("POST /api/v1/auth/login", func(w http.ResponseWriter, request recordedRequest) {
		var body map[string]string
		_ = json.Unmarshal(request.Body, &body)
		if body["username"] != "admin" || body["password"] != "correct horse" {
			writeTestJSON(w, 401, `{"error":{"code":"invalid_credentials","message":"invalid credentials"}}`)
			return
		}
		writeTestJSON(w, 200, `{"session_token":"session-1","expires_in_seconds":3600}`)
	})
	tokenNumber := 0
	api.handle("POST /api/v1/auth/tokens", func(w http.ResponseWriter, request recordedRequest) {
		var body struct {
			Scopes []string `json:"scopes"`
		}
		_ = json.Unmarshal(request.Body, &body)
		if !supportLabWrite && strings.Contains(strings.Join(body.Scopes, ","), "lab:write") {
			writeTestJSON(w, 400, `{"error":{"code":"api_token_rejected","message":"API token scope lab:write is unsupported"}}`)
			return
		}
		tokenNumber++
		writeTestJSON(w, 201, fmt.Sprintf(`{"token":{"id":"tok_%024d","name":"shakerproxy cli","scopes":%s,"expires_at":"2026-12-28T12:00:00Z"},"secret":"lgt_secret%d"}`, tokenNumber, mustJSON(body.Scopes), tokenNumber))
	})
	api.json("DELETE /api/v1/auth/tokens/tok_000000000000000000000001", 200, `{"token":{"id":"tok_000000000000000000000001"}}`)
}

func mustJSON(value any) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func TestLoginStoresPrivateTokenAndReplacesPrevious(t *testing.T) {
	api := newFakeAPI(t)
	loginHandlers(api, true)
	if err := os.Remove(api.tokenPath); err != nil {
		t.Fatal(err)
	}
	c, _, _ := testCLI()
	c.stdin = strings.NewReader("correct horse\n")
	code, stdout, stderr := runCLI(t, c, "login", "--password-stdin")
	if code != exitOK || !strings.Contains(stdout, "Logged in as admin. Token saved to "+api.tokenPath+" (valid until 2026-12-28).") {
		t.Fatalf("login: %d\n%s\n%s", code, stdout, stderr)
	}
	info, err := os.Lstat(api.tokenPath)
	secret, _ := os.ReadFile(api.tokenPath)
	if err != nil || info.Mode().Perm() != 0o600 || string(secret) != "lgt_secret1\n" {
		t.Fatalf("token file: %v %v %q", info, err, secret)
	}
	created := api.find("POST", "/api/v1/auth/tokens")[0]
	var body map[string]any
	_ = json.Unmarshal(created.Body, &body)
	if created.Auth != "Bearer session-1" || body["expires_in_seconds"] != float64(90*24*3600) || body["sensitive_scope_acknowledged"] != true || body["password"] != "correct horse" ||
		fmt.Sprint(body["scopes"]) != "[system:read devices:read traffic:read captures:read captures:write cases:read lab:write]" {
		t.Fatalf("unexpected token request %v auth=%s", body, created.Auth)
	}
	metadata := readTokenMetadata()
	if metadata == nil || metadata.TokenID != "tok_000000000000000000000001" {
		t.Fatalf("token metadata was not saved: %+v", metadata)
	}
	c.stdin = strings.NewReader("correct horse\n")
	if code, _, stderr := runCLI(t, c, "login", "--password-stdin"); code != exitOK {
		t.Fatalf("second login: %s", stderr)
	}
	if revoked := api.find("DELETE", "/api/v1/auth/tokens/tok_000000000000000000000001"); len(revoked) != 1 || !strings.Contains(string(revoked[0].Body), "replaced by shakerproxy login") {
		t.Fatalf("previous token was not revoked: %+v", revoked)
	}
	c.stdin = strings.NewReader("wrong\n")
	code, _, stderr = runCLI(t, c, "login", "--password-stdin")
	if code != exitFailure || !strings.Contains(stderr, "Wrong username or password.") || !strings.Contains(stderr, "admin reset") {
		t.Fatalf("wrong password: %d %s", code, stderr)
	}
	code, _, stderr = runCLI(t, c, "login")
	if code != exitFailure || !strings.Contains(stderr, "--password-file") {
		t.Fatalf("login without a terminal: %d %s", code, stderr)
	}
}

func TestLoginFallsBackWhenLabWriteIsUnknown(t *testing.T) {
	api := newFakeAPI(t)
	loginHandlers(api, false)
	c, _, _ := testCLI()
	c.stdin = strings.NewReader("correct horse\n")
	code, stdout, stderr := runCLI(t, c, "login", "--password-stdin")
	if code != exitOK || !strings.Contains(stdout, "no lab:write permission yet") {
		t.Fatalf("fallback login: %d\n%s\n%s", code, stdout, stderr)
	}
	if calls := api.find("POST", "/api/v1/auth/tokens"); len(calls) != 2 || strings.Contains(string(calls[1].Body), "lab:write") {
		t.Fatalf("fallback did not retry without lab:write: %d", len(calls))
	}
}

func TestLogoutRemovesTokenAndCanRevoke(t *testing.T) {
	api := newFakeAPI(t)
	loginHandlers(api, true)
	c, _, _ := testCLI()
	c.stdin = strings.NewReader("correct horse\n")
	if code, _, stderr := runCLI(t, c, "login", "--password-stdin"); code != exitOK {
		t.Fatal(stderr)
	}
	passwordFile := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(passwordFile, []byte("correct horse\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runCLI(t, c, "logout", "--revoke", "--password-file", passwordFile)
	if code != exitOK || !strings.Contains(stdout, "revoked the token") {
		t.Fatalf("logout --revoke: %d\n%s\n%s", code, stdout, stderr)
	}
	if _, err := os.Lstat(api.tokenPath); !os.IsNotExist(err) {
		t.Fatal("token file survived logout")
	}
	if _, err := os.Lstat(tokenMetadataPath()); !os.IsNotExist(err) {
		t.Fatal("token metadata survived logout")
	}
	code, stdout, _ = runCLI(t, c, "logout")
	if code != exitOK || !strings.Contains(stdout, "not logged in") {
		t.Fatalf("second logout: %d %s", code, stdout)
	}
}

func TestRenameUsesAdminReauthenticationAndAliasRevision(t *testing.T) {
	api := newFakeAPI(t)
	loginHandlers(api, true)
	api.json("GET /api/v1/devices/resolve", 200, `{"schema":1,"unique":true,"matches":[`+tvMatch+`]}`)
	api.json("GET /api/v1/devices/"+tvID, 200, tvDevice)
	api.json("PUT /api/v1/devices/"+tvID+"/alias", 200, `{"devices":[{"id":"`+tvID+`"}]}`)
	passwordFile := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(passwordFile, []byte("correct horse\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, _, _ := testCLI()
	code, stdout, stderr := runCLI(t, c, "rename", "10.77.0.23", "Lounge", "TV", "--password-file", passwordFile)
	if code != exitOK || !strings.Contains(stdout, `Renamed Living room TV to "Lounge TV".`) {
		t.Fatalf("rename: %d\n%s\n%s", code, stdout, stderr)
	}
	put := api.find("PUT", "/api/v1/devices/"+tvID+"/alias")[0]
	var body map[string]any
	_ = json.Unmarshal(put.Body, &body)
	if put.Auth != "Bearer session-1" || body["friendly_name"] != "Lounge TV" || body["expected_revision"] != float64(3) || body["password"] != "correct horse" || !strings.HasPrefix(put.Header.Get("Idempotency-Key"), "cli-rename-") {
		t.Fatalf("unexpected alias update %v %v", body, put.Header)
	}
}

func TestAPIPassthroughKeepsRawOutputAndExitCode(t *testing.T) {
	api := newFakeAPI(t)
	api.json("GET /api/v1/devices", 503, `{"error":{"code":"inventory_unavailable","message":"device inventory is unavailable"}}`)
	c, _, _ := testCLI()
	code, stdout, _ := runCLI(t, c, "api", "GET", "/api/v1/devices")
	if code != exitFailure || !strings.Contains(stdout, "inventory_unavailable") {
		t.Fatalf("api passthrough: %d %s", code, stdout)
	}
	if code, _, _ := runCLI(t, c, "api", "TRACE", "/api/v1/devices"); code != exitUsage {
		t.Fatalf("api accepted TRACE: %d", code)
	}
	if code, _, stderr := runCLI(t, c, "api", "GET", "https://example.com/api/v1/devices"); code != exitUsage || !strings.Contains(stderr, "local API path") {
		t.Fatalf("api accepted a remote URL: %d %s", code, stderr)
	}
	body := filepath.Join(t.TempDir(), "body.json")
	if err := os.WriteFile(body, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := runCLI(t, c, "api", "--data", body, "POST", "/api/v1/test-sessions"); code != exitUsage || !strings.Contains(stderr, "not valid JSON") {
		t.Fatalf("api accepted an invalid body: %d %s", code, stderr)
	}
	if got := len(api.find("POST", "/api/v1/test-sessions")); got != 0 {
		t.Fatalf("invalid requests reached the API %d times", got)
	}
}

func TestDockerSinceConvertsDays(t *testing.T) {
	if dockerSince("2d") != "48h" || dockerSince("30m") != "30m" {
		t.Fatalf("dockerSince: %s %s", dockerSince("2d"), dockerSince("30m"))
	}
}

func TestAPITokenPathIsPerUserWithoutRoot(t *testing.T) {
	t.Setenv("SHAKERPROXY_API_TOKEN_FILE", "")
	t.Setenv("XDG_CONFIG_HOME", "/home/tester/.config")
	t.Setenv("HOME", "/home/tester")
	t.Setenv("SUDO_USER", "")
	original := geteuid
	t.Cleanup(func() { geteuid = original })

	geteuid = func() int { return 1000 }
	if got := apiTokenPath(); got != "/home/tester/.config/shakerproxy/cli-api-token" {
		t.Fatalf("non-root token path = %q", got)
	}
	if got := commandHint("shakerproxy devices"); got != "shakerproxy devices" {
		t.Fatalf("non-root hint = %q", got)
	}

	geteuid = func() int { return 0 }
	if got := apiTokenPath(); got != defaultAPITokenFile {
		t.Fatalf("root token path = %q", got)
	}
	t.Setenv("SUDO_USER", "tester")
	if got := commandHint("shakerproxy devices"); got != "sudo shakerproxy devices" {
		t.Fatalf("sudo hint = %q", got)
	}
}

func TestLoginWithoutSudoStoresTokenInUserConfig(t *testing.T) {
	api := newFakeAPI(t)
	loginHandlers(api, true)
	configHome := filepath.Join(t.TempDir(), "config")
	t.Setenv("SHAKERPROXY_API_TOKEN_FILE", "")
	t.Setenv("XDG_CONFIG_HOME", configHome)
	original := geteuid
	t.Cleanup(func() { geteuid = original })
	geteuid = func() int { return 1000 }

	c, _, _ := testCLI()
	c.stdin = strings.NewReader("correct horse\n")
	code, stdout, stderr := runCLI(t, c, "login", "--password-stdin")
	tokenPath := filepath.Join(configHome, "shakerproxy", "cli-api-token")
	if code != exitOK || !strings.Contains(stdout, "Token saved to "+tokenPath) || !strings.Contains(stdout, "Try: shakerproxy devices") {
		t.Fatalf("login: %d\n%s\n%s", code, stdout, stderr)
	}
	directory, err := os.Stat(filepath.Dir(tokenPath))
	if err != nil || directory.Mode().Perm() != 0o700 {
		t.Fatalf("token directory: %v %v", directory, err)
	}
	api.json("GET /api/v1/devices", 200, `{"devices":[]}`)
	if code, _, stderr := runCLI(t, c, "devices"); code != exitOK {
		t.Fatalf("devices with the per-user token: %d %s", code, stderr)
	}
	if requests := api.find("GET", "/api/v1/devices"); len(requests) != 1 || requests[0].Auth != "Bearer lgt_secret1" {
		t.Fatalf("devices did not use the per-user token: %+v", requests)
	}
}

// Headers-only captures count TLS flows but cannot show handshakes; the
// report must say so instead of a bare "0 TLS".
func TestReportExplainsMissingTLSDetails(t *testing.T) {
	api := newFakeAPI(t)
	api.json("GET /api/v1/devices/EC2 client/report", 200, `{"schema":1,"generated_at":"2026-09-29T22:54:00Z",
	 "device":{"device_id":"device-35d06eff6436258199f4e8ed887198ed","friendly_name":"EC2 client","addresses":["172.31.47.197"]},
	 "window_start":"2026-09-29T22:50:00Z","window_end":"2026-09-29T22:54:00Z","ca_trust":"unknown",
	 "totals":{"events":81,"flows":35,"bytes":389000,"dns_queries":12,"tls_connections":0,"http_requests":6,"alerts":0},
	 "domains":[],"protocols":[{"protocol":"TLS","flows":12},{"protocol":"HTTP","flows":6}],
	 "tls":{},"http":{},"findings":[],"truncated":false}`)
	c, _, _ := testCLI()
	code, stdout, stderr := runCLI(t, c, "report", "EC2 client")
	if code != exitOK || !strings.Contains(stdout, "12 TLS flows, but no handshake details") || !strings.Contains(stdout, `shakerproxy test start "EC2 client" --full`) {
		t.Fatalf("report did not explain missing TLS details: %d\n%s\n%s", code, stdout, stderr)
	}
}
