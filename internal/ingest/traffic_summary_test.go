package ingest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/querylang"
)

type streamTypeFixture struct {
	Name  string          `json:"name"`
	Type  string          `json:"type"`
	Event json.RawMessage `json:"event"`
}

// loadStreamTypeFixtures reads the cases shared with the PostgreSQL test and
// the web UI's tests/ui/stream-types.test.mjs.
func loadStreamTypeFixtures(t *testing.T) []streamTypeFixture {
	t.Helper()
	raw, err := os.ReadFile("testdata/stream_types.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []streamTypeFixture
	if err := json.Unmarshal(raw, &fixtures); err != nil || len(fixtures) < 20 {
		t.Fatalf("stream type fixtures: %d cases, %v", len(fixtures), err)
	}
	return fixtures
}

func (fixture streamTypeFixture) event(t *testing.T) RecentEvent {
	t.Helper()
	var event RecentEvent
	if err := json.Unmarshal(fixture.Event, &event); err != nil {
		t.Fatalf("%s: %v", fixture.Name, err)
	}
	return event
}

func TestStreamTypeMatchesSharedFixtures(t *testing.T) {
	covered := map[string]bool{}
	for _, fixture := range loadStreamTypeFixtures(t) {
		covered[fixture.Type] = true
		if got := StreamType(fixture.event(t)); got != fixture.Type {
			t.Errorf("%s: StreamType = %q, want %q", fixture.Name, got, fixture.Type)
		}
	}
	for _, streamType := range StreamTypes {
		if !covered[streamType] {
			t.Errorf("no fixture covers %q", streamType)
		}
	}
}

func TestAnalyzerDuplicatesFilterIsValid(t *testing.T) {
	if analyzerDuplicates.Root == nil || !strings.HasPrefix(analyzerDuplicates.Canonical, "NOT ") {
		t.Fatalf("duplicate filter did not parse: %#v", analyzerDuplicates)
	}
	// It is compiled as its own clause, so a user's query keeps its whole
	// term budget.
	for _, kind := range []string{"kind:suricata.flow", "kind:zeek.ssl", "dst.port:5353"} {
		if !strings.Contains(analyzerDuplicatesFilter, kind) {
			t.Errorf("duplicate filter lacks %s", kind)
		}
	}
}

func TestParseTrafficSummaryQuery(t *testing.T) {
	query, err := ParseTrafficSummaryQuery(url.Values{})
	if err != nil || query.Buckets != DefaultTrafficSummaryBuckets || !query.From.IsZero() || !query.To.IsZero() || query.Events.Limit != 1 {
		t.Fatalf("defaults: %#v %v", query, err)
	}
	query, err = ParseTrafficSummaryQuery(url.Values{"from": {"2026-10-02T10:00:00Z"}, "to": {"2026-10-02T12:15:00+02:00"}, "buckets": {"15"}, "q": {"protocol:udp"}, "source": {"ZEEK"}})
	if err != nil || query.Buckets != 15 || query.Events.Source != SourceZeek || query.Events.Filter.Canonical != "protocol:udp" || query.To.Sub(query.From) != 15*time.Minute || query.To.Location() != time.UTC {
		t.Fatalf("explicit window: %#v %v", query, err)
	}
	for name, values := range map[string]url.Values{
		"empty window":      {"from": {"2026-10-02T10:00:00Z"}, "to": {"2026-10-02T11:00:00+01:00"}},
		"no buckets":        {"buckets": {"0"}},
		"too many buckets":  {"buckets": {"241"}},
		"word buckets":      {"buckets": {"sixty"}},
		"reversed window":   {"from": {"2026-10-02T11:00:00Z"}, "to": {"2026-10-02T10:00:00Z"}},
		"sub-second window": {"from": {"2026-10-02T10:00:00Z"}, "to": {"2026-10-02T10:00:00.5Z"}},
		"over 30 days":      {"from": {"2026-08-01T00:00:00Z"}, "to": {"2026-09-01T00:00:01Z"}},
		"limit":             {"limit": {"10"}},
		"cursor":            {"cursor": {"abc"}},
		"repeated from":     {"from": {"2026-10-02T10:00:00Z", "2026-10-02T10:01:00Z"}},
		"not a time":        {"from": {"yesterday"}},
		"unknown parameter": {"window": {"1h"}},
		"bad query":         {"q": {"nope:("}},
	} {
		if _, err := ParseTrafficSummaryQuery(values); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestTrafficSummaryWindow(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	from, to := TrafficSummaryQuery{Buckets: 60}.window(now)
	if !to.Equal(now) || to.Sub(from) != DefaultTrafficSummaryWindow {
		t.Fatalf("default window: %s – %s", from, to)
	}
	filter, err := querylang.Parse("time:last_6h AND (time:last_1h OR protocol:udp)")
	if err != nil {
		t.Fatal(err)
	}
	from, to = TrafficSummaryQuery{Buckets: 60, Events: RecentEventQuery{Filter: filter}}.window(now)
	if !to.Equal(now) || to.Sub(from) != time.Hour {
		t.Fatalf("relative window should use the narrowest time term: %s – %s", from, to)
	}
	start := now.Add(-2 * time.Hour)
	from, to = TrafficSummaryQuery{Buckets: 60, From: start}.window(now)
	if !from.Equal(start) || !to.Equal(now) {
		t.Fatalf("open-ended window: %s – %s", from, to)
	}
	from, to = TrafficSummaryQuery{Buckets: 60, From: now.Add(time.Hour)}.window(now)
	if to.Sub(from) != DefaultTrafficSummaryWindow {
		t.Fatalf("future start: %s – %s", from, to)
	}
	from, _ = TrafficSummaryQuery{Buckets: 60, From: now.AddDate(0, -3, 0)}.window(now)
	if now.Sub(from) != MaxTrafficSummaryWindow {
		t.Fatalf("window was not capped: %s", from)
	}
}

func TestInternalTrafficSummaryQueryRoundTrips(t *testing.T) {
	filter, err := querylang.Parse(`device.name:alias-ref-01 AND time:last_1h`)
	if err != nil {
		t.Fatal(err)
	}
	deviceID := "device-0123456789abcdef0123456789abcdef"
	anchor := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	query := TrafficSummaryQuery{
		Events:  RecentEventQuery{Limit: 1, Filter: filter, TimeAnchor: anchor, DeviceNameResolutions: map[string][]string{"alias-ref-01": {deviceID}}},
		From:    anchor.Add(-time.Hour),
		To:      anchor,
		Buckets: 30,
	}
	values, err := encodeInternalTrafficSummaryQuery(query)
	if err != nil || values.Has("limit") {
		t.Fatalf("encode: %v %v", values, err)
	}
	decoded, err := ParseInternalTrafficSummaryQuery(values)
	if err != nil || decoded.Buckets != 30 || !decoded.From.Equal(query.From) || !decoded.To.Equal(query.To) || !decoded.Events.TimeAnchor.Equal(anchor) || decoded.Events.DeviceNameResolutions["alias-ref-01"][0] != deviceID {
		t.Fatalf("round trip: %#v %v", decoded, err)
	}
	if _, err := ParseTrafficSummaryQuery(values); err == nil {
		t.Fatal("the public parser accepted private device resolutions")
	}
}

func testTrafficSummary(buckets int) TrafficSummary {
	from := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	width := 15 * time.Minute / time.Duration(buckets)
	summary := TrafficSummary{Schema: TrafficSummarySchemaVersion, GeneratedAt: from.Add(15 * time.Minute), From: from, To: from.Add(15 * time.Minute), BucketSeconds: width.Seconds(), Buckets: make([]TrafficSummaryBucket, buckets)}
	for index := range summary.Buckets {
		summary.Buckets[index].Start = from.Add(time.Duration(index) * width)
	}
	summary.Buckets[0].Counts.DNS = 3
	summary.Buckets[buckets-1].Counts.TLS = 2
	summary.Totals = TrafficSummaryTotals{Events: 5, BytesSent: 10, BytesReceived: 20, Types: StreamTypeCounts{DNS: 3, TLS: 2}}
	device := "device-0123456789abcdef0123456789abcdef"
	for _, field := range TrafficSummaryFacetFields {
		facet := TrafficSummaryFacet{Field: field, Values: []TrafficSummaryFacetValue{}, Exact: true}
		switch field {
		case SummaryFacetDevice:
			facet.Values = []TrafficSummaryFacetValue{{Value: device, Count: 4}, {Value: "ip:10.77.0.9", Label: "10.77.0.9", Count: 1}}
		case SummaryFacetType:
			facet.Values = []TrafficSummaryFacetValue{{Value: StreamDNS, Count: 3}, {Value: StreamTLS, Count: 2}}
		}
		summary.Facets = append(summary.Facets, facet)
	}
	return summary
}

func TestValidateTrafficSummary(t *testing.T) {
	query := TrafficSummaryQuery{Buckets: 5}
	if err := ValidateTrafficSummary(testTrafficSummary(5), query); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*TrafficSummary){
		"schema":            func(s *TrafficSummary) { s.Schema = 2 },
		"bucket count":      func(s *TrafficSummary) { s.Buckets = s.Buckets[1:] },
		"bucket order":      func(s *TrafficSummary) { s.Buckets[1].Start = s.Buckets[0].Start },
		"bucket outside":    func(s *TrafficSummary) { s.Buckets[0].Start = s.From.Add(-time.Second) },
		"negative count":    func(s *TrafficSummary) { s.Buckets[0].Counts.Other = -1 },
		"totals mismatch":   func(s *TrafficSummary) { s.Totals.Events = 6 },
		"types mismatch":    func(s *TrafficSummary) { s.Totals.Types.DNS = 2; s.Totals.Types.Other = 1 },
		"missing facet":     func(s *TrafficSummary) { s.Facets = s.Facets[1:] },
		"facet order":       func(s *TrafficSummary) { s.Facets[0], s.Facets[1] = s.Facets[1], s.Facets[0] },
		"sampled but exact": func(s *TrafficSummary) { s.Facets[2].SampledEvents = 10 },
		"empty value":       func(s *TrafficSummary) { s.Facets[0].Values[0].Value = "" },
		"control label":     func(s *TrafficSummary) { s.Facets[0].Values[0].Label = "TV\n" },
		"zero count":        func(s *TrafficSummary) { s.Facets[0].Values[0].Count = 0 },
		"negative bytes":    func(s *TrafficSummary) { s.Totals.BytesSent = -1 },
	} {
		summary := testTrafficSummary(5)
		mutate(&summary)
		if err := ValidateTrafficSummary(summary, query); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestQueryClientTrafficSummary(t *testing.T) {
	token := strings.Repeat("s", 32)
	deviceID := "device-0123456789abcdef0123456789abcdef"
	filter, err := querylang.Parse(`device.name:"Bench Camera" AND protocol:udp`)
	if err != nil {
		t.Fatal(err)
	}
	respond := func(w http.ResponseWriter, summary TrafficSummary) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(summary)
	}
	var reply func(http.ResponseWriter)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		decoded, parseErr := ParseInternalTrafficSummaryQuery(r.URL.Query())
		if r.URL.Path != "/v1/events/summary" || r.Header.Get("Authorization") != "Bearer "+token || parseErr != nil || decoded.Buckets != 5 || decoded.Events.Filter.Canonical != "device.name:alias-ref-01 AND protocol:udp" || decoded.Events.DeviceNameResolutions["alias-ref-01"][0] != deviceID || r.URL.Query().Has("limit") {
			t.Errorf("unexpected summary request: %s %v", r.URL, parseErr)
		}
		if strings.Contains(r.URL.RawQuery, "Bench") {
			t.Error("summary request exposed an inventory name")
		}
		reply(w)
	}))
	defer backend.Close()
	client, err := NewQueryClient(backend.URL, []byte(token), backend.Client())
	if err != nil {
		t.Fatal(err)
	}
	query := TrafficSummaryQuery{Buckets: 5, Events: RecentEventQuery{Filter: filter, DeviceNameResolutions: map[string][]string{"Bench Camera": {deviceID}}}}
	reply = func(w http.ResponseWriter) { respond(w, testTrafficSummary(5)) }
	summary, err := client.QueryTrafficSummary(t.Context(), query)
	if err != nil || summary.Totals.Events != 5 || summary.CanonicalQuery != filter.Canonical {
		t.Fatalf("summary: %#v %v", summary, err)
	}
	for name, forge := range map[string]func(w http.ResponseWriter){
		"device label": func(w http.ResponseWriter) {
			forged := testTrafficSummary(5)
			forged.Facets[0].Values[0].Label = "Someone's phone"
			respond(w, forged)
		},
		"port label": func(w http.ResponseWriter) {
			forged := testTrafficSummary(5)
			forged.Facets[4].Values = []TrafficSummaryFacetValue{{Value: "443", Label: "https", Count: 1}}
			respond(w, forged)
		},
		"unknown field": func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "application/json")
			raw, _ := json.Marshal(testTrafficSummary(5))
			_, _ = w.Write(append(raw[:len(raw)-1], []byte(`,"extra":1}`)...))
		},
		"wrong buckets": func(w http.ResponseWriter) { respond(w, testTrafficSummary(4)) },
		"error status": func(w http.ResponseWriter) {
			http.Error(w, "no", http.StatusServiceUnavailable)
		},
	} {
		reply = forge
		if _, err := client.QueryTrafficSummary(t.Context(), query); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}
