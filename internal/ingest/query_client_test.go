package ingest

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/inventory"
	"shakerproxy.dev/shakerproxy/internal/querylang"
)

const emptyEventFacetsJSON = `{"exact":true,"matched_count":0,"count_relation":"eq","basis":"all_matches","fields":[{"field":"source","values":[],"other_count":0},{"field":"kind","values":[],"other_count":0},{"field":"protocol","values":[],"other_count":0},{"field":"service","values":[],"other_count":0}],"domains":{"values":[],"other_count":0}}`

const oneZeekEventFacetsJSON = `{"exact":true,"matched_count":1,"count_relation":"eq","basis":"all_matches","fields":[{"field":"source","values":[{"value":"ZEEK","count":1}],"other_count":0},{"field":"kind","values":[{"value":"zeek.conn","count":1}],"other_count":0},{"field":"protocol","values":[{"value":"tcp","count":1}],"other_count":0},{"field":"service","values":[{"value":"ssl","count":1}],"other_count":0}],"domains":{"values":[{"domain":"grapheneos.network","count":1,"hosts":["connectivitycheck.grapheneos.network"]}],"other_count":0}}`

func TestQueryClientUsesFixedPathCredentialAndBoundedQuery(t *testing.T) {
	token := strings.Repeat("q", 32)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/events" || r.URL.Query().Get("limit") != "2" || r.URL.Query().Get("source") != "ZEEK" || r.Header.Get("Authorization") != "Bearer "+token {
			t.Errorf("unexpected backend request: %s %s %#v", r.Method, r.URL.String(), r.Header)
		}
		w.Header().Set("Content-Type", "application/json")
		now := time.Now().UTC()
		fmt.Fprintf(w, `{"schema":1,"generated_at":%q,"live_cursor":%q,"facets":`+oneZeekEventFacetsJSON+`,"events":[{"record_id":%q,"source":"ZEEK","kind":"zeek.conn","occurred_at":%q,"received_at":%q,"source_version":"8.2.1","parser_version":"shakerproxy-zeek-v1","confidence":80,"source_ip":"10.77.0.111","destination_ip":"1.1.1.1","source_port":54321,"destination_port":443,"protocol":"tcp","service":"ssl","network_bytes":460}]}`, now.Format(time.RFC3339Nano), encodeLiveEventCursor(now, strings.Repeat("0", 64)), strings.Repeat("a", 64), now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	}))
	defer backend.Close()
	client, err := NewQueryClient(backend.URL, []byte(token), backend.Client())
	if err != nil {
		t.Fatal(err)
	}
	page, err := client.QueryRecent(t.Context(), RecentEventQuery{Limit: 2, Source: SourceZeek})
	if err != nil || len(page.Events) != 1 || page.Events[0].Kind != "zeek.conn" || page.Events[0].SourceIP != "10.77.0.111" || page.Events[0].NetworkBytes != 460 {
		t.Fatalf("unexpected query result: %#v %v", page, err)
	}
}

func TestQueryClientRoundTripsCanonicalTypedFilter(t *testing.T) {
	token := strings.Repeat("q", 32)
	filter, err := querylang.Parse("protocol:TCP dst.port:>=443")
	if err != nil {
		t.Fatal(err)
	}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("q") != filter.Canonical {
			t.Errorf("typed filter was not canonical: %q", r.URL.Query().Get("q"))
		}
		w.Header().Set("Content-Type", "application/json")
		now := time.Now().UTC()
		fmt.Fprintf(w, `{"schema":1,"generated_at":%q,"live_cursor":%q,"canonical_query":%q,"facets":`+emptyEventFacetsJSON+`,"events":[]}`, now.Format(time.RFC3339Nano), encodeLiveEventCursor(now, strings.Repeat("0", 64)), filter.Canonical)
	}))
	defer backend.Close()
	client, err := NewQueryClient(backend.URL, []byte(token), backend.Client())
	if err != nil {
		t.Fatal(err)
	}
	page, err := client.QueryRecent(t.Context(), RecentEventQuery{Limit: 5, Filter: filter})
	if err != nil || page.CanonicalQuery != filter.Canonical {
		t.Fatalf("canonical typed filter did not round trip: %#v %v", page, err)
	}
}

func TestQueryClientSendsOnlyBoundedDeviceIDsForFriendlyNames(t *testing.T) {
	token := strings.Repeat("n", 32)
	filter, err := querylang.Parse(`name:"Bench Camera"`)
	if err != nil {
		t.Fatal(err)
	}
	deviceID := "device-0123456789abcdef0123456789abcdef"
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		decoded, parseErr := ParseInternalRecentEventQuery(r.URL.Query())
		if parseErr != nil || decoded.Filter.Canonical != `device.name:alias-ref-01` || len(decoded.DeviceNameResolutions["alias-ref-01"]) != 1 || decoded.DeviceNameResolutions["alias-ref-01"][0] != deviceID {
			t.Errorf("private friendly-name resolution was not validated: %#v %v", decoded, parseErr)
		}
		if strings.Contains(r.URL.RawQuery, "Bench+Camera") || strings.Contains(r.URL.RawQuery, "Bench%20Camera") {
			t.Error("resolution metadata exposed a plain-text inventory name")
		}
		w.Header().Set("Content-Type", "application/json")
		now := time.Now().UTC()
		fmt.Fprintf(w, `{"schema":1,"generated_at":%q,"live_cursor":%q,"canonical_query":%q,"facets":`+emptyEventFacetsJSON+`,"events":[]}`, now.Format(time.RFC3339Nano), encodeLiveEventCursor(now, strings.Repeat("0", 64)), decoded.Filter.Canonical)
	}))
	defer backend.Close()
	client, err := NewQueryClient(backend.URL, []byte(token), backend.Client())
	if err != nil {
		t.Fatal(err)
	}
	page, err := client.QueryRecent(t.Context(), RecentEventQuery{Limit: 5, Filter: filter, DeviceNameResolutions: map[string][]string{"Bench Camera": {deviceID}}})
	if err != nil || page.CanonicalQuery != filter.Canonical {
		t.Fatalf("friendly-name query did not round trip safely: %#v %v", page, err)
	}
}

func TestQueryClientRoundTripsAuthoritativeRelativeTimeAnchor(t *testing.T) {
	token := strings.Repeat("t", 32)
	filter, err := querylang.Parse(`time:last_15m`)
	if err != nil {
		t.Fatal(err)
	}
	anchor := time.Date(2026, 9, 1, 12, 30, 0, 0, time.UTC)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		decoded, parseErr := ParseInternalRecentEventQuery(r.URL.Query())
		if parseErr != nil || decoded.Filter.Canonical != filter.Canonical || !decoded.TimeAnchor.IsZero() {
			t.Errorf("unexpected first relative-time request: %#v %v", decoded, parseErr)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"schema":1,"generated_at":%q,"query_anchor":%q,"live_cursor":%q,"canonical_query":%q,"facets":`+emptyEventFacetsJSON+`,"events":[]}`, anchor.Format(time.RFC3339Nano), anchor.Format(time.RFC3339Nano), encodeAnchoredLiveEventCursor(anchor, strings.Repeat("0", 64), anchor), filter.Canonical)
	}))
	defer backend.Close()
	client, err := NewQueryClient(backend.URL, []byte(token), backend.Client())
	if err != nil {
		t.Fatal(err)
	}
	page, err := client.QueryRecent(t.Context(), RecentEventQuery{Limit: 5, Filter: filter})
	if err != nil || !page.QueryAnchor.Equal(anchor) || page.CanonicalQuery != filter.Canonical {
		t.Fatalf("relative-time anchor did not round trip: %#v %v", page, err)
	}
}

func TestQueryClientReadsBoundedOrderedLiveBatch(t *testing.T) {
	token := strings.Repeat("l", 32)
	after := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	afterID := strings.Repeat("0", 64)
	eventTime := after.Add(time.Second)
	eventID := strings.Repeat("c", 64)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cursorTime, cursorID, err := DecodeLiveEventCursor(r.URL.Query().Get("cursor"))
		if err != nil || r.URL.Path != "/v1/events/live-batch" || !cursorTime.Equal(after) || cursorID != afterID || r.Header.Get("Authorization") != "Bearer "+token {
			t.Errorf("unexpected live backend request: %s %#v %v", r.URL.String(), r.Header, err)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"schema":1,"generated_at":%q,"events":[{"record_id":%q,"source":"ZEEK","kind":"zeek.conn","occurred_at":%q,"received_at":%q,"source_version":"8.2.1","parser_version":"shakerproxy-zeek-v1","confidence":80}],"next_cursor":%q}`, eventTime.Format(time.RFC3339Nano), eventID, eventTime.Format(time.RFC3339Nano), eventTime.Format(time.RFC3339Nano), encodeLiveEventCursor(eventTime, eventID))
	}))
	defer backend.Close()
	client, err := NewQueryClient(backend.URL, []byte(token), backend.Client())
	if err != nil {
		t.Fatal(err)
	}
	batch, err := client.QueryAfter(t.Context(), LiveEventQuery{RecentEventQuery: RecentEventQuery{Limit: 2}, AfterReceivedAt: after, AfterRecordID: afterID})
	if err != nil || len(batch.Events) != 1 || batch.Events[0].RecordID != eventID {
		t.Fatalf("unexpected live query result: %#v %v", batch, err)
	}
}

func TestQueryClientKeepsRelativeTimeAnchorAcrossLivePoll(t *testing.T) {
	token := strings.Repeat("r", 32)
	filter, err := querylang.Parse(`time:last_15m`)
	if err != nil {
		t.Fatal(err)
	}
	anchor := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	after := anchor.Add(time.Minute)
	afterID := strings.Repeat("0", 64)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		decoded, parseErr := ParseInternalLiveEventQuery(r.URL.Query(), time.Now())
		if parseErr != nil || !decoded.TimeAnchor.Equal(anchor) || !decoded.AfterReceivedAt.Equal(after) || decoded.AfterRecordID != afterID {
			t.Errorf("live relative-time anchor shifted: %#v %v", decoded, parseErr)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"schema":1,"generated_at":%q,"query_anchor":%q,"next_cursor":%q,"canonical_query":%q,"events":[]}`, after.Add(time.Second).Format(time.RFC3339Nano), anchor.Format(time.RFC3339Nano), encodeAnchoredLiveEventCursor(after, afterID, anchor), filter.Canonical)
	}))
	defer backend.Close()
	client, err := NewQueryClient(backend.URL, []byte(token), backend.Client())
	if err != nil {
		t.Fatal(err)
	}
	batch, err := client.QueryAfter(t.Context(), LiveEventQuery{RecentEventQuery: RecentEventQuery{Limit: 5, Filter: filter, TimeAnchor: anchor}, AfterReceivedAt: after, AfterRecordID: afterID})
	if err != nil || !batch.QueryAnchor.Equal(anchor) || batch.CanonicalQuery != filter.Canonical {
		t.Fatalf("live relative-time anchor did not round trip: %#v %v", batch, err)
	}
}

func TestLiveBatchRejectsOutOfOrderEventsAndCursor(t *testing.T) {
	after := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	query := LiveEventQuery{RecentEventQuery: RecentEventQuery{Limit: 2}, AfterReceivedAt: after, AfterRecordID: strings.Repeat("0", 64)}
	newer := RecentEvent{RecordID: strings.Repeat("d", 64), Source: SourceZeek, Kind: "zeek.conn", OccurredAt: after, ReceivedAt: after.Add(2 * time.Second), SourceVersion: "8.2.1", ParserVersion: "shakerproxy-zeek-v1", Confidence: 80}
	older := newer
	older.RecordID = strings.Repeat("c", 64)
	older.ReceivedAt = after.Add(time.Second)
	batch := LiveEventBatch{Schema: 1, GeneratedAt: after.Add(3 * time.Second), Events: []RecentEvent{newer, older}, NextCursor: encodeLiveEventCursor(older.ReceivedAt, older.RecordID)}
	if err := validateLiveEventBatch(batch, query); err == nil {
		t.Fatal("out-of-order live events were accepted")
	}
}

func TestQueryClientRejectsUnsafeConfigurationAndResponses(t *testing.T) {
	token := []byte(strings.Repeat("q", 32))
	for _, baseURL := range []string{"https://ingestd:8081", "http://user:pass@ingestd:8081", "http://ingestd:8081/path", "http://ingestd:8081?query=yes"} {
		if _, err := NewQueryClient(baseURL, token, nil); err == nil {
			t.Fatalf("unsafe query service URL accepted: %s", baseURL)
		}
	}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"schema":1,"generated_at":"2026-09-01T12:00:00Z","events":[{"record_id":"bad","source":"ZEEK","kind":"zeek.conn","occurred_at":"2026-09-01T12:00:00Z","received_at":"2026-09-01T12:00:00Z","confidence":80}]}`))
	}))
	defer backend.Close()
	client, err := NewQueryClient(backend.URL, token, backend.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.QueryRecent(t.Context(), RecentEventQuery{Limit: 1}); err == nil {
		t.Fatal("invalid backend event was accepted")
	}
}

func TestQueryClientValidatesIngestionStatus(t *testing.T) {
	token := strings.Repeat("s", 32)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/query-stats" || r.Header.Get("Authorization") != "Bearer "+token {
			t.Errorf("unexpected status request: %s %#v", r.URL.Path, r.Header)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"schema":1,"generated_at":%q,"pending_records":2,"pending_bytes":1024,"quarantined_records":1,"quarantined_bytes":128,"oldest_pending_at":%q,"ingest_lag_seconds":4.5,"storage_pressure":false,"database_configured":true,"database_connected":true}`, time.Now().UTC().Format(time.RFC3339Nano), time.Now().Add(-5*time.Second).UTC().Format(time.RFC3339Nano))
	}))
	defer backend.Close()
	client, err := NewQueryClient(backend.URL, []byte(token), backend.Client())
	if err != nil {
		t.Fatal(err)
	}
	stats, err := client.IngestStatus(t.Context())
	if err != nil || stats.PendingRecords != 2 || !stats.DatabaseConnected {
		t.Fatalf("unexpected ingestion status: %#v %v", stats, err)
	}
}

func TestRecentEventPageRejectsUnsafeNetworkProjection(t *testing.T) {
	now := time.Now().UTC()
	page := RecentEventPage{Schema: 1, GeneratedAt: now, LiveCursor: encodeLiveEventCursor(now, strings.Repeat("0", 64)), Events: []RecentEvent{{RecordID: strings.Repeat("a", 64), Source: SourceZeek, Kind: "zeek.conn", OccurredAt: now, ReceivedAt: now, SourceVersion: "8.2.1", ParserVersion: "shakerproxy-zeek-v1", Confidence: 80, SourceIP: "not-an-ip", SourcePort: 70000}}}
	if err := validateRecentEventPage(page, RecentEventQuery{Limit: 1}); err == nil {
		t.Fatal("unsafe network projection was accepted")
	}
}

func TestRecentEventPageRejectsAttributionEvidenceOutsideEvent(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	event := RecentEvent{RecordID: strings.Repeat("a", 64), Source: SourceZeek, Kind: "zeek.conn", OccurredAt: now, ReceivedAt: now, SourceVersion: "8.2.1", ParserVersion: "shakerproxy-zeek-v1", DeviceID: "device-0123456789abcdef0123456789abcdef", Confidence: 70, SourceIP: "10.77.0.111"}
	event.AttributionEvidence = &AttributionEvidence{Schema: AttributionEvidenceSchema, DeviceID: event.DeviceID, Address: "10.77.0.112", Endpoint: AttributionEndpointSource, Source: inventory.SourceDHCP4Lease, Confidence: 95, ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(time.Hour)}
	page := RecentEventPage{Schema: 1, GeneratedAt: now, LiveCursor: encodeLiveEventCursor(now, strings.Repeat("0", 64)), Events: []RecentEvent{event}}
	if err := validateRecentEventPage(page, RecentEventQuery{Limit: 1}); err == nil {
		t.Fatal("attribution evidence for a different endpoint was accepted")
	}
	event.AttributionEvidence.Address = event.SourceIP
	page.Events[0] = event
	if err := validateRecentEventPage(page, RecentEventQuery{Limit: 1}); err != nil {
		t.Fatalf("valid exact attribution evidence was rejected: %v", err)
	}
}

func TestEventFacetValidationRejectsMisrepresentedCounts(t *testing.T) {
	valid := EventFacets{Exact: true, MatchedCount: 2, CountRelation: "eq", Basis: "all_matches", Fields: []EventFacet{
		{Field: "source", Values: []EventFacetValue{{Value: "ZEEK", Count: 2}}},
		{Field: "kind", Values: []EventFacetValue{{Value: "zeek.conn", Count: 2}}},
		{Field: "protocol", Values: []EventFacetValue{{Value: "tcp", Count: 2}}},
		{Field: "service", Values: []EventFacetValue{{Value: "ssl", Count: 1}}, OtherCount: 1},
	}, Domains: EventDomainFacet{Values: []EventDomainValue{}}}
	if err := validateEventFacets(valid, 2); err != nil {
		t.Fatalf("valid exact facets were rejected: %v", err)
	}
	invalid := valid
	invalid.Exact = false
	invalid.CountRelation = "gte"
	invalid.Basis = "newest_sample"
	if err := validateEventFacets(invalid, 2); err == nil {
		t.Fatal("undersized sample was represented as non-exact")
	}
	invalid = valid
	invalid.Fields = append([]EventFacet(nil), valid.Fields...)
	invalid.Fields[0].Values = []EventFacetValue{{Value: "ZEEK", Count: 3}}
	if err := validateEventFacets(invalid, 2); err == nil {
		t.Fatal("facet count larger than its population was accepted")
	}
}

func TestRecentEventPageRejectsDeviceNamesFromIngestService(t *testing.T) {
	now := time.Now().UTC()
	page := RecentEventPage{Schema: 1, GeneratedAt: now, LiveCursor: encodeLiveEventCursor(now, strings.Repeat("0", 64)), Events: []RecentEvent{{RecordID: strings.Repeat("a", 64), Source: SourceZeek, Kind: "zeek.conn", OccurredAt: now, ReceivedAt: now, SourceVersion: "8.2.1", ParserVersion: "shakerproxy-zeek-v1", Confidence: 80, DeviceID: "device-0123456789abcdef0123456789abcdef", DeviceFriendlyName: "Untrusted Label"}}}
	if err := validateRecentEventPage(page, RecentEventQuery{Limit: 1}); err == nil {
		t.Fatal("ingest service was allowed to author an administrator device name")
	}
}

func TestEventDomainsGroupHostsByRegistrableDomain(t *testing.T) {
	// Host counts arrive largest first, as readEventDomains returns them.
	domains := groupEventDomains([]EventFacetValue{
		{Value: "connectivitycheck.grapheneos.network", Count: 9},
		{Value: "www.googleapis.com", Count: 6},
		{Value: "time.grapheneos.network", Count: 2},
		{Value: "android.googleapis.com", Count: 1},
		{Value: "192.168.10.1", Count: 4},
		{Value: "bad host", Count: 3},
	}, 25)
	if err := validateEventDomains(domains); err != nil {
		t.Fatalf("grouped domains are invalid: %v", err)
	}
	if len(domains.Values) != 2 {
		t.Fatalf("domains = %+v, want grapheneos.network and googleapis.com", domains.Values)
	}
	first, second := domains.Values[0], domains.Values[1]
	if first.Domain != "grapheneos.network" || first.Count != 11 || !slices.Equal(first.Hosts, []string{"connectivitycheck.grapheneos.network", "time.grapheneos.network"}) {
		t.Fatalf("first domain = %+v", first)
	}
	if second.Domain != "googleapis.com" || second.Count != 7 || len(second.Hosts) != 2 {
		t.Fatalf("second domain = %+v", second)
	}
	// IP literals and malformed names are not domains; they stay in "other".
	if domains.OtherCount != 25-18 {
		t.Fatalf("other = %d, want 7", domains.OtherCount)
	}
}

func TestEventDomainsKeepTheLargestAndBoundHosts(t *testing.T) {
	hosts := []EventFacetValue{}
	for index := 0; index < MaxEventDomainValues+5; index++ {
		hosts = append(hosts, EventFacetValue{Value: fmt.Sprintf("host%d.example%02d.com", index, index), Count: int64(100 - index)})
	}
	for index := 0; index < MaxEventDomainHosts+3; index++ {
		hosts = append(hosts, EventFacetValue{Value: fmt.Sprintf("h%d.example00.com", index), Count: 1})
	}
	domains := groupEventDomains(hosts, 10_000)
	if err := validateEventDomains(domains); err != nil {
		t.Fatalf("bounded domains are invalid: %v", err)
	}
	if len(domains.Values) != MaxEventDomainValues || domains.Values[0].Domain != "example00.com" || len(domains.Values[0].Hosts) != MaxEventDomainHosts {
		t.Fatalf("domains were not bounded: %+v", domains.Values[0])
	}
}

func TestEventDomainValidationRejectsForgedDomains(t *testing.T) {
	for name, domains := range map[string]EventDomainFacet{
		"missing values":      {},
		"host outside domain": {Values: []EventDomainValue{{Domain: "example.com", Count: 1, Hosts: []string{"evil.net"}}}},
		"not registrable":     {Values: []EventDomainValue{{Domain: "www.example.com", Count: 1, Hosts: []string{"www.example.com"}}}},
		"out of order":        {Values: []EventDomainValue{{Domain: "a.com", Count: 1, Hosts: []string{"a.com"}}, {Domain: "b.com", Count: 2, Hosts: []string{"b.com"}}}},
		"no hosts":            {Values: []EventDomainValue{{Domain: "a.com", Count: 1, Hosts: []string{}}}},
		"negative other":      {Values: []EventDomainValue{}, OtherCount: -1},
	} {
		if err := validateEventDomains(domains); err == nil {
			t.Errorf("%s: forged domain facet was accepted", name)
		}
	}
}
