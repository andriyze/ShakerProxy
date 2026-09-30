package ingest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/querylang"
)

func TestQueryClientCreatesActorBoundFrozenSnapshot(t *testing.T) {
	token := strings.Repeat("q", 32)
	created := time.Date(2026, 9, 1, 15, 0, 0, 0, time.UTC)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/event-query-snapshots" || r.Header.Get("Authorization") != "Bearer "+token || r.Header.Get("X-ShakerProxy-Actor") != "admin" {
			t.Fatalf("unexpected query snapshot boundary request: %s %s %#v", r.Method, r.URL.Path, r.Header)
		}
		var request internalEventQuerySnapshotRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		values, err := url.ParseQuery(request.EncodedQuery)
		if err != nil {
			t.Fatal(err)
		}
		query, err := ParseInternalRecentEventQuery(values)
		if err != nil || query.Filter.Canonical != `device.name:alias-ref-01 AND device.tag:tag-ref-01 AND time:last_15m` || len(query.DeviceNameResolutions["alias-ref-01"]) != 1 || len(query.DeviceTagResolutions["tag-ref-01"]) != 1 || request.PublicCanonicalQuery != `device.name:"Bench Camera" AND device.tag:camera AND time:last_15m` {
			t.Fatalf("query snapshot did not freeze selector resolution: %#v %#v %v", request, query, err)
		}
		anchor := created
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(EventQuerySnapshot{Schema: 1, ID: "qsnap-0123456789abcdef0123456789abcdef", CanonicalQuery: request.PublicCanonicalQuery, Sort: DefaultEventQuerySort(), QueryAnchor: &anchor, MatchedCount: 3, CountRelation: "eq", CreatedAt: created, ExpiresAt: created.Add(15 * time.Minute), DatasetWatermark: EventDatasetWatermark{ReceivedAt: created, RecordID: strings.Repeat("a", 64)}, SnapshotSHA256: strings.Repeat("b", 64), PolicyVersion: QuerySnapshotPolicyVersion})
	}))
	defer backend.Close()
	client, err := NewQueryClient(backend.URL, []byte(token), backend.Client())
	if err != nil {
		t.Fatal(err)
	}
	filter, err := querylang.Parse(`device.name:"Bench Camera" AND device.tag:camera AND time:last_15m`)
	if err != nil {
		t.Fatal(err)
	}
	deviceID := "device-0123456789abcdef0123456789abcdef"
	snapshot, err := client.CreateEventQuerySnapshot(t.Context(), "admin", filter.Canonical, RecentEventQuery{Limit: 1, Filter: filter, DeviceNameResolutions: map[string][]string{"Bench Camera": {deviceID}}, DeviceTagResolutions: map[string][]string{"camera": {deviceID}}}, 15*time.Minute)
	if err != nil || snapshot.MatchedCount != 3 || snapshot.QueryAnchor == nil {
		t.Fatalf("query snapshot client failed: %#v %v", snapshot, err)
	}
}
