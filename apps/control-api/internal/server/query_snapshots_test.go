package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/ingest"
	"shakerproxy.dev/shakerproxy/internal/querylang"
)

type eventQuerySnapshotRepositoryFake struct {
	snapshot ingest.EventQuerySnapshot
	query    ingest.RecentEventQuery
	actor    string
}

func (f *eventQuerySnapshotRepositoryFake) CreateEventQuerySnapshot(_ context.Context, actor, canonical string, query ingest.RecentEventQuery, lifetime time.Duration) (ingest.EventQuerySnapshot, error) {
	f.actor, f.query = actor, query
	now := time.Date(2026, 9, 1, 15, 0, 0, 0, time.UTC)
	f.snapshot = ingest.EventQuerySnapshot{Schema: 1, ID: "qsnap-0123456789abcdef0123456789abcdef", CanonicalQuery: canonical, Sort: ingest.DefaultEventQuerySort(), MatchedCount: 42, CountRelation: "eq", CreatedAt: now, ExpiresAt: now.Add(lifetime), DatasetWatermark: ingest.EventDatasetWatermark{ReceivedAt: now, RecordID: strings.Repeat("a", 64)}, SnapshotSHA256: strings.Repeat("b", 64), PolicyVersion: ingest.QuerySnapshotPolicyVersion}
	if querylang.HasRelativeTime(query.Filter) {
		anchor := now
		f.snapshot.QueryAnchor = &anchor
	}
	return f.snapshot, nil
}

func (f *eventQuerySnapshotRepositoryFake) GetEventQuerySnapshot(_ context.Context, actor, id string) (ingest.EventQuerySnapshot, error) {
	if actor != f.actor || id != f.snapshot.ID {
		return ingest.EventQuerySnapshot{}, ingest.ErrQuerySnapshotNotFound
	}
	return f.snapshot, nil
}

func TestEventQuerySnapshotAPICanonicalizesAuthenticatesAndRestores(t *testing.T) {
	server, session := configuredAPIServer(t, filepath.Join(t.TempDir(), "absent.sock"))
	repository := &eventQuerySnapshotRepositoryFake{}
	server.eventSnapshots = repository
	body := `{"query":"source:zeek time:last_15m","sort":[{"field":"occurred_at","direction":"desc"},{"field":"record_id","direction":"desc"}]}`
	request := authenticatedJSONRequest(http.MethodPost, "/api/v1/event-query-snapshots", body, "", "")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated query snapshot returned %d", recorder.Code)
	}
	request = authenticatedJSONRequest(http.MethodPost, "/api/v1/event-query-snapshots", body, session, "")
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated || recorder.Header().Get("Cache-Control") != "no-store" || repository.actor != "admin" || repository.query.Filter.Canonical != "source:ZEEK AND time:last_15m" || !strings.Contains(recorder.Body.String(), `"matched_count":42`) || !strings.Contains(recorder.Body.String(), `"query_anchor"`) {
		t.Fatalf("query snapshot creation returned %d: %s", recorder.Code, recorder.Body.String())
	}
	request = authenticatedJSONRequest(http.MethodGet, "/api/v1/event-query-snapshots/"+repository.snapshot.ID, "", session, "")
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), repository.snapshot.SnapshotSHA256) {
		t.Fatalf("query snapshot lookup returned %d: %s", recorder.Code, recorder.Body.String())
	}
	request = authenticatedJSONRequest(http.MethodPost, "/api/v1/event-query-snapshots", `{"query":"protocol:tcp","sort":[{"field":"payload","direction":"asc"}]}`, session, "")
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("unsafe query snapshot sort returned %d", recorder.Code)
	}
	request = authenticatedJSONRequest(http.MethodPost, "/api/v1/event-query-snapshots", `{"query":"protocol:tcp","sort":[{"field":"occurred_at","direction":"desc"},{"field":"record_id","direction":"desc"}],"expires_in_seconds":9223372036854775807}`, session, "")
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("overflowing query snapshot expiry returned %d", recorder.Code)
	}
}
