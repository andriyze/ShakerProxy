package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/ingest"
)

type internalEventQuerySnapshotRepository struct {
	actor string
	query ingest.RecentEventQuery
}

func (f *internalEventQuerySnapshotRepository) CreateEventQuerySnapshot(_ context.Context, actor, canonical string, query ingest.RecentEventQuery, lifetime time.Duration) (ingest.EventQuerySnapshot, error) {
	f.actor, f.query = actor, query
	now := time.Date(2026, 9, 1, 15, 0, 0, 0, time.UTC)
	return ingest.EventQuerySnapshot{Schema: 1, ID: "qsnap-0123456789abcdef0123456789abcdef", CanonicalQuery: canonical, Sort: ingest.DefaultEventQuerySort(), MatchedCount: 1, CountRelation: "eq", CreatedAt: now, ExpiresAt: now.Add(lifetime), DatasetWatermark: ingest.EventDatasetWatermark{ReceivedAt: now, RecordID: strings.Repeat("a", 64)}, SnapshotSHA256: strings.Repeat("b", 64), PolicyVersion: ingest.QuerySnapshotPolicyVersion}, nil
}

func (f *internalEventQuerySnapshotRepository) GetEventQuerySnapshot(context.Context, string, string) (ingest.EventQuerySnapshot, error) {
	return ingest.EventQuerySnapshot{}, ingest.ErrQuerySnapshotNotFound
}

func TestInternalEventQuerySnapshotsUseOnlyQueryCredentialAndActor(t *testing.T) {
	repository := &internalEventQuerySnapshotRepository{}
	server, err := New(Config{Spool: &ingest.Spool{Root: filepath.Join(t.TempDir(), "spool"), MaxBytes: 8 << 20, ReserveBytes: 1}, Token: []byte(testToken), QueryToken: []byte(testQueryToken), EventSnapshots: repository})
	if err != nil {
		t.Fatal(err)
	}
	values := url.Values{"limit": {"1"}, "q": {"protocol:tcp"}}
	body := `{"schema":1,"public_canonical_query":"protocol:tcp","encoded_query":` + strconvQuote(values.Encode()) + `,"expires_in_seconds":900}`
	for _, token := range []string{"", testToken} {
		request := httptest.NewRequest(http.MethodPost, "/v1/event-query-snapshots", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-ShakerProxy-Actor", "admin")
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("non-query token returned %d", recorder.Code)
		}
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/event-query-snapshots", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+testQueryToken)
	request.Header.Set("X-ShakerProxy-Actor", "admin")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated || repository.actor != "admin" || repository.query.Filter.Canonical != "protocol:tcp" {
		t.Fatalf("query snapshot boundary returned %d: %s", recorder.Code, recorder.Body.String())
	}
}

func strconvQuote(value string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value) + `"`
}
