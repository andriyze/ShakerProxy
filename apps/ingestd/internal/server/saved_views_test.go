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
	"shakerproxy.dev/shakerproxy/internal/savedview"
)

const testSavedViewToken = "saved-view-test-token-0000000000001"

type internalSavedViewRepository struct{ created savedview.View }

func (r *internalSavedViewRepository) List(context.Context, string, savedview.ListFilter) (savedview.Page, error) {
	return savedview.Page{Schema: 1, Views: []savedview.View{}}, nil
}
func (r *internalSavedViewRepository) Get(context.Context, string, string) (savedview.View, error) {
	return r.created, nil
}
func (r *internalSavedViewRepository) Create(_ context.Context, actor string, configuration savedview.Configuration) (savedview.View, error) {
	normalized, err := savedview.Normalize(configuration)
	if err != nil {
		return savedview.View{}, err
	}
	now := time.Date(2026, 9, 1, 15, 0, 0, 0, time.UTC)
	r.created = savedview.View{Schema: 1, ID: "view-0123456789abcdef0123456789abcdef", Configuration: normalized, Owner: actor, LastEditor: actor, Revision: 1, CreatedAt: now, UpdatedAt: now}
	return r.created, nil
}
func (r *internalSavedViewRepository) Update(context.Context, string, string, savedview.Update) (savedview.View, error) {
	return savedview.View{}, savedview.ErrNotFound
}
func (r *internalSavedViewRepository) Delete(context.Context, string, string, int64) error {
	return savedview.ErrNotFound
}
func (r *internalSavedViewRepository) History(context.Context, string, string) (savedview.History, error) {
	return savedview.History{}, savedview.ErrNotFound
}

func TestSavedViewStorageUsesOnlyItsDistinctTokenAndActor(t *testing.T) {
	repository := &internalSavedViewRepository{}
	server, err := New(Config{Spool: &ingest.Spool{Root: filepath.Join(t.TempDir(), "spool"), MaxBytes: 8 << 20, ReserveBytes: 1}, Token: []byte(testToken), QueryToken: []byte(testQueryToken), SavedViewToken: []byte(testSavedViewToken), SavedViews: repository})
	if err != nil {
		t.Fatal(err)
	}
	body := `{"scope":"personal","name":"Camera traffic","page":"live-traffic","canonical_query":"source:zeek","time_behavior":{"mode":"query"},"sort":[{"field":"occurred_at","direction":"desc"}],"columns":["source"],"pinned_columns":["source"],"density":"compact","chart":{"visible":false}}`
	for _, token := range []string{"", testToken, testQueryToken} {
		request := httptest.NewRequest(http.MethodPost, "/v1/saved-views", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		request.Header.Set("X-ShakerProxy-Actor", "admin")
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("non-saved-view token returned %d", recorder.Code)
		}
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/saved-views", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+testSavedViewToken)
	request.Header.Set("X-ShakerProxy-Actor", "admin")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated || repository.created.Owner != "admin" || repository.created.CanonicalQuery != "source:ZEEK" || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("authenticated saved view create returned %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestSavedViewStorageRequiresDistinctCredential(t *testing.T) {
	_, err := New(Config{Spool: &ingest.Spool{Root: filepath.Join(t.TempDir(), "spool"), MaxBytes: 8 << 20, ReserveBytes: 1}, Token: []byte(testToken), QueryToken: []byte(testQueryToken), SavedViewToken: []byte(testQueryToken), SavedViews: &internalSavedViewRepository{}})
	if err == nil {
		t.Fatal("event query token was reused for saved view mutation")
	}
}
