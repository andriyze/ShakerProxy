package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/savedview"
)

type savedViewRepositoryFake struct{ view savedview.View }

func (f *savedViewRepositoryFake) List(context.Context, string, savedview.ListFilter) (savedview.Page, error) {
	views := []savedview.View{}
	if f.view.ID != "" {
		views = append(views, f.view)
	}
	return savedview.Page{Schema: 1, Views: views}, nil
}
func (f *savedViewRepositoryFake) Get(_ context.Context, _ string, id string) (savedview.View, error) {
	if f.view.ID != id {
		return savedview.View{}, savedview.ErrNotFound
	}
	return f.view, nil
}
func (f *savedViewRepositoryFake) Create(_ context.Context, actor string, configuration savedview.Configuration) (savedview.View, error) {
	normalized, err := savedview.Normalize(configuration)
	if err != nil {
		return savedview.View{}, err
	}
	now := time.Date(2026, 9, 1, 15, 0, 0, 0, time.UTC)
	f.view = savedview.View{Schema: 1, ID: "view-0123456789abcdef0123456789abcdef", Configuration: normalized, Owner: actor, LastEditor: actor, Revision: 1, CreatedAt: now, UpdatedAt: now}
	return f.view, nil
}
func (f *savedViewRepositoryFake) Update(_ context.Context, actor, id string, update savedview.Update) (savedview.View, error) {
	if f.view.ID != id {
		return savedview.View{}, savedview.ErrNotFound
	}
	if f.view.Owner != actor {
		return savedview.View{}, savedview.ErrForbidden
	}
	if f.view.Revision != update.ExpectedRevision {
		return savedview.View{}, savedview.ErrConflict
	}
	f.view.Configuration = update.Configuration
	f.view.Revision++
	f.view.LastEditor = actor
	f.view.UpdatedAt = f.view.UpdatedAt.Add(time.Minute)
	return f.view, nil
}
func (f *savedViewRepositoryFake) Delete(_ context.Context, actor, id string, revision int64) error {
	if f.view.ID != id {
		return savedview.ErrNotFound
	}
	if f.view.Owner != actor {
		return savedview.ErrForbidden
	}
	if f.view.Revision != revision {
		return savedview.ErrConflict
	}
	f.view = savedview.View{}
	return nil
}
func (f *savedViewRepositoryFake) History(_ context.Context, _ string, id string) (savedview.History, error) {
	if f.view.ID != id {
		return savedview.History{}, savedview.ErrNotFound
	}
	return savedview.History{Schema: 1, ViewID: id, Versions: []savedview.Version{{Revision: f.view.Revision, Editor: f.view.LastEditor, ChangedAt: f.view.UpdatedAt, Snapshot: f.view}}}, nil
}

func TestSavedViewAPICanonicalizesVersionsExportsAndDeletes(t *testing.T) {
	server, session := configuredAPIServer(t, filepath.Join(t.TempDir(), "absent.sock"))
	repository := &savedViewRepositoryFake{}
	server.savedViews = repository
	unauthenticated := httptest.NewRequest(http.MethodGet, "/api/v1/saved-views", nil)
	unauthenticated.Host = "shakerproxy.test"
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, unauthenticated)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated saved view list returned %d", recorder.Code)
	}
	body := `{"scope":"personal","name":"Camera traffic","page":"live-traffic","canonical_query":"source:zeek protocol:tcp","time_behavior":{"mode":"query"},"sort":[{"field":"occurred_at","direction":"desc"}],"columns":["source","occurred_at"],"pinned_columns":["source"],"density":"compact","chart":{"visible":false}}`
	request := authenticatedJSONRequest(http.MethodPost, "/api/v1/saved-views", body, session, "")
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated || !strings.Contains(recorder.Body.String(), `"canonical_query":"source:ZEEK AND protocol:tcp"`) || !strings.Contains(recorder.Body.String(), `"owner":"admin"`) || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("saved view creation returned %d: %s", recorder.Code, recorder.Body.String())
	}
	request = authenticatedJSONRequest(http.MethodPut, "/api/v1/saved-views/"+repository.view.ID, `{"expected_revision":0,"configuration":`+body+`}`, session, "")
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("invalid saved view revision returned %d: %s", recorder.Code, recorder.Body.String())
	}
	request = authenticatedJSONRequest(http.MethodGet, "/api/v1/saved-views/"+repository.view.ID+"/export", "", session, "")
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Header().Get("Content-Disposition"), repository.view.ID) || strings.Contains(recorder.Body.String(), `"owner"`) || !strings.Contains(recorder.Body.String(), `"view"`) {
		t.Fatalf("saved view export leaked metadata: %d %s", recorder.Code, recorder.Body.String())
	}
	request = authenticatedJSONRequest(http.MethodGet, "/api/v1/saved-views/"+repository.view.ID+"/history", "", session, "")
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"revision":1`) {
		t.Fatalf("saved view history returned %d: %s", recorder.Code, recorder.Body.String())
	}
	request = authenticatedJSONRequest(http.MethodDelete, "/api/v1/saved-views/"+repository.view.ID+"?expected_revision=1", "", session, "")
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent || !errors.Is(repository.Delete(t.Context(), "admin", "view-00000000000000000000000000000000", 1), savedview.ErrNotFound) {
		t.Fatalf("saved view delete returned %d", recorder.Code)
	}
}
