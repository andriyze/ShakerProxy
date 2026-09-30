package savedview

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestClientUsesIsolatedCredentialActorAndStrictResponse(t *testing.T) {
	token := strings.Repeat("s", 32)
	now := time.Date(2026, 9, 1, 15, 0, 0, 0, time.UTC)
	configuration, err := Normalize(Configuration{Scope: ScopePersonal, Name: "Camera traffic", Page: "live-traffic", CanonicalQuery: "source:zeek", TimeBehavior: TimeBehavior{Mode: "query"}})
	if err != nil {
		t.Fatal(err)
	}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token || r.Header.Get("X-ShakerProxy-Actor") != "admin" || r.Header.Get("Accept") != "application/json" {
			t.Errorf("saved view boundary headers were not isolated: %#v", r.Header)
		}
		w.Header().Set("Content-Type", "application/json")
		view := View{Schema: 1, ID: "view-0123456789abcdef0123456789abcdef", Configuration: configuration, Owner: "admin", LastEditor: "admin", Revision: 1, CreatedAt: now, UpdatedAt: now}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/saved-views":
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(view)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/saved-views":
			_ = json.NewEncoder(w).Encode(Page{Schema: 1, Views: []View{view}})
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/history"):
			_ = json.NewEncoder(w).Encode(History{Schema: 1, ViewID: view.ID, Versions: []Version{{Revision: 1, Editor: "admin", ChangedAt: now, Snapshot: view}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer backend.Close()
	client, err := NewClient(backend.URL, []byte(token), backend.Client())
	if err != nil {
		t.Fatal(err)
	}
	created, err := client.Create(t.Context(), "admin", configuration)
	if err != nil || created.CanonicalQuery != "source:ZEEK" {
		t.Fatalf("saved view client create failed: %#v %v", created, err)
	}
	page, err := client.List(t.Context(), "admin", ListFilter{Scope: ScopePersonal, Page: "live-traffic"})
	if err != nil || len(page.Views) != 1 {
		t.Fatalf("saved view client list failed: %#v %v", page, err)
	}
	history, err := client.History(t.Context(), "admin", created.ID)
	if err != nil || len(history.Versions) != 1 {
		t.Fatalf("saved view client history failed: %#v %v", history, err)
	}
}

func TestClientRejectsUnsafeCredentialAndMisrepresentedView(t *testing.T) {
	if _, err := NewClient("http://saved-views.test", []byte(strings.Repeat("x", 31)+"\n"), nil); err == nil {
		t.Fatal("unsafe saved view token was accepted")
	}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"schema":1,"views":[{"schema":1,"id":"view-0123456789abcdef0123456789abcdef","scope":"personal","name":"Unsafe","page":"live-traffic","time_behavior":{"mode":"query"},"sort":[],"columns":[],"pinned_columns":[],"density":"comfortable","chart":{"visible":false},"owner":"someone-else","last_editor":"someone-else","revision":1,"created_at":"2026-09-01T15:00:00Z","updated_at":"2026-09-01T15:00:00Z"}]}`))
	}))
	defer backend.Close()
	client, err := NewClient(backend.URL, []byte(strings.Repeat("s", 32)), backend.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.List(t.Context(), "admin", ListFilter{}); err == nil {
		t.Fatal("another actor's personal saved view crossed the boundary")
	}
}
