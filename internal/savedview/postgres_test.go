package savedview

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestPostgresStoreIntegration(t *testing.T) {
	databaseURL := os.Getenv("SHAKERPROXY_POSTGRES_TEST_URL")
	if databaseURL == "" {
		t.Skip("SHAKERPROXY_POSTGRES_TEST_URL is not set")
	}
	database, err := sql.Open("pgx", databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store := PostgresStore{DB: database}
	if err := store.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(t.Context(), "TRUNCATE shakerproxy_saved_view_versions, shakerproxy_saved_views"); err != nil {
		t.Fatal(err)
	}
	base := Configuration{Scope: ScopePersonal, Name: "Camera traffic", Description: "Investigation", Page: "live-traffic", CanonicalQuery: `name:"Bench Camera" protocol:tcp`, TimeBehavior: TimeBehavior{Mode: "query"}}
	created, err := store.Create(t.Context(), "admin", base)
	if err != nil || created.Revision != 1 || created.Owner != "admin" || created.CanonicalQuery != `device.name:"Bench Camera" AND protocol:tcp` {
		t.Fatalf("saved view create failed: %#v %v", created, err)
	}
	if _, err := store.Get(t.Context(), "other", created.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("personal view leaked to another actor: %v", err)
	}
	update := Update{ExpectedRevision: 1, Configuration: created.Configuration}
	update.Configuration.Scope = ScopeShared
	update.Configuration.Description = "Shared investigation"
	updated, err := store.Update(t.Context(), "admin", created.ID, update)
	if err != nil || updated.Revision != 2 || updated.Scope != ScopeShared || updated.LastEditor != "admin" {
		t.Fatalf("saved view update failed: %#v %v", updated, err)
	}
	if _, err := store.Update(t.Context(), "admin", created.ID, update); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale saved view update did not conflict: %v", err)
	}
	if _, err := store.Update(t.Context(), "other", created.ID, Update{ExpectedRevision: 2, Configuration: updated.Configuration}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("non-owner changed shared view: %v", err)
	}
	listed, err := store.List(t.Context(), "other", ListFilter{Scope: ScopeShared, Page: "live-traffic"})
	if err != nil || len(listed.Views) != 1 || listed.Views[0].ID != created.ID {
		t.Fatalf("shared view was not visible: %#v %v", listed, err)
	}
	history, err := store.History(t.Context(), "other", created.ID)
	if err != nil || len(history.Versions) != 2 || history.Versions[0].Revision != 2 || history.Versions[1].Revision != 1 {
		t.Fatalf("saved view history was not immutable: %#v %v", history, err)
	}
	if err := store.Delete(context.Background(), "admin", created.ID, 1); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale saved view delete did not conflict: %v", err)
	}
	if err := store.Delete(context.Background(), "admin", created.ID, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(t.Context(), "admin", created.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted view remained visible: %v", err)
	}
}
