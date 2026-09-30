package savedview

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
)

const postgresSchemaVersion = 1

const postgresSchema = `
CREATE TABLE IF NOT EXISTS shakerproxy_schema_versions (
  component text PRIMARY KEY,
  version integer NOT NULL CHECK (version > 0),
  applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS shakerproxy_saved_views (
  id text PRIMARY KEY CHECK (id ~ '^view-[a-f0-9]{32}$'),
  scope text NOT NULL CHECK (scope IN ('personal', 'shared')),
  page text NOT NULL CHECK (page = 'live-traffic'),
  owner_name text NOT NULL CHECK (length(owner_name) BETWEEN 1 AND 96),
  view_name text NOT NULL CHECK (length(view_name) BETWEEN 1 AND 96),
  configuration jsonb NOT NULL,
  last_editor text NOT NULL CHECK (length(last_editor) BETWEEN 1 AND 96),
  revision bigint NOT NULL CHECK (revision > 0),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS shakerproxy_saved_views_visibility_idx ON shakerproxy_saved_views(scope, owner_name, page, updated_at DESC, id);
CREATE TABLE IF NOT EXISTS shakerproxy_saved_view_versions (
  view_id text NOT NULL REFERENCES shakerproxy_saved_views(id) ON DELETE CASCADE,
  revision bigint NOT NULL CHECK (revision > 0),
  editor text NOT NULL CHECK (length(editor) BETWEEN 1 AND 96),
  changed_at timestamptz NOT NULL,
  snapshot jsonb NOT NULL,
  PRIMARY KEY (view_id, revision)
);
INSERT INTO shakerproxy_schema_versions(component, version)
VALUES ('saved_views', 1)
ON CONFLICT (component) DO UPDATE SET version = EXCLUDED.version, applied_at = clock_timestamp()
WHERE shakerproxy_schema_versions.version < EXCLUDED.version;
`

type PostgresStore struct{ DB *sql.DB }

func (s PostgresStore) Migrate(ctx context.Context) error {
	if s.DB == nil {
		return errors.New("PostgreSQL connection is required")
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fmt.Errorf("begin saved view migration: %w", err)
	}
	defer tx.Rollback()
	for _, statement := range strings.Split(postgresSchema, ";") {
		statement = strings.TrimSpace(statement)
		if statement == "" {
			continue
		}
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migrate saved view schema: %w", err)
		}
	}
	var version int
	if err := tx.QueryRowContext(ctx, "SELECT version FROM shakerproxy_schema_versions WHERE component = 'saved_views'").Scan(&version); err != nil || version != postgresSchemaVersion {
		return errors.New("saved view database schema version is unsupported")
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit saved view migration: %w", err)
	}
	return nil
}

func (s PostgresStore) List(ctx context.Context, actor string, filter ListFilter) (Page, error) {
	if s.DB == nil || !ValidActor(actor) || filter.Scope != "" && filter.Scope != ScopePersonal && filter.Scope != ScopeShared || filter.Page != "" && filter.Page != "live-traffic" {
		return Page{}, errors.New("saved view list request is invalid")
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT id, scope, page, owner_name, view_name, configuration, last_editor, revision, created_at, updated_at
FROM shakerproxy_saved_views
WHERE (scope = 'shared' OR owner_name = $1) AND ($2 = '' OR scope = $2) AND ($3 = '' OR page = $3)
ORDER BY updated_at DESC, id ASC LIMIT 100`, actor, filter.Scope, filter.Page)
	if err != nil {
		return Page{}, fmt.Errorf("list saved views: %w", err)
	}
	defer rows.Close()
	views := make([]View, 0)
	for rows.Next() {
		view, err := scanView(rows)
		if err != nil {
			return Page{}, err
		}
		views = append(views, view)
	}
	if err := rows.Err(); err != nil {
		return Page{}, fmt.Errorf("read saved views: %w", err)
	}
	return Page{Schema: SchemaVersion, Views: views}, nil
}

func (s PostgresStore) Get(ctx context.Context, actor, id string) (View, error) {
	if s.DB == nil || !ValidActor(actor) || !ValidID(id) {
		return View{}, errors.New("saved view lookup is invalid")
	}
	view, err := scanView(s.DB.QueryRowContext(ctx, `SELECT id, scope, page, owner_name, view_name, configuration, last_editor, revision, created_at, updated_at
FROM shakerproxy_saved_views WHERE id = $1 AND (scope = 'shared' OR owner_name = $2)`, id, actor))
	if errors.Is(err, sql.ErrNoRows) {
		return View{}, ErrNotFound
	}
	return view, err
}

func (s PostgresStore) Create(ctx context.Context, actor string, configuration Configuration) (View, error) {
	if s.DB == nil || !ValidActor(actor) {
		return View{}, errors.New("saved view create request is invalid")
	}
	normalized, err := Normalize(configuration)
	if err != nil {
		return View{}, err
	}
	encoded, err := json.Marshal(normalized)
	if err != nil {
		return View{}, err
	}
	for attempt := 0; attempt < 3; attempt++ {
		id, err := newID()
		if err != nil {
			return View{}, err
		}
		tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
		if err != nil {
			return View{}, fmt.Errorf("begin saved view creation: %w", err)
		}
		if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", actor); err != nil {
			_ = tx.Rollback()
			return View{}, fmt.Errorf("lock saved view owner: %w", err)
		}
		var ownedCount int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM shakerproxy_saved_views WHERE owner_name=$1", actor).Scan(&ownedCount); err != nil {
			_ = tx.Rollback()
			return View{}, fmt.Errorf("count owned saved views: %w", err)
		}
		if ownedCount >= MaxOwnedViews {
			_ = tx.Rollback()
			return View{}, ErrLimit
		}
		view, err := scanView(tx.QueryRowContext(ctx, `INSERT INTO shakerproxy_saved_views(id, scope, page, owner_name, view_name, configuration, last_editor, revision, created_at, updated_at)
VALUES ($1,$2,$3,$4,$5,$6::jsonb,$4,1,clock_timestamp(),clock_timestamp())
RETURNING id, scope, page, owner_name, view_name, configuration, last_editor, revision, created_at, updated_at`, id, normalized.Scope, normalized.Page, actor, normalized.Name, encoded))
		if err == nil {
			err = insertVersion(ctx, tx, view)
		}
		if err == nil {
			err = tx.Commit()
		}
		if err == nil {
			return view, nil
		}
		_ = tx.Rollback()
		if !isUniqueViolation(err) {
			return View{}, fmt.Errorf("create saved view: %w", err)
		}
	}
	return View{}, errors.New("could not allocate a saved view ID")
}

func (s PostgresStore) Update(ctx context.Context, actor, id string, update Update) (View, error) {
	if s.DB == nil || !ValidActor(actor) || !ValidID(id) || update.ExpectedRevision < 1 {
		return View{}, errors.New("saved view update request is invalid")
	}
	normalized, err := Normalize(update.Configuration)
	if err != nil {
		return View{}, err
	}
	encoded, err := json.Marshal(normalized)
	if err != nil {
		return View{}, err
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return View{}, fmt.Errorf("begin saved view update: %w", err)
	}
	defer tx.Rollback()
	current, err := loadForMutation(ctx, tx, actor, id)
	if err != nil {
		return View{}, err
	}
	if current.Revision != update.ExpectedRevision {
		return View{}, ErrConflict
	}
	view, err := scanView(tx.QueryRowContext(ctx, `UPDATE shakerproxy_saved_views SET scope=$2, page=$3, view_name=$4, configuration=$5::jsonb, last_editor=$6, revision=revision+1, updated_at=clock_timestamp()
WHERE id=$1 RETURNING id, scope, page, owner_name, view_name, configuration, last_editor, revision, created_at, updated_at`, id, normalized.Scope, normalized.Page, normalized.Name, encoded, actor))
	if err != nil {
		return View{}, fmt.Errorf("update saved view: %w", err)
	}
	if err := insertVersion(ctx, tx, view); err != nil {
		return View{}, err
	}
	if err := tx.Commit(); err != nil {
		return View{}, fmt.Errorf("commit saved view update: %w", err)
	}
	return view, nil
}

func (s PostgresStore) Delete(ctx context.Context, actor, id string, expectedRevision int64) error {
	if s.DB == nil || !ValidActor(actor) || !ValidID(id) || expectedRevision < 1 {
		return errors.New("saved view delete request is invalid")
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("begin saved view deletion: %w", err)
	}
	defer tx.Rollback()
	current, err := loadForMutation(ctx, tx, actor, id)
	if err != nil {
		return err
	}
	if current.Revision != expectedRevision {
		return ErrConflict
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM shakerproxy_saved_views WHERE id=$1", id); err != nil {
		return fmt.Errorf("delete saved view: %w", err)
	}
	return tx.Commit()
}

func (s PostgresStore) History(ctx context.Context, actor, id string) (History, error) {
	if _, err := s.Get(ctx, actor, id); err != nil {
		return History{}, err
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT revision, editor, changed_at, snapshot FROM shakerproxy_saved_view_versions WHERE view_id=$1 ORDER BY revision DESC LIMIT 100`, id)
	if err != nil {
		return History{}, fmt.Errorf("list saved view history: %w", err)
	}
	defer rows.Close()
	versions := make([]Version, 0)
	for rows.Next() {
		var version Version
		var raw []byte
		if err := rows.Scan(&version.Revision, &version.Editor, &version.ChangedAt, &raw); err != nil {
			return History{}, fmt.Errorf("decode saved view history: %w", err)
		}
		if err := decodeStrict(raw, &version.Snapshot); err != nil || ValidateView(version.Snapshot) != nil || version.Snapshot.ID != id || version.Snapshot.Revision != version.Revision || version.Snapshot.LastEditor != version.Editor {
			return History{}, errors.New("saved view history contains an invalid snapshot")
		}
		version.ChangedAt = version.ChangedAt.UTC()
		if !version.ChangedAt.Equal(version.Snapshot.UpdatedAt) {
			return History{}, errors.New("saved view history timestamp does not match its snapshot")
		}
		versions = append(versions, version)
	}
	if err := rows.Err(); err != nil {
		return History{}, fmt.Errorf("read saved view history: %w", err)
	}
	return History{Schema: SchemaVersion, ViewID: id, Versions: versions}, nil
}

type rowScanner interface{ Scan(...any) error }

func scanView(row rowScanner) (View, error) {
	var view View
	var scope string
	var raw []byte
	if err := row.Scan(&view.ID, &scope, &view.Page, &view.Owner, &view.Name, &raw, &view.LastEditor, &view.Revision, &view.CreatedAt, &view.UpdatedAt); err != nil {
		return View{}, err
	}
	if err := decodeStrict(raw, &view.Configuration); err != nil {
		return View{}, errors.New("saved view configuration is invalid")
	}
	view.Scope = Scope(scope)
	view.Schema = SchemaVersion
	view.CreatedAt, view.UpdatedAt = view.CreatedAt.UTC(), view.UpdatedAt.UTC()
	normalized, err := Normalize(view.Configuration)
	if err != nil || !reflect.DeepEqual(normalized, view.Configuration) || normalized.Scope != view.Scope || normalized.Page != view.Page || normalized.Name != view.Name || !ValidID(view.ID) || !ValidActor(view.Owner) || !ValidActor(view.LastEditor) || view.Revision < 1 || view.CreatedAt.IsZero() || view.UpdatedAt.Before(view.CreatedAt) {
		return View{}, errors.New("saved view row is invalid")
	}
	view.Configuration = normalized
	return view, nil
}

func loadForMutation(ctx context.Context, tx *sql.Tx, actor, id string) (View, error) {
	view, err := scanView(tx.QueryRowContext(ctx, `SELECT id, scope, page, owner_name, view_name, configuration, last_editor, revision, created_at, updated_at FROM shakerproxy_saved_views WHERE id=$1 FOR UPDATE`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return View{}, ErrNotFound
	}
	if err != nil {
		return View{}, err
	}
	if view.Owner != actor {
		return View{}, ErrForbidden
	}
	return view, nil
}

func insertVersion(ctx context.Context, tx *sql.Tx, view View) error {
	snapshot, err := json.Marshal(view)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO shakerproxy_saved_view_versions(view_id, revision, editor, changed_at, snapshot) VALUES ($1,$2,$3,$4,$5::jsonb)`, view.ID, view.Revision, view.LastEditor, view.UpdatedAt, snapshot); err != nil {
		return fmt.Errorf("append saved view version: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM shakerproxy_saved_view_versions WHERE view_id=$1 AND revision <= $2`, view.ID, view.Revision-MaxHistory); err != nil {
		return fmt.Errorf("prune saved view history: %w", err)
	}
	return nil
}

func newID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return "view-" + hex.EncodeToString(value), nil
}

func decodeStrict(data []byte, destination any) error {
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("JSON contains trailing data")
	}
	return nil
}

func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "SQLSTATE 23505")
}
