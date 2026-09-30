package ingest

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"time"

	"shakerproxy.dev/shakerproxy/internal/querylang"
)

type storedEventQueryState struct {
	Source                Source              `json:"source,omitempty"`
	Kind                  string              `json:"kind,omitempty"`
	CaptureSessionID      string              `json:"capture_session_id,omitempty"`
	DeviceID              string              `json:"device_id,omitempty"`
	CanonicalQuery        string              `json:"canonical_query,omitempty"`
	DeviceNameResolutions map[string][]string `json:"device_name_resolutions,omitempty"`
	DeviceTagResolutions  map[string][]string `json:"device_tag_resolutions,omitempty"`
}

func (s PostgresSink) CreateEventQuerySnapshot(ctx context.Context, actor, publicCanonical string, query RecentEventQuery, lifetime time.Duration) (EventQuerySnapshot, error) {
	if s.DB == nil || !validSnapshotActor(actor) || lifetime < MinQuerySnapshotTTL || lifetime > MaxQuerySnapshotTTL || lifetime%time.Second != 0 || !query.BeforeOccurredAt.IsZero() || query.BeforeRecordID != "" || query.Source != "" || query.Kind != "" || query.CaptureSessionID != "" || query.DeviceID != "" {
		return EventQuerySnapshot{}, errors.New("event query snapshot request is invalid")
	}
	publicFilter, err := querylang.Parse(publicCanonical)
	if err != nil || publicFilter.Canonical != publicCanonical {
		return EventQuerySnapshot{}, errors.New("event query snapshot canonical filter is invalid")
	}
	query.Limit = 1
	if err := validateRecentEventQuery(query); err != nil {
		return EventQuerySnapshot{}, err
	}
	if err := validateSnapshotFilterMapping(publicFilter, query.Filter); err != nil {
		return EventQuerySnapshot{}, err
	}
	state := stateFromRecentQuery(query)
	encodedState, err := json.Marshal(state)
	if err != nil || len(encodedState) > 32<<10 {
		return EventQuerySnapshot{}, errors.New("event query snapshot state is invalid")
	}
	id, err := newQuerySnapshotID()
	if err != nil {
		return EventQuerySnapshot{}, err
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return EventQuerySnapshot{}, fmt.Errorf("begin event query snapshot: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1, 1))", actor); err != nil {
		return EventQuerySnapshot{}, fmt.Errorf("lock event query snapshot owner: %w", err)
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM shakerproxy_event_query_snapshots WHERE expires_at <= clock_timestamp()"); err != nil {
		return EventQuerySnapshot{}, fmt.Errorf("expire event query snapshots: %w", err)
	}
	var active int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM shakerproxy_event_query_snapshots WHERE actor_name=$1", actor).Scan(&active); err != nil {
		return EventQuerySnapshot{}, fmt.Errorf("count active event query snapshots: %w", err)
	}
	if active >= MaxActiveQuerySnapshots {
		return EventQuerySnapshot{}, ErrQuerySnapshotLimit
	}
	if _, err := tx.ExecContext(ctx, "LOCK TABLE normalized_events IN SHARE MODE"); err != nil {
		return EventQuerySnapshot{}, fmt.Errorf("freeze event query dataset boundary: %w", err)
	}
	var createdAt time.Time
	if err := tx.QueryRowContext(ctx, "SELECT clock_timestamp()").Scan(&createdAt); err != nil {
		return EventQuerySnapshot{}, fmt.Errorf("read event query snapshot time: %w", err)
	}
	createdAt = createdAt.UTC()
	if querylang.HasRelativeTime(query.Filter) {
		query.TimeAnchor = createdAt
		state = stateFromRecentQuery(query)
		encodedState, err = json.Marshal(state)
		if err != nil {
			return EventQuerySnapshot{}, errors.New("encode anchored event query snapshot")
		}
	}
	watermark := EventDatasetWatermark{ReceivedAt: createdAt, RecordID: strings.Repeat("0", 64)}
	row := tx.QueryRowContext(ctx, "SELECT ingest_sequence, received_at, record_id FROM normalized_events ORDER BY ingest_sequence DESC LIMIT 1")
	if err := row.Scan(&watermark.IngestSequence, &watermark.ReceivedAt, &watermark.RecordID); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return EventQuerySnapshot{}, fmt.Errorf("read event query dataset watermark: %w", err)
	}
	watermark.ReceivedAt = watermark.ReceivedAt.UTC()
	clauses, args, err := buildEventWhere(query, true)
	if err != nil {
		return EventQuerySnapshot{}, err
	}
	args = append(args, watermark.IngestSequence)
	clauses = append(clauses, fmt.Sprintf("ingest_sequence <= $%d", len(args)))
	statement := fmt.Sprintf("SELECT count(*) FROM (SELECT 1 FROM normalized_events WHERE %s LIMIT %d) bounded_matches", strings.Join(clauses, " AND "), MaxQuerySnapshotCountScan+1)
	var count int64
	if err := tx.QueryRowContext(ctx, statement, args...).Scan(&count); err != nil {
		return EventQuerySnapshot{}, fmt.Errorf("count frozen event query population: %w", err)
	}
	relation := "eq"
	if count > MaxQuerySnapshotCountScan {
		count, relation = MaxQuerySnapshotCountScan, "gte"
	}
	expiresAt := createdAt.Add(lifetime)
	snapshot := EventQuerySnapshot{Schema: QuerySnapshotSchemaVersion, ID: id, CanonicalQuery: publicCanonical, Sort: DefaultEventQuerySort(), MatchedCount: count, CountRelation: relation, CreatedAt: createdAt, ExpiresAt: expiresAt, DatasetWatermark: watermark, PolicyVersion: QuerySnapshotPolicyVersion}
	if !query.TimeAnchor.IsZero() {
		anchor := query.TimeAnchor.UTC()
		snapshot.QueryAnchor = &anchor
	}
	snapshot.SnapshotSHA256, err = hashEventQuerySnapshot(actor, snapshot, state)
	if err != nil {
		return EventQuerySnapshot{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO shakerproxy_event_query_snapshots(
id, actor_name, public_canonical_query, query_state, query_anchor, watermark_received_at,
watermark_record_id, watermark_ingest_sequence, matched_count, count_relation, snapshot_sha256, policy_version, created_at, expires_at)
VALUES ($1,$2,$3,$4::jsonb,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, snapshot.ID, actor, snapshot.CanonicalQuery, encodedState, nullableTime(snapshot.QueryAnchor), watermark.ReceivedAt, watermark.RecordID, watermark.IngestSequence, snapshot.MatchedCount, snapshot.CountRelation, snapshot.SnapshotSHA256, snapshot.PolicyVersion, snapshot.CreatedAt, snapshot.ExpiresAt); err != nil {
		return EventQuerySnapshot{}, fmt.Errorf("persist event query snapshot: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return EventQuerySnapshot{}, fmt.Errorf("commit event query snapshot: %w", err)
	}
	return snapshot, nil
}

func (s PostgresSink) GetEventQuerySnapshot(ctx context.Context, actor, id string) (EventQuerySnapshot, error) {
	snapshot, _, err := s.loadEventQuerySnapshot(ctx, actor, id)
	return snapshot, err
}

func (s PostgresSink) ResolveEventQuerySnapshot(ctx context.Context, actor, id string) (ResolvedEventQuerySnapshot, error) {
	snapshot, state, err := s.loadEventQuerySnapshot(ctx, actor, id)
	if err != nil {
		return ResolvedEventQuerySnapshot{}, err
	}
	query, err := state.recentQuery(snapshot.QueryAnchor)
	if err != nil {
		return ResolvedEventQuerySnapshot{}, err
	}
	return ResolvedEventQuerySnapshot{Snapshot: snapshot, Query: query}, nil
}

func (s PostgresSink) loadEventQuerySnapshot(ctx context.Context, actor, id string) (EventQuerySnapshot, storedEventQueryState, error) {
	if s.DB == nil || !validSnapshotActor(actor) || !ValidQuerySnapshotID(id) {
		return EventQuerySnapshot{}, storedEventQueryState{}, errors.New("event query snapshot lookup is invalid")
	}
	var snapshot EventQuerySnapshot
	var raw []byte
	var anchor sql.NullTime
	var owner string
	err := s.DB.QueryRowContext(ctx, `SELECT id, actor_name, public_canonical_query, query_state, query_anchor,
watermark_received_at, watermark_record_id, watermark_ingest_sequence, matched_count, count_relation, snapshot_sha256,
policy_version, created_at, expires_at FROM shakerproxy_event_query_snapshots
WHERE id=$1 AND actor_name=$2 AND expires_at > clock_timestamp()`, id, actor).Scan(&snapshot.ID, &owner, &snapshot.CanonicalQuery, &raw, &anchor, &snapshot.DatasetWatermark.ReceivedAt, &snapshot.DatasetWatermark.RecordID, &snapshot.DatasetWatermark.IngestSequence, &snapshot.MatchedCount, &snapshot.CountRelation, &snapshot.SnapshotSHA256, &snapshot.PolicyVersion, &snapshot.CreatedAt, &snapshot.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return EventQuerySnapshot{}, storedEventQueryState{}, ErrQuerySnapshotNotFound
	}
	if err != nil {
		return EventQuerySnapshot{}, storedEventQueryState{}, fmt.Errorf("load event query snapshot: %w", err)
	}
	var state storedEventQueryState
	if err := decodeStrictSnapshotJSON(raw, &state); err != nil {
		return EventQuerySnapshot{}, storedEventQueryState{}, errors.New("stored event query snapshot state is invalid")
	}
	snapshot.Schema, snapshot.Sort = QuerySnapshotSchemaVersion, DefaultEventQuerySort()
	snapshot.CreatedAt, snapshot.ExpiresAt, snapshot.DatasetWatermark.ReceivedAt = snapshot.CreatedAt.UTC(), snapshot.ExpiresAt.UTC(), snapshot.DatasetWatermark.ReceivedAt.UTC()
	if anchor.Valid {
		value := anchor.Time.UTC()
		snapshot.QueryAnchor = &value
	}
	query, queryErr := state.recentQuery(snapshot.QueryAnchor)
	publicFilter, publicErr := querylang.Parse(snapshot.CanonicalQuery)
	expectedHash, hashErr := hashEventQuerySnapshot(owner, snapshot, state)
	if queryErr != nil || publicErr != nil || publicFilter.Canonical != snapshot.CanonicalQuery || validateSnapshotFilterMapping(publicFilter, query.Filter) != nil || hashErr != nil || ValidateEventQuerySnapshot(snapshot) != nil || expectedHash != snapshot.SnapshotSHA256 {
		return EventQuerySnapshot{}, storedEventQueryState{}, errors.New("stored event query snapshot is invalid")
	}
	return snapshot, state, nil
}

func stateFromRecentQuery(query RecentEventQuery) storedEventQueryState {
	return storedEventQueryState{Source: query.Source, Kind: query.Kind, CaptureSessionID: query.CaptureSessionID, DeviceID: query.DeviceID, CanonicalQuery: query.Filter.Canonical, DeviceNameResolutions: query.DeviceNameResolutions, DeviceTagResolutions: query.DeviceTagResolutions}
}

func validateSnapshotFilterMapping(public, storage querylang.Query) error {
	publicNames := querylang.DeviceNameValues(public)
	storageNames := querylang.DeviceNameValues(storage)
	publicTags := querylang.DeviceTagValues(public)
	storageTags := querylang.DeviceTagValues(storage)
	if len(publicNames) != len(storageNames) || len(publicTags) != len(storageTags) {
		return errors.New("event query snapshot selector mapping is invalid")
	}
	if len(publicNames) == 0 && len(publicTags) == 0 {
		if public.Canonical != storage.Canonical || !reflect.DeepEqual(public.Root, storage.Root) {
			return errors.New("event query snapshot public and storage filters differ")
		}
		return nil
	}
	replacements := make(map[string]string, len(publicNames))
	for index, name := range publicNames {
		expected := fmt.Sprintf("alias-ref-%02d", index+1)
		if storageNames[index] != expected {
			return errors.New("event query snapshot alias mapping is invalid")
		}
		replacements[name] = expected
	}
	rewritten, err := querylang.RewriteDeviceNames(public, replacements)
	if err != nil {
		return errors.New("event query snapshot public and storage filters differ")
	}
	tagReplacements := make(map[string]string, len(publicTags))
	for index, tag := range publicTags {
		expected := fmt.Sprintf("tag-ref-%02d", index+1)
		if storageTags[index] != expected {
			return errors.New("event query snapshot tag mapping is invalid")
		}
		tagReplacements[tag] = expected
	}
	rewritten, err = querylang.RewriteDeviceTags(rewritten, tagReplacements)
	if err != nil {
		return errors.New("event query snapshot public and storage filters differ")
	}
	// The internal query transport reparses its canonical text. Reparse the
	// independently rewritten public query too so equivalent ASTs use the same
	// normalized representation before the structural comparison.
	reparsed, err := querylang.Parse(rewritten.Canonical)
	if err != nil || reparsed.Canonical != storage.Canonical || !reflect.DeepEqual(reparsed.Root, storage.Root) {
		return errors.New("event query snapshot public and storage filters differ")
	}
	return nil
}

func (s storedEventQueryState) recentQuery(anchor *time.Time) (RecentEventQuery, error) {
	filter, err := querylang.Parse(s.CanonicalQuery)
	if err != nil || filter.Canonical != s.CanonicalQuery {
		return RecentEventQuery{}, errors.New("stored event query snapshot filter is invalid")
	}
	query := RecentEventQuery{Limit: 1, Source: s.Source, Kind: s.Kind, CaptureSessionID: s.CaptureSessionID, DeviceID: s.DeviceID, Filter: filter, DeviceNameResolutions: s.DeviceNameResolutions, DeviceTagResolutions: s.DeviceTagResolutions}
	if anchor != nil {
		query.TimeAnchor = anchor.UTC()
	}
	if err := validateRecentEventQuery(query); err != nil {
		return RecentEventQuery{}, err
	}
	if querylang.HasRelativeTime(filter) != (anchor != nil) {
		return RecentEventQuery{}, errors.New("stored event query snapshot anchor is inconsistent")
	}
	return query, nil
}

func hashEventQuerySnapshot(actor string, snapshot EventQuerySnapshot, state storedEventQueryState) (string, error) {
	snapshot.SnapshotSHA256 = ""
	payload := struct {
		Actor    string                `json:"actor"`
		Snapshot EventQuerySnapshot    `json:"snapshot"`
		State    storedEventQueryState `json:"state"`
	}{Actor: actor, Snapshot: snapshot, State: state}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func newQuerySnapshotID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return "qsnap-" + hex.EncodeToString(value), nil
}

func nullableTime(value *time.Time) any {
	if value == nil {
		return nil
	}
	return value.UTC()
}

func decodeStrictSnapshotJSON(data []byte, destination any) error {
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
