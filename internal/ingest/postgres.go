package ingest

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"shakerproxy.dev/shakerproxy/internal/capture"
)

const postgresSchemaVersion = 14

const postgresSchema = `
CREATE TABLE IF NOT EXISTS shakerproxy_schema_versions (
  component text PRIMARY KEY,
  version integer NOT NULL CHECK (version > 0),
  applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
INSERT INTO shakerproxy_schema_versions(component, version)
VALUES ('normalized_ingest', 14)
ON CONFLICT (component) DO UPDATE SET version = EXCLUDED.version, applied_at = clock_timestamp()
WHERE shakerproxy_schema_versions.version < EXCLUDED.version;

CREATE TABLE IF NOT EXISTS normalized_event_identities (
  record_id text PRIMARY KEY CHECK (record_id ~ '^[a-f0-9]{64}$'),
  event_sha256 text NOT NULL CHECK (event_sha256 ~ '^[a-f0-9]{64}$'),
  first_received_at timestamptz NOT NULL
);

CREATE SEQUENCE IF NOT EXISTS normalized_events_ingest_sequence_seq AS bigint;

CREATE TABLE IF NOT EXISTS normalized_events (
  record_id text NOT NULL CHECK (record_id ~ '^[a-f0-9]{64}$'),
  ingest_sequence bigint NOT NULL DEFAULT nextval('normalized_events_ingest_sequence_seq') CHECK (ingest_sequence > 0),
  event_sha256 text NOT NULL CHECK (event_sha256 ~ '^[a-f0-9]{64}$'),
  source text NOT NULL,
  kind text NOT NULL,
  occurred_at timestamptz NOT NULL,
  received_at timestamptz NOT NULL,
  source_version text NOT NULL,
  parser_version text NOT NULL,
  capture_session_id text,
  flow_id text,
  device_id text,
  confidence smallint NOT NULL CHECK (confidence BETWEEN 0 AND 100),
  source_ip inet,
  destination_ip inet,
  source_port integer CHECK (source_port BETWEEN 1 AND 65535),
  destination_port integer CHECK (destination_port BETWEEN 1 AND 65535),
  protocol text,
  service text,
  network_bytes bigint CHECK (network_bytes >= 0),
  dns_query text CHECK (dns_query IS NULL OR length(dns_query) BETWEEN 1 AND 253),
  dns_record_type text CHECK (dns_record_type IS NULL OR length(dns_record_type) BETWEEN 1 AND 32),
  dns_response_code text CHECK (dns_response_code IS NULL OR length(dns_response_code) BETWEEN 1 AND 32),
  dns_answer_count integer CHECK (dns_answer_count IS NULL OR dns_answer_count BETWEEN 0 AND 10000),
  detection_type text CHECK (detection_type IS NULL OR length(detection_type) BETWEEN 1 AND 64),
  detection_severity text CHECK (detection_severity IS NULL OR detection_severity IN ('WARNING','HIGH','CRITICAL')),
  detection_state text CHECK (detection_state IS NULL OR detection_state IN ('OPEN','RESOLVED')),
  detection_summary text CHECK (detection_summary IS NULL OR length(detection_summary) BETWEEN 1 AND 256),
  detection_scope text CHECK (detection_scope IS NULL OR length(detection_scope) BETWEEN 1 AND 256),
  tls_server_name text CHECK (tls_server_name IS NULL OR length(tls_server_name) BETWEEN 1 AND 253),
  tls_interception_state text CHECK (tls_interception_state IS NULL OR tls_interception_state IN ('INTERCEPTED','BYPASSED','FAILED')),
  tls_failure_reason text CHECK (tls_failure_reason IS NULL OR length(tls_failure_reason) BETWEEN 1 AND 96),
  tls_pinning_suspected boolean,
  tls_client_recent_success boolean,
  tls_bypass_activated boolean,
  tls_platform text CHECK (tls_platform IS NULL OR tls_platform IN ('android','android-tv','ios','tvos')),
  attribution_evidence jsonb CHECK (attribution_evidence IS NULL OR (jsonb_typeof(attribution_evidence) = 'object' AND octet_length(attribution_evidence::text) <= 2048)),
  payload jsonb NOT NULL,
  PRIMARY KEY (occurred_at, record_id)
) PARTITION BY RANGE (occurred_at);
ALTER TABLE normalized_events ADD COLUMN IF NOT EXISTS source_ip inet;
ALTER TABLE normalized_events ADD COLUMN IF NOT EXISTS destination_ip inet;
ALTER TABLE normalized_events ADD COLUMN IF NOT EXISTS source_port integer CHECK (source_port BETWEEN 1 AND 65535);
ALTER TABLE normalized_events ADD COLUMN IF NOT EXISTS destination_port integer CHECK (destination_port BETWEEN 1 AND 65535);
ALTER TABLE normalized_events ADD COLUMN IF NOT EXISTS protocol text;
ALTER TABLE normalized_events ADD COLUMN IF NOT EXISTS service text;
ALTER TABLE normalized_events ADD COLUMN IF NOT EXISTS network_bytes bigint CHECK (network_bytes >= 0);
ALTER TABLE normalized_events ADD COLUMN IF NOT EXISTS dns_query text CHECK (dns_query IS NULL OR length(dns_query) BETWEEN 1 AND 253);
ALTER TABLE normalized_events ADD COLUMN IF NOT EXISTS dns_record_type text CHECK (dns_record_type IS NULL OR length(dns_record_type) BETWEEN 1 AND 32);
ALTER TABLE normalized_events ADD COLUMN IF NOT EXISTS dns_response_code text CHECK (dns_response_code IS NULL OR length(dns_response_code) BETWEEN 1 AND 32);
ALTER TABLE normalized_events ADD COLUMN IF NOT EXISTS dns_answer_count integer CHECK (dns_answer_count IS NULL OR dns_answer_count BETWEEN 0 AND 10000);
ALTER TABLE normalized_events ADD COLUMN IF NOT EXISTS detection_type text CHECK (detection_type IS NULL OR length(detection_type) BETWEEN 1 AND 64);
ALTER TABLE normalized_events ADD COLUMN IF NOT EXISTS detection_severity text CHECK (detection_severity IS NULL OR detection_severity IN ('WARNING','HIGH','CRITICAL'));
ALTER TABLE normalized_events ADD COLUMN IF NOT EXISTS detection_state text CHECK (detection_state IS NULL OR detection_state IN ('OPEN','RESOLVED'));
ALTER TABLE normalized_events ADD COLUMN IF NOT EXISTS detection_summary text CHECK (detection_summary IS NULL OR length(detection_summary) BETWEEN 1 AND 256);
ALTER TABLE normalized_events ADD COLUMN IF NOT EXISTS detection_scope text CHECK (detection_scope IS NULL OR length(detection_scope) BETWEEN 1 AND 256);
ALTER TABLE normalized_events ADD COLUMN IF NOT EXISTS tls_server_name text CHECK (tls_server_name IS NULL OR length(tls_server_name) BETWEEN 1 AND 253);
ALTER TABLE normalized_events ADD COLUMN IF NOT EXISTS tls_interception_state text CHECK (tls_interception_state IS NULL OR tls_interception_state IN ('INTERCEPTED','BYPASSED','FAILED'));
ALTER TABLE normalized_events ADD COLUMN IF NOT EXISTS tls_failure_reason text CHECK (tls_failure_reason IS NULL OR length(tls_failure_reason) BETWEEN 1 AND 96);
ALTER TABLE normalized_events ADD COLUMN IF NOT EXISTS tls_pinning_suspected boolean;
ALTER TABLE normalized_events ADD COLUMN IF NOT EXISTS tls_client_recent_success boolean;
ALTER TABLE normalized_events ADD COLUMN IF NOT EXISTS tls_bypass_activated boolean;
ALTER TABLE normalized_events ADD COLUMN IF NOT EXISTS tls_platform text CHECK (tls_platform IS NULL OR tls_platform IN ('android','android-tv','ios','tvos'));
ALTER TABLE normalized_events ADD COLUMN IF NOT EXISTS attribution_evidence jsonb CHECK (attribution_evidence IS NULL OR (jsonb_typeof(attribution_evidence) = 'object' AND octet_length(attribution_evidence::text) <= 2048));
ALTER TABLE normalized_events ADD COLUMN IF NOT EXISTS ingest_sequence bigint DEFAULT nextval('normalized_events_ingest_sequence_seq');
UPDATE normalized_events SET ingest_sequence=nextval('normalized_events_ingest_sequence_seq') WHERE ingest_sequence IS NULL;
ALTER TABLE normalized_events ALTER COLUMN ingest_sequence SET NOT NULL;
ALTER SEQUENCE normalized_events_ingest_sequence_seq OWNED BY normalized_events.ingest_sequence;
CREATE INDEX IF NOT EXISTS normalized_events_record_id_idx ON normalized_events(record_id);
CREATE INDEX IF NOT EXISTS normalized_events_capture_time_idx ON normalized_events(capture_session_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS normalized_events_source_kind_time_idx ON normalized_events(source, kind, occurred_at DESC);
CREATE INDEX IF NOT EXISTS normalized_events_device_time_idx ON normalized_events(device_id, occurred_at DESC) WHERE device_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS normalized_events_received_record_idx ON normalized_events(received_at, record_id);
CREATE INDEX IF NOT EXISTS normalized_events_ingest_sequence_idx ON normalized_events(ingest_sequence);
ALTER TABLE normalized_events ADD COLUMN IF NOT EXISTS app_protocol text CHECK (app_protocol IS NULL OR app_protocol ~ '^[a-z0-9][a-z0-9-]{0,63}$');
ALTER TABLE normalized_events ADD COLUMN IF NOT EXISTS protocol_category text CHECK (protocol_category IS NULL OR protocol_category ~ '^[a-z][a-z-]{0,63}$');
ALTER TABLE normalized_events ADD COLUMN IF NOT EXISTS protocol_visibility text CHECK (protocol_visibility IS NULL OR protocol_visibility IN ('DECRYPTED','CLEARTEXT','ENCRYPTED_METADATA','OPAQUE'));
ALTER TABLE normalized_events ADD COLUMN IF NOT EXISTS protocol_evidence text CHECK (protocol_evidence IS NULL OR protocol_evidence IN ('ANALYZER','PORT_HEURISTIC','UNCLASSIFIED'));
ALTER TABLE normalized_events ADD COLUMN IF NOT EXISTS protocol_exotic boolean;
ALTER TABLE normalized_events ADD COLUMN IF NOT EXISTS http_method text CHECK (http_method IS NULL OR length(http_method) BETWEEN 1 AND 32);
ALTER TABLE normalized_events ADD COLUMN IF NOT EXISTS http_host text CHECK (http_host IS NULL OR length(http_host) BETWEEN 1 AND 253);
ALTER TABLE normalized_events ADD COLUMN IF NOT EXISTS http_path text CHECK (http_path IS NULL OR octet_length(http_path) BETWEEN 1 AND 256);
ALTER TABLE normalized_events ADD COLUMN IF NOT EXISTS http_status smallint CHECK (http_status IS NULL OR http_status BETWEEN 100 AND 599);
ALTER TABLE normalized_events ADD COLUMN IF NOT EXISTS alert_signature text CHECK (alert_signature IS NULL OR octet_length(alert_signature) BETWEEN 1 AND 256);
ALTER TABLE normalized_events ADD COLUMN IF NOT EXISTS alert_severity smallint CHECK (alert_severity IS NULL OR alert_severity BETWEEN 1 AND 4);
ALTER TABLE normalized_events ADD COLUMN IF NOT EXISTS alert_category text CHECK (alert_category IS NULL OR octet_length(alert_category) BETWEEN 1 AND 128);
ALTER TABLE normalized_events ADD COLUMN IF NOT EXISTS projection_version smallint;
CREATE INDEX IF NOT EXISTS normalized_events_app_protocol_time_idx ON normalized_events(app_protocol, occurred_at DESC) WHERE app_protocol IS NOT NULL;
CREATE INDEX IF NOT EXISTS normalized_events_source_ip_time_idx ON normalized_events(source_ip, occurred_at DESC) WHERE source_ip IS NOT NULL;
CREATE INDEX IF NOT EXISTS normalized_events_destination_ip_time_idx ON normalized_events(destination_ip, occurred_at DESC) WHERE destination_ip IS NOT NULL;
CREATE INDEX IF NOT EXISTS normalized_events_destination_port_time_idx ON normalized_events(destination_port, occurred_at DESC) WHERE destination_port IS NOT NULL;
CREATE INDEX IF NOT EXISTS normalized_events_dns_query_time_idx ON normalized_events(dns_query, occurred_at DESC) WHERE dns_query IS NOT NULL;
CREATE INDEX IF NOT EXISTS normalized_events_tls_server_name_time_idx ON normalized_events(tls_server_name, occurred_at DESC) WHERE tls_server_name IS NOT NULL;
CREATE INDEX IF NOT EXISTS normalized_events_projection_backfill_idx ON normalized_events(occurred_at DESC, record_id DESC) WHERE projection_version IS NULL;

CREATE TABLE IF NOT EXISTS normalized_event_deletion_tombstones (
  capture_session_id text PRIMARY KEY CHECK (capture_session_id ~ '^capture-[a-f0-9]{32}$'),
  operation_id text NOT NULL CHECK (operation_id ~ '^[A-Za-z0-9_-]{16,128}$'),
  actor_name text NOT NULL CHECK (length(actor_name) BETWEEN 1 AND 96),
  created_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS normalized_event_deletion_tombstones_created_idx ON normalized_event_deletion_tombstones(created_at, capture_session_id);

CREATE TABLE IF NOT EXISTS normalized_event_deletion_receipts (
  capture_session_id text PRIMARY KEY REFERENCES normalized_event_deletion_tombstones(capture_session_id),
  operation_id text NOT NULL CHECK (operation_id ~ '^[A-Za-z0-9_-]{16,128}$'),
  preview_sha256 text NOT NULL CHECK (preview_sha256 ~ '^[a-f0-9]{64}$'),
  deleted_event_rows bigint NOT NULL CHECK (deleted_event_rows >= 0),
  deleted_identity_rows bigint NOT NULL CHECK (deleted_identity_rows >= 0),
  deleted_event_logical_bytes bigint NOT NULL CHECK (deleted_event_logical_bytes >= 0),
  deleted_identity_logical_bytes bigint NOT NULL CHECK (deleted_identity_logical_bytes >= 0),
  completed_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS normalized_event_deletion_receipts_completed_idx ON normalized_event_deletion_receipts(completed_at, capture_session_id);

CREATE TABLE IF NOT EXISTS normalized_event_selection_tombstones (
  operation_id text PRIMARY KEY CHECK (operation_id ~ '^[A-Za-z0-9_-]{16,128}$'),
  actor_name text NOT NULL CHECK (length(actor_name) BETWEEN 1 AND 96),
  device_id text NOT NULL CHECK (device_id ~ '^device-[a-f0-9]{32}$'),
  start_at timestamptz NOT NULL,
  end_at timestamptz NOT NULL CHECK (end_at > start_at),
  selection_sha256 text NOT NULL CHECK (selection_sha256 ~ '^[a-f0-9]{64}$'),
  selection_json jsonb NOT NULL,
  query_snapshot_id text NOT NULL CHECK (query_snapshot_id ~ '^qsnap-[a-f0-9]{32}$'),
  query_snapshot_sha256 text NOT NULL CHECK (query_snapshot_sha256 ~ '^[a-f0-9]{64}$'),
  deletion_preview_sha256 text CHECK (deletion_preview_sha256 IS NULL OR deletion_preview_sha256 ~ '^[a-f0-9]{64}$'),
  created_at timestamptz NOT NULL
);
ALTER TABLE normalized_event_selection_tombstones
  ADD COLUMN IF NOT EXISTS deletion_preview_sha256 text
  CHECK (deletion_preview_sha256 IS NULL OR deletion_preview_sha256 ~ '^[a-f0-9]{64}$');
CREATE INDEX IF NOT EXISTS normalized_event_selection_tombstones_time_idx ON normalized_event_selection_tombstones(start_at, end_at, operation_id);
CREATE INDEX IF NOT EXISTS normalized_event_selection_tombstones_device_time_idx ON normalized_event_selection_tombstones(device_id, start_at, end_at);

CREATE TABLE IF NOT EXISTS normalized_event_selection_deletion_preparations (
  operation_id text PRIMARY KEY REFERENCES normalized_event_selection_tombstones(operation_id),
  preview_sha256 text NOT NULL CHECK (preview_sha256 ~ '^[a-f0-9]{64}$'),
  prepared_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS normalized_event_selection_deletion_preparations_time_idx ON normalized_event_selection_deletion_preparations(prepared_at, operation_id);

CREATE TABLE IF NOT EXISTS normalized_event_selection_deletion_receipts (
  operation_id text PRIMARY KEY REFERENCES normalized_event_selection_tombstones(operation_id),
  preview_sha256 text NOT NULL CHECK (preview_sha256 ~ '^[a-f0-9]{64}$'),
  deleted_event_rows bigint NOT NULL CHECK (deleted_event_rows >= 0),
  deleted_identity_rows bigint NOT NULL CHECK (deleted_identity_rows >= 0),
  deleted_event_logical_bytes bigint NOT NULL CHECK (deleted_event_logical_bytes >= 0),
  deleted_identity_logical_bytes bigint NOT NULL CHECK (deleted_identity_logical_bytes >= 0),
  completed_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS normalized_event_selection_deletion_receipts_completed_idx ON normalized_event_selection_deletion_receipts(completed_at, operation_id);

CREATE TABLE IF NOT EXISTS shakerproxy_event_query_snapshots (
  id text PRIMARY KEY CHECK (id ~ '^qsnap-[a-f0-9]{32}$'),
  actor_name text NOT NULL CHECK (length(actor_name) BETWEEN 1 AND 96),
  public_canonical_query text NOT NULL CHECK (octet_length(public_canonical_query) <= 2048),
  query_state jsonb NOT NULL,
  query_anchor timestamptz,
  watermark_received_at timestamptz NOT NULL,
  watermark_record_id text NOT NULL CHECK (watermark_record_id ~ '^[a-f0-9]{64}$'),
  watermark_ingest_sequence bigint NOT NULL CHECK (watermark_ingest_sequence >= 0),
  matched_count bigint NOT NULL CHECK (matched_count >= 0),
  count_relation text NOT NULL CHECK (count_relation IN ('eq', 'gte')),
  snapshot_sha256 text NOT NULL CHECK (snapshot_sha256 ~ '^[a-f0-9]{64}$'),
  policy_version text NOT NULL CHECK (policy_version = 'event-query-v1'),
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL CHECK (expires_at > created_at)
);
ALTER TABLE shakerproxy_event_query_snapshots ADD COLUMN IF NOT EXISTS watermark_ingest_sequence bigint NOT NULL DEFAULT 0 CHECK (watermark_ingest_sequence >= 0);
CREATE INDEX IF NOT EXISTS shakerproxy_event_query_snapshots_actor_expiry_idx ON shakerproxy_event_query_snapshots(actor_name, expires_at DESC, id);
CREATE INDEX IF NOT EXISTS shakerproxy_event_query_snapshots_expiry_idx ON shakerproxy_event_query_snapshots(expires_at);
`

type PostgresSink struct {
	DB         *sql.DB
	Attributor DeviceAttributor
}

func (s PostgresSink) Migrate(ctx context.Context) error {
	if s.DB == nil {
		return errors.New("PostgreSQL connection is required")
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fmt.Errorf("begin normalized ingestion migration: %w", err)
	}
	defer tx.Rollback()
	for _, statement := range strings.Split(postgresSchema, ";") {
		statement = strings.TrimSpace(statement)
		if statement == "" {
			continue
		}
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migrate normalized ingestion schema: %w", err)
		}
	}
	var version int
	if err := tx.QueryRowContext(ctx, "SELECT version FROM shakerproxy_schema_versions WHERE component = 'normalized_ingest'").Scan(&version); err != nil || version != postgresSchemaVersion {
		return errors.New("normalized ingestion database schema version is unsupported")
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit normalized ingestion migration: %w", err)
	}
	return nil
}

func (s PostgresSink) Ping(ctx context.Context) error {
	if s.DB == nil {
		return errors.New("PostgreSQL connection is required")
	}
	return s.DB.PingContext(ctx)
}

func (s PostgresSink) WriteBatch(ctx context.Context, batch []PendingRecord) error {
	if s.DB == nil || len(batch) == 0 || len(batch) > MaxDrainBatchRecords {
		return errors.New("PostgreSQL ingestion batch is invalid")
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("begin ingestion transaction: %w", err)
	}
	defer tx.Rollback()
	months := make(map[string]time.Time)
	captureSessionIDs := make(map[string]struct{})
	for _, pending := range batch {
		if !validRecordID(pending.RecordID) || envelopeRecordID(pending.Record.Envelope) != pending.RecordID || pending.Record.Envelope.Validate() != nil {
			if validRecordID(pending.RecordID) {
				return &RecordError{RecordIDs: []string{pending.RecordID}, Err: errors.New("PostgreSQL ingestion batch contains an invalid record")}
			}
			return errors.New("PostgreSQL ingestion batch contains an invalid record")
		}
		month := monthStart(pending.Record.Envelope.OccurredAt)
		months[month.Format("200601")] = month
		if pending.Record.Envelope.CaptureSessionID != "" {
			captureSessionIDs[pending.Record.Envelope.CaptureSessionID] = struct{}{}
		}
	}
	tombstoneKeys := make([]string, 0, len(captureSessionIDs))
	for captureSessionID := range captureSessionIDs {
		tombstoneKeys = append(tombstoneKeys, captureSessionID)
	}
	sort.Strings(tombstoneKeys)
	for _, captureSessionID := range tombstoneKeys {
		if err := lockCaptureIngestion(ctx, tx, captureSessionID); err != nil {
			return err
		}
		var tombstoned bool
		if err := tx.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM normalized_event_deletion_tombstones WHERE capture_session_id = $1)", captureSessionID).Scan(&tombstoned); err != nil {
			return fmt.Errorf("check normalized event deletion tombstone: %w", err)
		}
		if tombstoned {
			recordIDs := make([]string, 0)
			for _, pending := range batch {
				if pending.Record.Envelope.CaptureSessionID == captureSessionID {
					recordIDs = append(recordIDs, pending.RecordID)
				}
			}
			return &RecordError{RecordIDs: recordIDs, Purge: true, Err: fmt.Errorf("%w: %s", ErrCaptureTombstoned, captureSessionID)}
		}
	}
	if _, err := tx.ExecContext(ctx, "LOCK TABLE normalized_event_selection_tombstones IN SHARE MODE"); err != nil {
		return fmt.Errorf("lock normalized event selection tombstones: %w", err)
	}
	selectionTombstones, err := readEventSelectionTombstonesForBatch(ctx, tx, batch)
	if err != nil {
		return err
	}
	type attributedEvent struct {
		envelope Envelope
		evidence *AttributionEvidence
	}
	attributed := make([]attributedEvent, len(batch))
	for index, pending := range batch {
		envelope, evidence, err := AttributeAnalyzerEvent(pending.Record.Envelope, s.Attributor)
		if err != nil {
			return err
		}
		projection := NetworkProjection{}
		if envelope.DeviceID == "" {
			projection = ProjectNetworkFields(envelope)
		}
		for _, tombstone := range selectionTombstones {
			if !envelope.OccurredAt.Before(tombstone.Selection.StartAt) && envelope.OccurredAt.Before(tombstone.Selection.EndAt) && tombstone.Selection.matchesValidatedEnvelope(envelope, projection) {
				return &RecordError{RecordIDs: []string{pending.RecordID}, Purge: true, Err: fmt.Errorf("%w: %s", ErrEventSelectionTombstoned, tombstone.OperationID)}
			}
		}
		attributed[index] = attributedEvent{envelope: envelope, evidence: evidence}
	}
	keys := make([]string, 0, len(months))
	for key := range months {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		month := months[key]
		// Explicit UTC offsets keep partition bounds aligned with monthStart
		// regardless of the database session's TimeZone setting.
		statement := fmt.Sprintf("CREATE TABLE IF NOT EXISTS normalized_events_%s PARTITION OF normalized_events FOR VALUES FROM ('%s') TO ('%s')", key, month.Format("2006-01-02 15:04:05+00"), month.AddDate(0, 1, 0).Format("2006-01-02 15:04:05+00"))
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("create normalized event partition %s: %w", key, err)
		}
	}
	for index, pending := range batch {
		record := pending.Record
		var storedDigest string
		err := tx.QueryRowContext(ctx, `INSERT INTO normalized_event_identities(record_id, event_sha256, first_received_at)
VALUES ($1, $2, $3)
ON CONFLICT (record_id) DO UPDATE SET record_id = normalized_event_identities.record_id
RETURNING event_sha256`, pending.RecordID, record.EventSHA256, record.ReceivedAt).Scan(&storedDigest)
		if err != nil {
			return recordDataError(pending.RecordID, fmt.Errorf("bind normalized event identity: %w", err))
		}
		if storedDigest != record.EventSHA256 {
			return &RecordError{RecordIDs: []string{pending.RecordID}, Err: errors.New("normalized event identity conflicts with stored content")}
		}
		envelope := attributed[index].envelope
		attributionJSON := ""
		if attributed[index].evidence != nil {
			encoded, marshalErr := json.Marshal(attributed[index].evidence)
			if marshalErr != nil || len(encoded) > 2048 {
				return errors.New("encode normalized event attribution evidence")
			}
			attributionJSON = string(encoded)
		}
		projection := ProjectEvent(envelope)
		if err := linkSplitConnection(ctx, tx, &envelope, &projection); err != nil {
			return recordDataError(pending.RecordID, err)
		}
		columns := normalizedEventColumns(pending, envelope, projection, attributionJSON)
		if _, err := tx.ExecContext(ctx, columns.insertStatement(), columns.args()...); err != nil {
			return recordDataError(pending.RecordID, fmt.Errorf("insert normalized event: %w", err))
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit normalized ingestion batch: %w", err)
	}
	return nil
}

func (s PostgresSink) PutEventSelectionTombstone(ctx context.Context, tombstone EventSelectionTombstone) (EventSelectionTombstone, bool, error) {
	if s.DB == nil || tombstone.Validate() != nil {
		return EventSelectionTombstone{}, false, errors.New("PostgreSQL event selection tombstone request is invalid")
	}
	tombstone.CreatedAt = tombstone.CreatedAt.UTC().Truncate(time.Microsecond)
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return EventSelectionTombstone{}, false, fmt.Errorf("begin event selection tombstone transaction: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(hashtextextended('normalized-event-selection-tombstones', 7))"); err != nil {
		return EventSelectionTombstone{}, false, fmt.Errorf("lock event selection tombstone population: %w", err)
	}
	stored, exists, err := readDatabaseEventSelectionTombstone(ctx, tx, tombstone.OperationID)
	if err != nil {
		return EventSelectionTombstone{}, false, err
	}
	if exists {
		if !reflect.DeepEqual(stored, tombstone) {
			return EventSelectionTombstone{}, false, ErrEventSelectionConflict
		}
		if err := tx.Commit(); err != nil {
			return EventSelectionTombstone{}, false, fmt.Errorf("commit event selection tombstone replay: %w", err)
		}
		return stored, true, nil
	}
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM normalized_event_selection_tombstones").Scan(&count); err != nil {
		return EventSelectionTombstone{}, false, fmt.Errorf("count event selection tombstones: %w", err)
	}
	if count >= MaxEventSelectionTombstones {
		return EventSelectionTombstone{}, false, errors.New("event selection tombstone limit reached")
	}
	selectionJSON, err := json.Marshal(tombstone.Selection)
	if err != nil {
		return EventSelectionTombstone{}, false, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO normalized_event_selection_tombstones(
operation_id,actor_name,device_id,start_at,end_at,selection_sha256,selection_json,
query_snapshot_id,query_snapshot_sha256,deletion_preview_sha256,created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,NULLIF($10,''),$11)`, tombstone.OperationID, tombstone.Actor, tombstone.Selection.DeviceID, tombstone.Selection.StartAt, tombstone.Selection.EndAt, tombstone.SelectionSHA256, selectionJSON, tombstone.QuerySnapshotID, tombstone.QuerySnapshotSHA256, tombstone.DeletionPreviewSHA256, tombstone.CreatedAt); err != nil {
		return EventSelectionTombstone{}, false, fmt.Errorf("persist event selection tombstone: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return EventSelectionTombstone{}, false, fmt.Errorf("commit event selection tombstone: %w", err)
	}
	return tombstone, false, nil
}

func readDatabaseEventSelectionTombstone(ctx context.Context, tx *sql.Tx, operationID string) (EventSelectionTombstone, bool, error) {
	tombstone := EventSelectionTombstone{Schema: EventSelectionSchemaVersion}
	var selectionJSON []byte
	err := tx.QueryRowContext(ctx, `SELECT operation_id,actor_name,selection_sha256,selection_json,
query_snapshot_id,query_snapshot_sha256,COALESCE(deletion_preview_sha256,''),created_at
FROM normalized_event_selection_tombstones WHERE operation_id=$1`, operationID).Scan(&tombstone.OperationID, &tombstone.Actor, &tombstone.SelectionSHA256, &selectionJSON, &tombstone.QuerySnapshotID, &tombstone.QuerySnapshotSHA256, &tombstone.DeletionPreviewSHA256, &tombstone.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return EventSelectionTombstone{}, false, nil
	}
	if err != nil {
		return EventSelectionTombstone{}, false, fmt.Errorf("read event selection tombstone: %w", err)
	}
	if err := decodeStrictSnapshotJSON(selectionJSON, &tombstone.Selection); err != nil {
		return EventSelectionTombstone{}, false, errors.New("stored event selection is invalid")
	}
	tombstone.CreatedAt = tombstone.CreatedAt.UTC().Truncate(time.Microsecond)
	if err := tombstone.Validate(); err != nil {
		return EventSelectionTombstone{}, false, err
	}
	return tombstone, true, nil
}

func readEventSelectionTombstonesForBatch(ctx context.Context, tx *sql.Tx, batch []PendingRecord) ([]EventSelectionTombstone, error) {
	minimum, maximum := batch[0].Record.Envelope.OccurredAt, batch[0].Record.Envelope.OccurredAt
	for _, pending := range batch[1:] {
		if pending.Record.Envelope.OccurredAt.Before(minimum) {
			minimum = pending.Record.Envelope.OccurredAt
		}
		if pending.Record.Envelope.OccurredAt.After(maximum) {
			maximum = pending.Record.Envelope.OccurredAt
		}
	}
	rows, err := tx.QueryContext(ctx, `SELECT operation_id,actor_name,selection_sha256,selection_json,
query_snapshot_id,query_snapshot_sha256,COALESCE(deletion_preview_sha256,''),created_at
FROM normalized_event_selection_tombstones
WHERE start_at <= $1 AND end_at > $2
ORDER BY operation_id LIMIT $3`, maximum, minimum, MaxEventSelectionTombstones+1)
	if err != nil {
		return nil, fmt.Errorf("read event selection tombstones: %w", err)
	}
	defer rows.Close()
	result := make([]EventSelectionTombstone, 0)
	for rows.Next() {
		tombstone := EventSelectionTombstone{Schema: EventSelectionSchemaVersion}
		var selectionJSON []byte
		if err := rows.Scan(&tombstone.OperationID, &tombstone.Actor, &tombstone.SelectionSHA256, &selectionJSON, &tombstone.QuerySnapshotID, &tombstone.QuerySnapshotSHA256, &tombstone.DeletionPreviewSHA256, &tombstone.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan event selection tombstone: %w", err)
		}
		if err := decodeStrictSnapshotJSON(selectionJSON, &tombstone.Selection); err != nil {
			return nil, errors.New("stored event selection is invalid")
		}
		tombstone.CreatedAt = tombstone.CreatedAt.UTC().Truncate(time.Microsecond)
		if err := tombstone.Validate(); err != nil {
			return nil, err
		}
		result = append(result, tombstone)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate event selection tombstones: %w", err)
	}
	if len(result) > MaxEventSelectionTombstones {
		return nil, errors.New("event selection tombstone limit exceeded")
	}
	return result, nil
}

func (s PostgresSink) PutCaptureTombstone(ctx context.Context, tombstone CaptureTombstone) (CaptureTombstone, bool, error) {
	if s.DB == nil {
		return CaptureTombstone{}, false, errors.New("PostgreSQL connection is required")
	}
	if err := tombstone.Validate(); err != nil {
		return CaptureTombstone{}, false, err
	}
	tombstone.CreatedAt = tombstone.CreatedAt.UTC().Truncate(time.Microsecond)
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return CaptureTombstone{}, false, fmt.Errorf("begin capture tombstone transaction: %w", err)
	}
	defer tx.Rollback()
	if err := lockCaptureIngestion(ctx, tx, tombstone.CaptureSessionID); err != nil {
		return CaptureTombstone{}, false, err
	}
	stored := CaptureTombstone{Schema: CaptureTombstoneSchemaVersion}
	err = tx.QueryRowContext(ctx, `SELECT capture_session_id, operation_id, actor_name, created_at
FROM normalized_event_deletion_tombstones WHERE capture_session_id = $1`, tombstone.CaptureSessionID).Scan(&stored.CaptureSessionID, &stored.OperationID, &stored.Actor, &stored.CreatedAt)
	existing := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return CaptureTombstone{}, false, fmt.Errorf("read normalized event deletion tombstone: %w", err)
	}
	if !existing {
		if _, err := tx.ExecContext(ctx, `INSERT INTO normalized_event_deletion_tombstones(capture_session_id, operation_id, actor_name, created_at)
VALUES ($1,$2,$3,$4)`, tombstone.CaptureSessionID, tombstone.OperationID, tombstone.Actor, tombstone.CreatedAt); err != nil {
			return CaptureTombstone{}, false, fmt.Errorf("persist normalized event deletion tombstone: %w", err)
		}
		stored = tombstone
	}
	if err := stored.Validate(); err != nil {
		return CaptureTombstone{}, false, fmt.Errorf("stored normalized event deletion tombstone is invalid: %w", err)
	}
	stored.CreatedAt = stored.CreatedAt.UTC()
	if err := tx.Commit(); err != nil {
		return CaptureTombstone{}, false, fmt.Errorf("commit capture tombstone transaction: %w", err)
	}
	return stored, existing, nil
}

func (s PostgresSink) ReadCaptureEventFootprint(ctx context.Context, captureSessionID string) (CaptureEventDatabaseFootprint, error) {
	if s.DB == nil {
		return CaptureEventDatabaseFootprint{}, errors.New("PostgreSQL connection is required")
	}
	if !capture.ValidSessionID(captureSessionID) {
		return CaptureEventDatabaseFootprint{}, errors.New("capture session ID is invalid")
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return CaptureEventDatabaseFootprint{}, fmt.Errorf("begin capture event footprint transaction: %w", err)
	}
	defer tx.Rollback()
	if err := lockCaptureIngestion(ctx, tx, captureSessionID); err != nil {
		return CaptureEventDatabaseFootprint{}, err
	}
	footprint, err := readCaptureEventFootprintTx(ctx, tx, captureSessionID)
	if err != nil {
		return CaptureEventDatabaseFootprint{}, err
	}
	if err := tx.Commit(); err != nil {
		return CaptureEventDatabaseFootprint{}, fmt.Errorf("commit capture event footprint transaction: %w", err)
	}
	return footprint, nil
}

func lockCaptureIngestion(ctx context.Context, tx *sql.Tx, captureSessionID string) error {
	if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", captureSessionID); err != nil {
		return fmt.Errorf("lock capture ingestion boundary: %w", err)
	}
	return nil
}

// recordDataError marks a statement failure as specific to one record when
// PostgreSQL classifies it as a data exception (class 22) or an integrity
// constraint violation (class 23, including a row with no matching partition).
// Connection, locking, and other transient failures stay batch-level so the
// drain retries them instead of setting data aside.
func recordDataError(recordID string, err error) error {
	var stateErr interface{ SQLState() string }
	if errors.As(err, &stateErr) {
		if state := stateErr.SQLState(); strings.HasPrefix(state, "22") || strings.HasPrefix(state, "23") {
			return &RecordError{RecordIDs: []string{recordID}, Err: err}
		}
	}
	return err
}

func monthStart(value time.Time) time.Time {
	value = value.UTC()
	return time.Date(value.Year(), value.Month(), 1, 0, 0, 0, 0, time.UTC)
}
