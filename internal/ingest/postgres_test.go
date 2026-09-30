package ingest

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"shakerproxy.dev/shakerproxy/internal/inventory"
	"shakerproxy.dev/shakerproxy/internal/querylang"
)

func TestPostgresSchemaUsesPartitionedEventsAndGlobalIdentityLedger(t *testing.T) {
	for _, required := range []string{"PARTITION BY RANGE (occurred_at)", "normalized_event_identities", "PRIMARY KEY (occurred_at, record_id)", "payload jsonb", "capture_session_id", "source_ip inet", "destination_ip inet", "network_bytes bigint", "dns_query text", "dns_record_type text", "dns_response_code text", "tls_server_name text", "tls_interception_state text", "tls_pinning_suspected boolean", "tls_client_recent_success boolean", "clock_timestamp()", "normalized_event_deletion_tombstones", "normalized_event_deletion_receipts", "normalized_event_selection_tombstones", "normalized_event_selection_deletion_preparations", "normalized_event_selection_deletion_receipts", "selection_json jsonb", "deletion_preview_sha256", "operation_id"} {
		if !strings.Contains(postgresSchema, required) {
			t.Fatalf("PostgreSQL schema is missing %q", required)
		}
	}
}

func TestPostgresEventSelectionTombstoneBlocksInFlightReplay(t *testing.T) {
	databaseURL := os.Getenv("SHAKERPROXY_POSTGRES_TEST_URL")
	if databaseURL == "" {
		t.Skip("SHAKERPROXY_POSTGRES_TEST_URL is not set")
	}
	database, err := sql.Open("pgx", databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	sink := PostgresSink{DB: database}
	if err := sink.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(t.Context(), "TRUNCATE normalized_event_selection_deletion_receipts, normalized_event_selection_deletion_preparations, normalized_event_deletion_receipts, normalized_events, normalized_event_identities, normalized_event_deletion_tombstones, normalized_event_selection_tombstones"); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	spool := &Spool{Root: filepath.Join(t.TempDir(), "selection-db-spool"), MaxBytes: 8 << 20, ReserveBytes: 1}
	if _, err := spool.Accept([]byte(selectionEventJSON("selection-db-event-0001", selectionDeviceID, "10.77.0.111", now))); err != nil {
		t.Fatal(err)
	}
	inFlight, err := spool.PendingBatch(10)
	if err != nil || len(inFlight) != 1 {
		t.Fatalf("could not prepare in-flight batch: %#v err=%v", inFlight, err)
	}
	selection, err := CanonicalEventSelection(selectionDeviceID, now.Add(-time.Hour), now.Add(time.Hour), []EventSelectionAddress{{Address: "10.77.0.111", StartAt: now.Add(-time.Hour), EndAt: now.Add(time.Hour)}})
	if err != nil {
		t.Fatal(err)
	}
	selectionSHA, _ := selection.SHA256()
	tombstone := EventSelectionTombstone{Schema: 1, OperationID: "device-event-delete-database-0001", Actor: "admin", Selection: selection, SelectionSHA256: selectionSHA, QuerySnapshotID: "qsnap-0123456789abcdef0123456789abcdef", QuerySnapshotSHA256: strings.Repeat("d", 64), CreatedAt: now}
	stored, existing, err := sink.PutEventSelectionTombstone(t.Context(), tombstone)
	if err != nil || existing || stored.OperationID != tombstone.OperationID {
		t.Fatalf("database tombstone was not installed: %#v existing=%v err=%v", stored, existing, err)
	}
	if err := sink.WriteBatch(t.Context(), inFlight); !errors.Is(err, ErrEventSelectionTombstoned) {
		t.Fatalf("in-flight batch crossed the database barrier: %v", err)
	}
	var events, identities int
	if err := database.QueryRowContext(t.Context(), "SELECT count(*) FROM normalized_events").Scan(&events); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(t.Context(), "SELECT count(*) FROM normalized_event_identities").Scan(&identities); err != nil {
		t.Fatal(err)
	}
	if events != 0 || identities != 0 {
		t.Fatalf("blocked batch partially wrote rows: events=%d identities=%d", events, identities)
	}
	replayed, existing, err := sink.PutEventSelectionTombstone(t.Context(), tombstone)
	if err != nil || !existing || replayed.OperationID != tombstone.OperationID {
		t.Fatalf("database tombstone replay was not stable: %#v existing=%v err=%v", replayed, existing, err)
	}
	conflicting := tombstone
	conflicting.Actor = "another-admin"
	if _, _, err := sink.PutEventSelectionTombstone(t.Context(), conflicting); !errors.Is(err, ErrEventSelectionConflict) {
		t.Fatalf("database tombstone operation was rebound: %v", err)
	}
	unrelatedSpool := &Spool{Root: filepath.Join(t.TempDir(), "unrelated-db-spool"), MaxBytes: 8 << 20, ReserveBytes: 1}
	if _, err := unrelatedSpool.Accept([]byte(selectionEventJSON("selection-db-event-0002", "device-ffeeddccbbaa99887766554433221100", "10.77.0.222", now))); err != nil {
		t.Fatal(err)
	}
	unrelated, err := unrelatedSpool.PendingBatch(10)
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.WriteBatch(t.Context(), unrelated); err != nil {
		t.Fatalf("unrelated batch was blocked: %#v err=%v", unrelated, err)
	}
}

func TestPostgresEventSelectionDeletionIsSnapshotBoundAndVerified(t *testing.T) {
	databaseURL := os.Getenv("SHAKERPROXY_POSTGRES_TEST_URL")
	if databaseURL == "" {
		t.Skip("SHAKERPROXY_POSTGRES_TEST_URL is not set")
	}
	database, err := sql.Open("pgx", databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	sink := PostgresSink{DB: database}
	if err := sink.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(t.Context(), "TRUNCATE shakerproxy_event_query_snapshots, normalized_event_selection_deletion_receipts, normalized_event_selection_deletion_preparations, normalized_event_deletion_receipts, normalized_events, normalized_event_identities, normalized_event_deletion_tombstones, normalized_event_selection_tombstones"); err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 9, 1, 11, 0, 0, 0, time.UTC)
	end := start.Add(2 * time.Hour)
	spool := &Spool{Root: filepath.Join(t.TempDir(), "selection-delete-spool"), MaxBytes: 8 << 20, ReserveBytes: 1}
	events := []string{
		selectionEventJSON("selection-delete-event-0001", selectionDeviceID, "10.77.0.111", start.Add(15*time.Minute)),
		selectionEventJSON("selection-delete-event-0002", selectionDeviceID, "10.77.0.111", start.Add(30*time.Minute)),
		selectionEventJSON("selection-delete-event-0003", "device-ffeeddccbbaa99887766554433221100", "10.77.0.222", start.Add(45*time.Minute)),
	}
	for _, event := range events {
		if _, err := spool.Accept([]byte(event)); err != nil {
			t.Fatal(err)
		}
	}
	if result, err := DrainOnce(t.Context(), spool, sink, 10); err != nil || result.Committed != 3 {
		t.Fatalf("could not seed event selection deletion: %#v err=%v", result, err)
	}
	selection, err := CanonicalEventSelection(selectionDeviceID, start, end, []EventSelectionAddress{{Address: "10.77.0.111", StartAt: start, EndAt: end}})
	if err != nil {
		t.Fatal(err)
	}
	canonical := "device.id:" + selectionDeviceID + " AND time>=" + start.Format(time.RFC3339Nano) + " AND time<" + end.Format(time.RFC3339Nano)
	filter, err := querylang.Parse(canonical)
	if err != nil {
		t.Fatal(err)
	}
	query := RecentEventQuery{Limit: 1, Filter: filter}
	snapshot, err := sink.CreateEventQuerySnapshot(t.Context(), "admin", filter.Canonical, query, 10*time.Minute)
	if err != nil || snapshot.MatchedCount != 2 || snapshot.CountRelation != "eq" {
		t.Fatalf("could not freeze selection query: %#v err=%v", snapshot, err)
	}
	preview, err := sink.PreviewEventSelectionDeletion(t.Context(), "admin", selection, snapshot)
	if err != nil || preview.Database.EventRows != 2 || preview.Database.ExclusiveIdentityRows != 2 || preview.Database.EventLogicalBytes == 0 || preview.Database.IdentityLogicalBytes == 0 || preview.Database.TombstonePresent {
		t.Fatalf("selection deletion preview is inaccurate: %#v err=%v", preview, err)
	}
	secondSnapshot, err := sink.CreateEventQuerySnapshot(t.Context(), "admin", filter.Canonical, query, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	secondPreview, err := sink.PreviewEventSelectionDeletion(t.Context(), "admin", selection, secondSnapshot)
	if err != nil || secondPreview.PreviewSHA256 == preview.PreviewSHA256 {
		t.Fatalf("independent preview was not independently bound: %#v err=%v", secondPreview, err)
	}
	operationID := "device-event-delete-transaction-0001"
	if _, err := sink.DeleteEventSelection(t.Context(), preview, operationID); !errors.Is(err, ErrEventSelectionTombstoneMissing) {
		t.Fatalf("selection deletion without a barrier was accepted: %v", err)
	}
	selectionSHA, _ := selection.SHA256()
	tombstone := EventSelectionTombstone{Schema: 1, OperationID: operationID, Actor: "admin", Selection: selection, SelectionSHA256: selectionSHA, QuerySnapshotID: snapshot.ID, QuerySnapshotSHA256: snapshot.SnapshotSHA256, DeletionPreviewSHA256: strings.Repeat("e", 64), CreatedAt: time.Now().UTC()}
	stored, replayed, err := sink.PrepareEventSelectionDeletion(t.Context(), preview, tombstone)
	if err != nil || replayed || stored.OperationID != operationID || stored.DeletionPreviewSHA256 != tombstone.DeletionPreviewSHA256 {
		t.Fatalf("selection deletion barrier was not preview-bound: %#v replayed=%v err=%v", stored, replayed, err)
	}
	alternatePreview := preview
	alternatePreview.GeneratedAt = alternatePreview.GeneratedAt.Add(time.Microsecond)
	alternatePreview.PreviewSHA256, _ = hashEventSelectionDeletionPreview(alternatePreview)
	if err := alternatePreview.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := sink.PrepareEventSelectionDeletion(t.Context(), alternatePreview, tombstone); !errors.Is(err, ErrEventSelectionDeletionConflict) {
		t.Fatalf("prepared operation accepted different preview evidence: %v", err)
	}
	receipt, err := sink.DeleteEventSelection(t.Context(), preview, operationID)
	if err != nil || receipt.Replayed || receipt.DeletedEventRows != 2 || receipt.DeletedIdentityRows != 2 || !receipt.VerifiedAbsent || receipt.PreviewSHA256 != preview.PreviewSHA256 {
		t.Fatalf("selection rows were not transactionally deleted: %#v err=%v", receipt, err)
	}
	var targetEvents, unrelatedEvents, identities, receipts int
	if err := database.QueryRowContext(t.Context(), "SELECT count(*) FROM normalized_events WHERE device_id=$1", selectionDeviceID).Scan(&targetEvents); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(t.Context(), "SELECT count(*) FROM normalized_events WHERE device_id<>$1", selectionDeviceID).Scan(&unrelatedEvents); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(t.Context(), "SELECT count(*) FROM normalized_event_identities").Scan(&identities); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(t.Context(), "SELECT count(*) FROM normalized_event_selection_deletion_receipts").Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if targetEvents != 0 || unrelatedEvents != 1 || identities != 1 || receipts != 1 {
		t.Fatalf("selection deletion verification differs: target=%d unrelated=%d identities=%d receipts=%d", targetEvents, unrelatedEvents, identities, receipts)
	}
	if _, err := database.ExecContext(t.Context(), "DELETE FROM shakerproxy_event_query_snapshots WHERE id IN ($1,$2)", snapshot.ID, secondSnapshot.ID); err != nil {
		t.Fatal(err)
	}
	replayedReceipt, err := sink.DeleteEventSelection(t.Context(), preview, operationID)
	if err != nil || !replayedReceipt.Replayed || replayedReceipt.CompletedAt != receipt.CompletedAt {
		t.Fatalf("completed deletion did not replay after snapshot expiry/removal: %#v err=%v", replayedReceipt, err)
	}
	if _, err := sink.DeleteEventSelection(t.Context(), secondPreview, operationID); !errors.Is(err, ErrEventSelectionDeletionConflict) {
		t.Fatalf("operation replay accepted different preview evidence: %v", err)
	}
}

func TestPostgresEventSelectionPreviewRejectsRowsAfterSnapshotWatermark(t *testing.T) {
	databaseURL := os.Getenv("SHAKERPROXY_POSTGRES_TEST_URL")
	if databaseURL == "" {
		t.Skip("SHAKERPROXY_POSTGRES_TEST_URL is not set")
	}
	database, err := sql.Open("pgx", databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	sink := PostgresSink{DB: database}
	if err := sink.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(t.Context(), "TRUNCATE shakerproxy_event_query_snapshots, normalized_event_selection_deletion_receipts, normalized_event_selection_deletion_preparations, normalized_event_deletion_receipts, normalized_events, normalized_event_identities, normalized_event_deletion_tombstones, normalized_event_selection_tombstones"); err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 9, 1, 11, 0, 0, 0, time.UTC)
	end := start.Add(2 * time.Hour)
	seed := func(id string) {
		spool := &Spool{Root: filepath.Join(t.TempDir(), id), MaxBytes: 8 << 20, ReserveBytes: 1}
		if _, err := spool.Accept([]byte(selectionEventJSON(id, selectionDeviceID, "10.77.0.111", start.Add(time.Hour)))); err != nil {
			t.Fatal(err)
		}
		if result, err := DrainOnce(t.Context(), spool, sink, 10); err != nil || result.Committed != 1 {
			t.Fatalf("seed %s: %#v err=%v", id, result, err)
		}
	}
	seed("selection-watermark-event-0001")
	canonical := "device.id:" + selectionDeviceID + " AND time>=" + start.Format(time.RFC3339Nano) + " AND time<" + end.Format(time.RFC3339Nano)
	filter, _ := querylang.Parse(canonical)
	snapshot, err := sink.CreateEventQuerySnapshot(t.Context(), "admin", filter.Canonical, RecentEventQuery{Limit: 1, Filter: filter}, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	seed("selection-watermark-event-0002")
	selection, _ := CanonicalEventSelection(selectionDeviceID, start, end, nil)
	if _, err := sink.PreviewEventSelectionDeletion(t.Context(), "admin", selection, snapshot); !errors.Is(err, ErrEventSelectionDeletionPreviewStale) {
		t.Fatalf("post-watermark matching row did not stale selection preview: %v", err)
	}
}

func TestPostgresCaptureEventDeletionIsPreviewBoundAndIdempotent(t *testing.T) {
	databaseURL := os.Getenv("SHAKERPROXY_POSTGRES_TEST_URL")
	if databaseURL == "" {
		t.Skip("SHAKERPROXY_POSTGRES_TEST_URL is not set")
	}
	database, err := sql.Open("pgx", databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	sink := PostgresSink{DB: database}
	if err := sink.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(t.Context(), "TRUNCATE normalized_event_selection_deletion_receipts, normalized_event_selection_deletion_preparations, normalized_event_deletion_receipts, normalized_events, normalized_event_identities, normalized_event_deletion_tombstones, normalized_event_selection_tombstones"); err != nil {
		t.Fatal(err)
	}
	spool := &Spool{Root: filepath.Join(t.TempDir(), "spool"), MaxBytes: 8 << 20, ReserveBytes: 1}
	accepted, err := spool.Accept([]byte(validEvent))
	if err != nil {
		t.Fatal(err)
	}
	if result, err := DrainOnce(t.Context(), spool, sink, 10); err != nil || result.Committed != 1 {
		t.Fatalf("could not seed deletion target: %#v err=%v", result, err)
	}
	planner := CaptureEventDeletionPlanner{Spool: spool, Database: sink}
	preview, err := planner.Preview(t.Context(), "capture-0123456789abcdef0123456789abcdef")
	if err != nil || preview.Database.EventRows != 1 || preview.Database.ExclusiveIdentityRows != 1 {
		t.Fatalf("could not preview deletion target: %#v err=%v", preview, err)
	}
	if _, err := sink.DeleteCaptureEvents(t.Context(), preview); !errors.Is(err, ErrCaptureEventTombstoneMissing) {
		t.Fatalf("deletion without a barrier was accepted: %v", err)
	}
	service := CaptureEventDeletionService{Spool: spool, Database: sink}
	deleteRequest := CaptureEventDeletionRequest{Schema: CaptureEventDeletionOperationSchema, Preview: preview, OperationID: "capture-delete-operation-0001", Actor: "admin"}
	outcome, err := service.Delete(t.Context(), deleteRequest)
	receipt := outcome.Database
	if err != nil || outcome.Replayed || outcome.Tombstone.OperationID != deleteRequest.OperationID || outcome.Spool.Existing || receipt.Replayed || receipt.CaptureSessionID != preview.CaptureSessionID || receipt.OperationID != deleteRequest.OperationID || receipt.PreviewSHA256 != preview.PreviewSHA256 || receipt.DeletedEventRows != 1 || receipt.DeletedIdentityRows != 1 || receipt.DeletedEventLogicalBytes != preview.Database.EventLogicalBytes || receipt.DeletedIdentityLogicalBytes != preview.Database.IdentityLogicalBytes || !receipt.VerifiedAbsent {
		t.Fatalf("capture events were not transactionally coordinated: %#v err=%v", outcome, err)
	}
	var events, identities, receipts int
	if err := database.QueryRowContext(t.Context(), "SELECT count(*) FROM normalized_events WHERE record_id=$1", accepted.RecordID).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(t.Context(), "SELECT count(*) FROM normalized_event_identities WHERE record_id=$1", accepted.RecordID).Scan(&identities); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(t.Context(), "SELECT count(*) FROM normalized_event_deletion_receipts WHERE capture_session_id=$1", preview.CaptureSessionID).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if events != 0 || identities != 0 || receipts != 1 {
		t.Fatalf("deletion verification state is wrong: events=%d identities=%d receipts=%d", events, identities, receipts)
	}
	replayed, err := service.Delete(t.Context(), deleteRequest)
	if err != nil || !replayed.Replayed || !replayed.Spool.Existing || !replayed.Database.Replayed || replayed.CompletedAt != receipt.CompletedAt {
		t.Fatalf("deletion replay was not stable: %#v err=%v", replayed, err)
	}
	newPreview, err := planner.Preview(t.Context(), preview.CaptureSessionID)
	if err != nil {
		t.Fatal(err)
	}
	conflictingRequest := deleteRequest
	conflictingRequest.Preview = newPreview
	conflictingRequest.OperationID = "capture-delete-operation-0002"
	if _, err := service.Delete(t.Context(), conflictingRequest); !errors.Is(err, ErrCaptureEventDeletionConflict) {
		t.Fatalf("different preview replay did not conflict: %v", err)
	}

	staleCaptureID := "capture-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	staleSpool := &Spool{Root: filepath.Join(t.TempDir(), "stale-delete-spool"), MaxBytes: 8 << 20, ReserveBytes: 1}
	firstStaleEvent := strings.Replace(strings.Replace(validEvent, preview.CaptureSessionID, staleCaptureID, 1), "zeek-event-00000001", "zeek-event-stale-0001", 1)
	if _, err := staleSpool.Accept([]byte(firstStaleEvent)); err != nil {
		t.Fatal(err)
	}
	if result, err := DrainOnce(t.Context(), staleSpool, sink, 10); err != nil || result.Committed != 1 {
		t.Fatalf("could not seed stale deletion target: %#v err=%v", result, err)
	}
	stalePlanner := CaptureEventDeletionPlanner{Spool: staleSpool, Database: sink}
	stalePreview, err := stalePlanner.Preview(t.Context(), staleCaptureID)
	if err != nil {
		t.Fatal(err)
	}
	secondStaleEvent := strings.Replace(firstStaleEvent, "zeek-event-stale-0001", "zeek-event-stale-0002", 1)
	if _, err := staleSpool.Accept([]byte(secondStaleEvent)); err != nil {
		t.Fatal(err)
	}
	if result, err := DrainOnce(t.Context(), staleSpool, sink, 10); err != nil || result.Committed != 1 {
		t.Fatalf("could not change stale deletion target: %#v err=%v", result, err)
	}
	staleService := CaptureEventDeletionService{Spool: staleSpool, Database: sink}
	if _, err := staleService.Delete(t.Context(), CaptureEventDeletionRequest{Schema: CaptureEventDeletionOperationSchema, Preview: stalePreview, OperationID: "capture-delete-operation-stale", Actor: "admin"}); !errors.Is(err, ErrCaptureEventDeletionPreviewStale) {
		t.Fatalf("changed row population did not stale the preview: %v", err)
	}
	if err := database.QueryRowContext(t.Context(), "SELECT count(*) FROM normalized_events WHERE capture_session_id=$1", staleCaptureID).Scan(&events); err != nil || events != 2 {
		t.Fatalf("stale preview partially deleted rows: events=%d err=%v", events, err)
	}
	staleFootprint, err := staleSpool.ReadCaptureEventFootprint(staleCaptureID)
	if err != nil || staleFootprint.TombstonePresent {
		t.Fatalf("stale database preview installed a spool barrier: %#v err=%v", staleFootprint, err)
	}

	expiredCaptureID := "capture-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	expiredSpool := &Spool{Root: filepath.Join(t.TempDir(), "expired-delete-spool"), MaxBytes: 8 << 20, ReserveBytes: 1}
	expiredPlanner := CaptureEventDeletionPlanner{Spool: expiredSpool, Database: sink, Now: func() time.Time { return time.Now().UTC().Add(-DefaultEventDeletionPreviewTTL - time.Minute) }}
	expiredPreview, err := expiredPlanner.Preview(t.Context(), expiredCaptureID)
	if err != nil {
		t.Fatal(err)
	}
	expiredService := CaptureEventDeletionService{Spool: expiredSpool, Database: sink}
	if _, err := expiredService.Delete(t.Context(), CaptureEventDeletionRequest{Schema: CaptureEventDeletionOperationSchema, Preview: expiredPreview, OperationID: "capture-delete-operation-expired", Actor: "admin"}); !errors.Is(err, ErrCaptureEventDeletionPreviewExpired) {
		t.Fatalf("expired preview was accepted: %v", err)
	}

	spoolRaceCaptureID := "capture-cccccccccccccccccccccccccccccccc"
	spoolRace := &Spool{Root: filepath.Join(t.TempDir(), "spool-race-delete"), MaxBytes: 8 << 20, ReserveBytes: 1}
	firstSpoolEvent := strings.Replace(strings.Replace(validEvent, preview.CaptureSessionID, spoolRaceCaptureID, 1), "zeek-event-00000001", "zeek-event-spool-0001", 1)
	if _, err := spoolRace.Accept([]byte(firstSpoolEvent)); err != nil {
		t.Fatal(err)
	}
	spoolRaceService := CaptureEventDeletionService{Spool: spoolRace, Database: sink}
	spoolRacePreview, err := spoolRaceService.Preview(t.Context(), spoolRaceCaptureID)
	if err != nil || spoolRacePreview.Spool.PendingRecords != 1 || spoolRacePreview.Database.EventRows != 0 {
		t.Fatalf("could not preview spool race: %#v err=%v", spoolRacePreview, err)
	}
	if _, err := spoolRace.Accept([]byte(strings.Replace(firstSpoolEvent, "zeek-event-spool-0001", "zeek-event-spool-0002", 1))); err != nil {
		t.Fatal(err)
	}
	if _, err := spoolRaceService.Delete(t.Context(), CaptureEventDeletionRequest{Schema: CaptureEventDeletionOperationSchema, Preview: spoolRacePreview, OperationID: "capture-delete-operation-spool-race", Actor: "admin"}); !errors.Is(err, ErrCaptureEventDeletionPreviewStale) {
		t.Fatalf("changed spool population did not stale the preview: %v", err)
	}
	spoolRaceFootprint, err := spoolRace.ReadCaptureEventFootprint(spoolRaceCaptureID)
	if err != nil || spoolRaceFootprint.PendingRecords != 2 || spoolRaceFootprint.TombstonePresent {
		t.Fatalf("stale spool preview purged or blocked pending data: %#v err=%v", spoolRaceFootprint, err)
	}
	databaseRaceFootprint, err := sink.ReadCaptureEventFootprint(t.Context(), spoolRaceCaptureID)
	if err != nil || !databaseRaceFootprint.TombstonePresent {
		t.Fatalf("database barrier was not retained after safe spool failure: %#v err=%v", databaseRaceFootprint, err)
	}
}

func TestPostgresCaptureTombstoneBlocksDelayedBatchReplay(t *testing.T) {
	databaseURL := os.Getenv("SHAKERPROXY_POSTGRES_TEST_URL")
	if databaseURL == "" {
		t.Skip("SHAKERPROXY_POSTGRES_TEST_URL is not set")
	}
	database, err := sql.Open("pgx", databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	sink := PostgresSink{DB: database}
	if err := sink.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(t.Context(), "TRUNCATE normalized_event_selection_deletion_receipts, normalized_event_selection_deletion_preparations, normalized_event_deletion_receipts, normalized_events, normalized_event_identities, normalized_event_deletion_tombstones, normalized_event_selection_tombstones"); err != nil {
		t.Fatal(err)
	}
	spool := &Spool{Root: filepath.Join(t.TempDir(), "spool"), MaxBytes: 8 << 20, ReserveBytes: 1}
	accepted, err := spool.Accept([]byte(validEvent))
	if err != nil {
		t.Fatal(err)
	}
	delayedBatch, err := spool.PendingBatch(10)
	if err != nil || len(delayedBatch) != 1 {
		t.Fatalf("could not stage delayed analyzer batch: %#v err=%v", delayedBatch, err)
	}
	tombstone := CaptureTombstone{Schema: CaptureTombstoneSchemaVersion, CaptureSessionID: delayedBatch[0].Record.Envelope.CaptureSessionID, OperationID: "capture-delete-operation-0001", Actor: "admin", CreatedAt: time.Now().UTC().Truncate(time.Microsecond)}
	stored, existing, err := sink.PutCaptureTombstone(t.Context(), tombstone)
	if err != nil || existing || stored != tombstone {
		t.Fatalf("database tombstone was not created: %#v existing=%v err=%v", stored, existing, err)
	}
	if err := sink.WriteBatch(t.Context(), delayedBatch); !errors.Is(err, ErrCaptureTombstoned) {
		t.Fatalf("delayed database batch crossed tombstone: %v", err)
	}
	var events, identities int
	if err := database.QueryRowContext(t.Context(), "SELECT count(*) FROM normalized_events WHERE record_id=$1", accepted.RecordID).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(t.Context(), "SELECT count(*) FROM normalized_event_identities WHERE record_id=$1", accepted.RecordID).Scan(&identities); err != nil {
		t.Fatal(err)
	}
	if events != 0 || identities != 0 {
		t.Fatalf("tombstoned replay changed the event store: events=%d identities=%d", events, identities)
	}
	replayed, existing, err := sink.PutCaptureTombstone(t.Context(), CaptureTombstone{Schema: CaptureTombstoneSchemaVersion, CaptureSessionID: tombstone.CaptureSessionID, OperationID: "capture-delete-operation-0002", Actor: "another-admin", CreatedAt: tombstone.CreatedAt.Add(time.Hour)})
	if err != nil || !existing || replayed != tombstone {
		t.Fatalf("database tombstone replay did not preserve evidence: %#v existing=%v err=%v", replayed, existing, err)
	}
}

func TestPostgresSinkIntegration(t *testing.T) {
	databaseURL := os.Getenv("SHAKERPROXY_POSTGRES_TEST_URL")
	if databaseURL == "" {
		t.Skip("SHAKERPROXY_POSTGRES_TEST_URL is not set")
	}
	database, err := sql.Open("pgx", databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	deviceID := "device-0123456789abcdef0123456789abcdef"
	sink := PostgresSink{DB: database, Attributor: fakeDeviceAttributor{results: map[string]inventory.AddressAttribution{"10.77.0.111": testAddressAttribution(deviceID, "10.77.0.111")}}}
	if err := sink.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(t.Context(), "TRUNCATE shakerproxy_event_query_snapshots, normalized_event_selection_deletion_receipts, normalized_event_selection_deletion_preparations, normalized_event_deletion_receipts, normalized_events, normalized_event_identities, normalized_event_deletion_tombstones, normalized_event_selection_tombstones"); err != nil {
		t.Fatal(err)
	}
	spool := &Spool{Root: filepath.Join(t.TempDir(), "spool"), MaxBytes: 8 << 20, ReserveBytes: 1}
	attributedEvent := strings.Replace(validEvent, `"source":"ZEEK"`, `"source":"SURICATA"`, 1)
	accepted, err := spool.Accept([]byte(attributedEvent))
	if err != nil {
		t.Fatal(err)
	}
	if result, err := DrainOnce(t.Context(), spool, sink, 100); err != nil || result.Committed != 1 {
		t.Fatalf("first database drain failed: %#v, %v", result, err)
	}
	if _, err := spool.Accept([]byte(attributedEvent)); err != nil {
		t.Fatal(err)
	}
	if result, err := DrainOnce(t.Context(), spool, sink, 100); err != nil || result.Committed != 1 {
		t.Fatalf("idempotent replay failed: %#v, %v", result, err)
	}
	var events, identities int
	if err := database.QueryRowContext(t.Context(), "SELECT count(*) FROM normalized_events WHERE record_id = $1", accepted.RecordID).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(t.Context(), "SELECT count(*) FROM normalized_event_identities WHERE record_id = $1", accepted.RecordID).Scan(&identities); err != nil {
		t.Fatal(err)
	}
	if events != 1 || identities != 1 {
		t.Fatalf("replay duplicated database rows: events=%d identities=%d", events, identities)
	}
	var storedDeviceID, storedAttribution string
	var storedConfidence int
	if err := database.QueryRowContext(t.Context(), "SELECT device_id, confidence, attribution_evidence::text FROM normalized_events WHERE record_id = $1", accepted.RecordID).Scan(&storedDeviceID, &storedConfidence, &storedAttribution); err != nil || storedDeviceID != deviceID || storedConfidence != 70 || !strings.Contains(storedAttribution, `"endpoint": "SOURCE"`) {
		t.Fatalf("database event attribution was not persisted: device=%q confidence=%d evidence=%q err=%v", storedDeviceID, storedConfidence, storedAttribution, err)
	}
	secondEvent := strings.Replace(attributedEvent, `"event_id":"zeek-event-00000001"`, `"event_id":"zeek-event-00000002"`, 1)
	secondEvent = strings.Replace(secondEvent, `"occurred_at":"2026-09-01T12:00:00.123456789Z"`, `"occurred_at":"2026-09-01T12:01:00.123456789Z"`, 1)
	secondAccepted, err := spool.Accept([]byte(secondEvent))
	if err != nil {
		t.Fatal(err)
	}
	if result, err := DrainOnce(t.Context(), spool, sink, 100); err != nil || result.Committed != 1 {
		t.Fatalf("second database drain failed: %#v, %v", result, err)
	}
	page, err := sink.QueryRecent(t.Context(), RecentEventQuery{Limit: 1, Source: SourceSuricata, DeviceID: deviceID})
	if err != nil || len(page.Events) != 1 || page.Events[0].RecordID != secondAccepted.RecordID || page.Events[0].DeviceID != deviceID || page.Events[0].AttributionEvidence == nil || page.Events[0].AttributionEvidence.Endpoint != AttributionEndpointSource || page.NextCursor == "" {
		t.Fatalf("database recent-event query did not return the attributed record: %#v %v", page, err)
	}
	if page.Events[0].SourceIP != "10.77.0.111" || page.Events[0].Protocol != "tcp" {
		t.Fatalf("database query omitted the safe network projection: %#v", page.Events[0])
	}
	if page.Facets == nil || !page.Facets.Exact || page.Facets.MatchedCount != 2 || len(page.Facets.Fields) != 4 || page.Facets.Fields[0].Field != "source" || len(page.Facets.Fields[0].Values) != 1 || page.Facets.Fields[0].Values[0] != (EventFacetValue{Value: "SURICATA", Count: 2}) {
		t.Fatalf("database query did not compute exact initial facets: %#v", page.Facets)
	}
	boundaryTime, boundaryID, err := DecodeLiveEventCursor(page.LiveCursor)
	if err != nil || !boundaryTime.Equal(page.GeneratedAt) || boundaryID != strings.Repeat("0", 64) {
		t.Fatalf("recent query did not return its exact live boundary: %#v %v", page, err)
	}
	staleSpool := &Spool{Root: filepath.Join(t.TempDir(), "stale-spool"), MaxBytes: 8 << 20, ReserveBytes: 1, Now: func() time.Time { return time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC) }}
	lateEvent := strings.Replace(validEvent, `"event_id":"zeek-event-00000001"`, `"event_id":"zeek-event-00000003"`, 1)
	lateEvent = strings.Replace(lateEvent, `"occurred_at":"2026-09-01T12:00:00.123456789Z"`, `"occurred_at":"2026-09-01T12:02:00.123456789Z"`, 1)
	lateAccepted, err := staleSpool.Accept([]byte(lateEvent))
	if err != nil {
		t.Fatal(err)
	}
	if result, err := DrainOnce(t.Context(), staleSpool, sink, 100); err != nil || result.Committed != 1 {
		t.Fatalf("late database drain failed: %#v, %v", result, err)
	}
	footprint, err := sink.ReadCaptureEventFootprint(t.Context(), "capture-0123456789abcdef0123456789abcdef")
	if err != nil || footprint.EventRows != 3 || footprint.ExclusiveIdentityRows != 3 || footprint.EventLogicalBytes <= 0 || footprint.IdentityLogicalBytes <= 0 || footprint.MaxIngestSequence <= 0 || footprint.TombstonePresent {
		t.Fatalf("capture event footprint was not exact: %#v err=%v", footprint, err)
	}
	lateBatch, err := sink.QueryAfter(t.Context(), LiveEventQuery{RecentEventQuery: RecentEventQuery{Limit: 10, Source: SourceZeek}, AfterReceivedAt: boundaryTime, AfterRecordID: boundaryID})
	if err != nil || len(lateBatch.Events) != 1 || lateBatch.Events[0].RecordID != lateAccepted.RecordID || !lateBatch.Events[0].ReceivedAt.After(boundaryTime) {
		t.Fatalf("stale spool receipt time crossed the live boundary: %#v %v", lateBatch, err)
	}
	filter, err := querylang.Parse("source:SURICATA AND protocol:tcp AND src.ip:10.77.0.111 AND confidence:70")
	if err != nil {
		t.Fatal(err)
	}
	filtered, err := sink.QueryRecent(t.Context(), RecentEventQuery{Limit: 5, Filter: filter})
	if err != nil || len(filtered.Events) != 2 || filtered.CanonicalQuery != filter.Canonical {
		t.Fatalf("typed PostgreSQL filter did not return the expected records: %#v %v", filtered, err)
	}
	nameFilter, err := querylang.Parse(`device.name:"Bench Camera" AND source:SURICATA`)
	if err != nil {
		t.Fatal(err)
	}
	nameFiltered, err := sink.QueryRecent(t.Context(), RecentEventQuery{Limit: 5, Filter: nameFilter, DeviceNameResolutions: map[string][]string{"Bench Camera": {deviceID}}})
	if err != nil || len(nameFiltered.Events) != 2 || nameFiltered.CanonicalQuery != nameFilter.Canonical {
		t.Fatalf("resolved device-name PostgreSQL filter did not preserve boolean semantics: %#v %v", nameFiltered, err)
	}
	tagFilter, err := querylang.Parse(`device.tag:camera AND source:SURICATA`)
	if err != nil {
		t.Fatal(err)
	}
	tagFiltered, err := sink.QueryRecent(t.Context(), RecentEventQuery{Limit: 5, Filter: tagFilter, DeviceTagResolutions: map[string][]string{"camera": {deviceID}}})
	if err != nil || len(tagFiltered.Events) != 2 || tagFiltered.CanonicalQuery != tagFilter.Canonical {
		t.Fatalf("resolved device-tag PostgreSQL filter did not preserve boolean semantics: %#v %v", tagFiltered, err)
	}
	timeFilter, err := querylang.Parse(`time:last_1m`)
	if err != nil {
		t.Fatal(err)
	}
	timeAnchor := time.Date(2026, 9, 1, 12, 1, 30, 123456789, time.UTC)
	timeFiltered, err := sink.QueryRecent(t.Context(), RecentEventQuery{Limit: 5, Filter: timeFilter, TimeAnchor: timeAnchor})
	if err != nil || len(timeFiltered.Events) != 1 || timeFiltered.Events[0].RecordID != secondAccepted.RecordID || !timeFiltered.QueryAnchor.Equal(timeAnchor) {
		t.Fatalf("frozen relative-time query crossed its window: %#v %v", timeFiltered, err)
	}
	cursor, err := decodeRecentEventCursor(page.NextCursor)
	if err != nil || cursor.RecordID != secondAccepted.RecordID {
		t.Fatalf("database query cursor was invalid: %q %v", page.NextCursor, err)
	}
	older, err := sink.QueryRecent(t.Context(), RecentEventQuery{Limit: 1, Source: SourceSuricata, DeviceID: deviceID, BeforeOccurredAt: cursor.BeforeOccurredAt, BeforeRecordID: cursor.RecordID})
	if err != nil || len(older.Events) != 1 || older.Events[0].RecordID != accepted.RecordID || older.Facets != nil {
		t.Fatalf("database cursor did not return the next event: %#v %v", older, err)
	}
	live, err := sink.QueryAfter(t.Context(), LiveEventQuery{RecentEventQuery: RecentEventQuery{Limit: 10, Source: SourceSuricata, DeviceID: deviceID}, AfterReceivedAt: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), AfterRecordID: strings.Repeat("0", 64)})
	if err != nil || len(live.Events) != 2 || live.Events[0].ReceivedAt.After(live.Events[1].ReceivedAt) || live.NextCursor == "" {
		t.Fatalf("database live query was not bounded and ordered: %#v %v", live, err)
	}
	liveAfter, liveID, err := DecodeLiveEventCursor(live.NextCursor)
	if err != nil || liveID != live.Events[len(live.Events)-1].RecordID {
		t.Fatalf("database live cursor was invalid: %q %v", live.NextCursor, err)
	}
	resumed, err := sink.QueryAfter(t.Context(), LiveEventQuery{RecentEventQuery: RecentEventQuery{Limit: 10, Source: SourceSuricata, DeviceID: deviceID}, AfterReceivedAt: liveAfter, AfterRecordID: liveID})
	if err != nil || len(resumed.Events) != 0 || resumed.NextCursor != live.NextCursor {
		t.Fatalf("database live query did not resume exactly: %#v %v", resumed, err)
	}
	conflict := strings.Replace(attributedEvent, `"proto":"tcp"`, `"proto":"udp"`, 1)
	if _, err := spool.Accept([]byte(conflict)); err != nil {
		t.Fatal(err)
	}
	conflictResult, err := DrainOnce(t.Context(), spool, sink, 100)
	if err != nil || conflictResult.Committed != 0 || conflictResult.Rejected != 1 {
		t.Fatalf("database identity conflict was not set aside: %#v, %v", conflictResult, err)
	}
	pending, err := spool.PendingBatch(100)
	if err != nil || len(pending) != 0 {
		t.Fatalf("conflicting record kept blocking the pending queue: %#v, %v", pending, err)
	}
	if rejected, err := os.ReadDir(filepath.Join(spool.Root, "rejected")); err != nil || len(rejected) != 1 {
		t.Fatalf("conflicting record was not retained for operator handling: %v, %v", rejected, err)
	}
	if _, err := database.ExecContext(t.Context(), `INSERT INTO normalized_events(
record_id,event_sha256,source,kind,occurred_at,received_at,source_version,parser_version,confidence,protocol,payload)
SELECT lpad(to_hex(3000000 + value),64,'0'),lpad(to_hex(4000000 + value),64,'0'),'HOST','facet.sample.test',
       '2026-09-10T12:00:00Z'::timestamptz + value * interval '1 microsecond',
       '2026-09-10T12:00:00Z'::timestamptz + value * interval '1 microsecond',
       'facet-test','facet-test',80,CASE WHEN value % 2 = 0 THEN 'tcp' ELSE 'udp' END,'{}'::jsonb
FROM generate_series(1,10001) AS value
ON CONFLICT (occurred_at,record_id) DO NOTHING`); err != nil {
		t.Fatal(err)
	}
	sampleFilter, err := querylang.Parse(`kind:facet.sample.test`)
	if err != nil {
		t.Fatal(err)
	}
	sampled, err := sink.QueryRecent(t.Context(), RecentEventQuery{Limit: 1, Filter: sampleFilter})
	if err != nil || sampled.Facets == nil || sampled.Facets.Exact || sampled.Facets.MatchedCount != MaxEventFacetInput || sampled.Facets.CountRelation != "gte" || sampled.Facets.Basis != "newest_sample" || len(sampled.Facets.Fields[2].Values) != 2 || sampled.Facets.Fields[2].Values[0].Count != 5000 || sampled.Facets.Fields[2].Values[1].Count != 5000 {
		t.Fatalf("large facet population was not explicitly sampled: %#v %v", sampled.Facets, err)
	}
	if _, err := database.ExecContext(t.Context(), "DELETE FROM normalized_events WHERE kind='snapshot.freeze.test'"); err != nil {
		t.Fatal(err)
	}
	firstSnapshotRecord := strings.Repeat("c", 64)
	if _, err := database.ExecContext(t.Context(), `INSERT INTO normalized_events(record_id,event_sha256,source,kind,occurred_at,received_at,source_version,parser_version,confidence,payload)
VALUES ($1,$1,'HOST','snapshot.freeze.test','2026-09-01T15:00:00Z',clock_timestamp(),'snapshot-test','snapshot-test',80,'{}'::jsonb)`, firstSnapshotRecord); err != nil {
		t.Fatal(err)
	}
	snapshotFilter, err := querylang.Parse("kind:snapshot.freeze.test")
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := sink.CreateEventQuerySnapshot(t.Context(), "admin", snapshotFilter.Canonical, RecentEventQuery{Limit: 1, Filter: snapshotFilter}, DefaultQuerySnapshotTTL)
	if err != nil || snapshot.MatchedCount != 1 || snapshot.CountRelation != "eq" || snapshot.SnapshotSHA256 == "" {
		t.Fatalf("database query snapshot was not frozen: %#v %v", snapshot, err)
	}
	secondSnapshotRecord := strings.Repeat("d", 64)
	if _, err := database.ExecContext(t.Context(), `INSERT INTO normalized_events(record_id,event_sha256,source,kind,occurred_at,received_at,source_version,parser_version,confidence,payload)
VALUES ($1,$1,'HOST','snapshot.freeze.test','2026-09-01T15:01:00Z',clock_timestamp(),'snapshot-test','snapshot-test',80,'{}'::jsonb)`, secondSnapshotRecord); err != nil {
		t.Fatal(err)
	}
	resolved, err := sink.ResolveEventQuerySnapshot(t.Context(), "admin", snapshot.ID)
	if err != nil || resolved.Snapshot.SnapshotSHA256 != snapshot.SnapshotSHA256 {
		t.Fatalf("database query snapshot did not resolve: %#v %v", resolved, err)
	}
	clauses, args, err := buildEventWhere(resolved.Query, true)
	if err != nil {
		t.Fatal(err)
	}
	args = append(args, resolved.Snapshot.DatasetWatermark.IngestSequence)
	clauses = append(clauses, fmt.Sprintf("ingest_sequence <= $%d", len(args)))
	var frozenCount int
	if err := database.QueryRowContext(t.Context(), "SELECT count(*) FROM normalized_events WHERE "+strings.Join(clauses, " AND "), args...).Scan(&frozenCount); err != nil || frozenCount != 1 {
		t.Fatalf("post-snapshot ingestion changed the frozen population: count=%d err=%v", frozenCount, err)
	}
}

func TestMonthStartUsesUTCPartitionBoundaries(t *testing.T) {
	input := time.Date(2026, 9, 30, 23, 0, 0, 0, time.FixedZone("west", -5*60*60))
	expected := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	if actual := monthStart(input); !actual.Equal(expected) {
		t.Fatalf("unexpected partition boundary: %s", actual)
	}
}

func TestPostgresSinkRejectsMissingConnectionAndEmptyBatch(t *testing.T) {
	sink := PostgresSink{}
	if err := sink.Migrate(t.Context()); err == nil {
		t.Fatal("migration accepted a missing database")
	}
	if err := sink.WriteBatch(t.Context(), nil); err == nil {
		t.Fatal("sink accepted an empty batch")
	}
}
