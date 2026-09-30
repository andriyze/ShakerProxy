package capture

import (
	"context"
	"testing"
	"time"
)

func TestEvidenceHoldBlocksDeletionRetentionAndReleasesByOwningCase(t *testing.T) {
	manager, session, _ := finalizedDeletionManager(t, false)
	sessionID := session.ID
	request := SetHoldRequest{SessionID: sessionID, CaseID: "case-0123456789abcdef0123456789abcdef", Active: true, ExpectedRevision: 0, Actor: "admin", Reason: "incident evidence", IdempotencyKey: "hold-request-0001"}
	hold, err := manager.SetEvidenceHold(request)
	if err != nil {
		t.Fatal(err)
	}
	if !hold.Active || hold.Revision != 1 {
		t.Fatalf("hold not active: %#v", hold)
	}
	preview, err := manager.PreviewDeletion(context.Background(), sessionID)
	if err != nil || !preview.RetentionLock {
		t.Fatalf("hold missing from deletion preview: %#v %v", preview, err)
	}
	_, err = manager.Delete(context.Background(), DeleteRequest{SessionID: sessionID, PreviewSHA256: preview.PreviewSHA256, PreviewExpiresAt: preview.ExpiresAt, Confirmation: sessionID, Administrator: "admin", IdempotencyKey: "delete-held-0001"})
	if err == nil {
		t.Fatal("held capture was deleted")
	}
	retention, err := manager.PreviewRetention(context.Background(), RetentionPolicyInput{MaxPCAPBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(retention.BlockedByRetentionLock) != 1 || len(retention.Selected) != 0 {
		t.Fatalf("hold did not block retention: %#v", retention)
	}
	wrong := request
	wrong.Active = false
	wrong.ExpectedRevision = 1
	wrong.CaseID = "case-ffffffffffffffffffffffffffffffff"
	wrong.IdempotencyKey = "hold-request-0002"
	if _, err := manager.SetEvidenceHold(wrong); err == nil {
		t.Fatal("different case released hold")
	}
	release := request
	release.Active = false
	release.ExpectedRevision = 1
	release.Reason = "custodian release"
	release.IdempotencyKey = "hold-request-0003"
	hold, err = manager.SetEvidenceHold(release)
	if err != nil {
		t.Fatal(err)
	}
	if hold.Active || hold.Revision != 2 {
		t.Fatalf("hold not released: %#v", hold)
	}
	preview, err = manager.PreviewDeletion(context.Background(), sessionID)
	if err != nil || preview.RetentionLock {
		t.Fatalf("released hold still blocks deletion: %#v %v", preview, err)
	}
}

func TestEvidenceHoldIdempotencyAndHistorySurviveReload(t *testing.T) {
	manager, session, _ := finalizedDeletionManager(t, false)
	sessionID := session.ID
	manager.Now = func() time.Time { return time.Date(2026, 9, 2, 6, 0, 0, 0, time.UTC) }
	request := SetHoldRequest{SessionID: sessionID, CaseID: "case-0123456789abcdef0123456789abcdef", Active: true, ExpectedRevision: 0, Actor: "admin", Reason: "incident evidence", IdempotencyKey: "hold-request-0004"}
	first, err := manager.SetEvidenceHold(request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := manager.SetEvidenceHold(request)
	if err != nil || second.Revision != first.Revision || len(second.History) != 1 {
		t.Fatalf("hold replay changed state: %#v %v", second, err)
	}
	reloaded, err := manager.Store.ReadEvidenceHold(sessionID)
	if err != nil || reloaded.Validate() != nil || reloaded.History[0].RequestSHA256 == "" {
		t.Fatalf("invalid durable hold: %#v %v", reloaded, err)
	}
	release := request
	release.Active = false
	release.ExpectedRevision = 1
	release.Reason = "release"
	release.IdempotencyKey = "hold-request-0005"
	if _, err := manager.SetEvidenceHold(release); err != nil {
		t.Fatal(err)
	}
	replayedApply, err := manager.SetEvidenceHold(request)
	if err != nil || !replayedApply.Active || replayedApply.Revision != 1 || len(replayedApply.History) != 1 {
		t.Fatalf("historical replay did not return its stable outcome: %#v %v", replayedApply, err)
	}
	current, err := manager.Store.ReadEvidenceHold(sessionID)
	if err != nil || current.Active || current.Revision != 2 {
		t.Fatalf("historical replay changed current state: %#v %v", current, err)
	}
}
