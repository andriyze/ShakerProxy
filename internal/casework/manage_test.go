package casework

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testQueryPin(now time.Time) *QuerySnapshotPin {
	return &QuerySnapshotPin{CanonicalQuery: "device.name:TV", MatchedCount: 12, CountRelation: "eq", SnapshotCreatedAt: now, SnapshotSHA256: strings.Repeat("b", 64), DatasetWatermark: QueryWatermark{IngestSequence: 7, ReceivedAt: now, RecordID: strings.Repeat("a", 64)}}
}

func TestCaseUpdateRenamesEditsMultilineDescriptionAndIsIdempotent(t *testing.T) {
	now := time.Date(2026, 9, 2, 6, 0, 0, 0, time.UTC)
	store := &Store{Path: filepath.Join(t.TempDir(), "cases.json"), Now: func() time.Time { return now }}
	item, err := store.Create("Camera", "First line\r\nSecond line", "admin", "create")
	if err != nil || item.Description != "First line\nSecond line" {
		t.Fatalf("multi-line description was rejected or not normalized: %#v %v", item, err)
	}
	name, description := "Camera firmware 2", "Steps:\n\t1. boot\n\t2. update"
	updated, changed, err := store.Update(item.ID, item.Revision, Update{Name: &name, Description: &description}, "admin", "")
	if err != nil || !changed || updated.Name != name || updated.Description != description || updated.Revision != 2 || updated.Timeline[1].Action != "CASE_UPDATED" || updated.Timeline[1].Reason != "Case renamed and description edited" {
		t.Fatalf("update = %#v changed=%v err=%v", updated, changed, err)
	}
	same, changed, err := store.Update(item.ID, 0, Update{Name: &name}, "admin", "")
	if err != nil || changed || same.Revision != 2 {
		t.Fatalf("no-op update changed the case: %#v %v %v", same, changed, err)
	}
	other := "Other"
	if _, _, err := store.Update(item.ID, 1, Update{Name: &other}, "admin", ""); !errors.Is(err, ErrRevisionChanged) {
		t.Fatalf("stale update returned %v", err)
	}
	bell := "ring\a"
	if _, _, err := store.Update(item.ID, 0, Update{Description: &bell}, "admin", ""); err == nil {
		t.Fatal("control characters were accepted in a description")
	}
	multiline := "Name\nwith newline"
	if _, _, err := store.Update(item.ID, 0, Update{Name: &multiline}, "admin", ""); err == nil {
		t.Fatal("a case name with a newline was accepted")
	}
	reloaded, err := store.Get(item.ID)
	if err != nil || reloaded.Validate() != nil {
		t.Fatalf("updated case does not validate: %v", err)
	}
}

func TestQuerySnapshotEvidenceMustPinQueryAndWatermark(t *testing.T) {
	now := time.Date(2026, 9, 2, 6, 0, 0, 0, time.UTC)
	store := &Store{Path: filepath.Join(t.TempDir(), "cases.json"), Now: func() time.Time { return now }}
	item, err := store.Create("Queries", "", "admin", "create")
	if err != nil {
		t.Fatal(err)
	}
	snapshotID := "qsnap-0123456789abcdef0123456789abcdef"
	if _, err := store.AddEvidence(item.ID, 0, EvidenceQuerySnapshot, snapshotID, "Query", "admin", "attach"); err == nil {
		t.Fatal("query snapshot evidence without a pinned query was accepted")
	}
	if _, err := store.AttachEvidence(item.ID, 0, EvidenceInput{Kind: EvidenceCapture, ArtifactID: testCaptureID, Label: "Capture", Query: testQueryPin(now)}, "admin", "attach"); err == nil {
		t.Fatal("a capture carrying a query pin was accepted")
	}
	attached, err := store.AttachEvidence(item.ID, 0, EvidenceInput{Kind: EvidenceQuerySnapshot, ArtifactID: snapshotID, Label: "TV traffic", Query: testQueryPin(now)}, "admin", "attach")
	if err != nil || attached.Evidence[0].Query == nil || attached.Evidence[0].Query.DatasetWatermark.IngestSequence != 7 {
		t.Fatalf("pinned query evidence = %#v err=%v", attached, err)
	}
	reloaded, err := store.Get(item.ID)
	if err != nil || reloaded.Evidence[0].Query.CanonicalQuery != "device.name:TV" {
		t.Fatalf("pinned query did not persist: %#v %v", reloaded, err)
	}
}

func TestEvidenceChangesPreserveHoldSemantics(t *testing.T) {
	now := time.Date(2026, 9, 2, 6, 0, 0, 0, time.UTC)
	store := &Store{Path: filepath.Join(t.TempDir(), "cases.json"), Now: func() time.Time { return now }}
	item, err := store.Create("Held", "", "admin", "create")
	if err != nil {
		t.Fatal(err)
	}
	item, err = store.AddEvidence(item.ID, item.Revision, EvidenceCapture, testCaptureID, "Capture", "admin", "attach")
	if err != nil {
		t.Fatal(err)
	}
	item, err = store.RecordHold(item.ID, item.Revision, true, "preserve", "admin", "case-hold-operation-7001", []HoldResult{{EvidenceID: item.Evidence[0].ID, ArtifactID: testCaptureID, Protected: true, Revision: 1}})
	if err != nil || item.Hold.State != HoldActive {
		t.Fatalf("hold = %#v %v", item.Hold, err)
	}
	// Non-capture evidence can be added under an active hold without touching it.
	item, err = store.AddEvidence(item.ID, item.Revision, EvidenceCaptureExport, "export-0123456789abcdef0123456789abcdef", "Export", "admin", "attach export")
	if err != nil || item.Hold.State != HoldActive || len(item.Hold.Results) != 1 {
		t.Fatalf("export under hold changed it: %#v %v", item.Hold, err)
	}
	// A new capture under an active hold is recorded as not yet protected.
	second := "capture-ffffffffffffffffffffffffffffffff"
	item, err = store.AddEvidence(item.ID, item.Revision, EvidenceCapture, second, "Second capture", "admin", "attach second")
	if err != nil || item.Hold.State != HoldPartial || len(item.Hold.Results) != 2 || item.Hold.Results[1].Protected || !strings.Contains(item.Hold.Results[1].Failure, "apply the hold again") || item.Validate() != nil {
		t.Fatalf("capture under hold = %#v %v", item.Hold, err)
	}
	// The protected capture cannot be removed; the unprotected one can.
	if _, err := store.RemoveEvidence(item.ID, item.Evidence[0].ID, 0, "admin", ""); !errors.Is(err, ErrHoldActive) {
		t.Fatalf("removing a protected capture returned %v", err)
	}
	item, err = store.RemoveEvidence(item.ID, item.Evidence[2].ID, item.Revision, "admin", "")
	if err != nil || item.Hold.State != HoldActive || len(item.Hold.Results) != 1 || len(item.Evidence) != 2 || item.Timeline[len(item.Timeline)-1].Action != "EVIDENCE_REMOVED" {
		t.Fatalf("removing the unprotected capture = %#v %v", item, err)
	}
	if _, err := store.Delete(item.ID, 0); !errors.Is(err, ErrHoldActive) {
		t.Fatalf("deleting a held case returned %v", err)
	}
	item, err = store.RecordHold(item.ID, item.Revision, false, "release", "admin", "case-hold-operation-7002", []HoldResult{{EvidenceID: item.Evidence[0].ID, ArtifactID: testCaptureID, Revision: 2}})
	if err != nil || item.Hold.State != HoldInactive {
		t.Fatalf("release = %#v %v", item.Hold, err)
	}
	item, err = store.RemoveEvidence(item.ID, item.Evidence[0].ID, 0, "admin", "")
	if err != nil || !item.Hold.UpdatedAt.IsZero() || len(item.Hold.Results) != 0 || item.Validate() != nil {
		t.Fatalf("removing the last capture did not reset the hold: %#v %v", item.Hold, err)
	}
	if _, err := store.Delete(item.ID, 1); !errors.Is(err, ErrRevisionChanged) {
		t.Fatalf("stale delete returned %v", err)
	}
	deleted, err := store.Delete(item.ID, 0)
	if err != nil || deleted.ID != item.ID {
		t.Fatalf("delete = %#v %v", deleted, err)
	}
	if _, err := store.Get(item.ID); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("deleted case is still readable: %v", err)
	}
	if _, err := store.RemoveEvidence(item.ID, item.Evidence[0].ID, 0, "admin", ""); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("evidence removal on a deleted case returned %v", err)
	}
}

func TestCaseLimitIsReportedAsCaseLimit(t *testing.T) {
	store := &Store{Path: filepath.Join(t.TempDir(), "cases.json")}
	current := ledger{Schema: Schema, Cases: []Case{}}
	template, err := store.Create("Template", "", "admin", "create")
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < MaxCases; index++ {
		item := template
		item.ID = "case-" + strings.Repeat("0", 28) + hex4(index)
		current.Cases = append(current.Cases, item)
	}
	if err := store.write(current); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create("One more", "", "admin", "create"); !errors.Is(err, ErrCaseLimit) || !strings.Contains(err.Error(), "delete cases") {
		t.Fatalf("full case ledger returned %v", err)
	}
}

func hex4(value int) string {
	const digits = "0123456789abcdef"
	return string([]byte{digits[value>>12&15], digits[value>>8&15], digits[value>>4&15], digits[value&15]})
}
