package casework

import (
	"path/filepath"
	"testing"
	"time"
)

const testCaptureID = "capture-0123456789abcdef0123456789abcdef"

func TestCaseLifecycleHasOptimisticMembershipHoldAndHashChainedTimeline(t *testing.T) {
	now := time.Date(2026, 9, 2, 6, 0, 0, 0, time.UTC)
	store := &Store{Path: filepath.Join(t.TempDir(), "cases.json"), Now: func() time.Time { return now }}
	item, err := store.Create("Camera incident", "Bench camera investigation", "admin", "authorized investigation")
	if err != nil {
		t.Fatal(err)
	}
	if item.Revision != 1 || item.Status != StatusOpen || item.Hold.State != HoldInactive || len(item.Timeline) != 1 {
		t.Fatalf("unexpected case: %#v", item)
	}
	now = now.Add(time.Minute)
	item, err = store.AddEvidence(item.ID, item.Revision, EvidenceCapture, testCaptureID, "Final packet capture", "admin", "attach capture evidence")
	if err != nil {
		t.Fatal(err)
	}
	if len(item.Evidence) != 1 || item.Revision != 2 {
		t.Fatalf("evidence was not attached: %#v", item)
	}
	result := HoldResult{EvidenceID: item.Evidence[0].ID, ArtifactID: testCaptureID, Protected: true, Revision: 1}
	now = now.Add(time.Minute)
	item, err = store.RecordHold(item.ID, item.Revision, true, "preserve incident evidence", "admin", "case-hold-operation-0001", []HoldResult{result})
	if err != nil {
		t.Fatal(err)
	}
	if item.Hold.State != HoldActive || !item.Hold.DesiredActive || item.Revision != 3 {
		t.Fatalf("hold not active: %#v", item.Hold)
	}
	if _, err := store.AddEvidence(item.ID, item.Revision, EvidenceQuerySnapshot, "qsnap-0123456789abcdef0123456789abcdef", "Snapshot", "admin", "late evidence"); err == nil {
		t.Fatal("active hold allowed membership change")
	}
	result.Protected = false
	result.Revision = 2
	now = now.Add(time.Minute)
	item, err = store.RecordHold(item.ID, item.Revision, false, "custodian approved release", "admin", "case-hold-operation-0002", []HoldResult{result})
	if err != nil {
		t.Fatal(err)
	}
	if item.Hold.State != HoldInactive || item.Hold.DesiredActive || item.Revision != 4 {
		t.Fatalf("hold not released: %#v", item.Hold)
	}
	now = now.Add(time.Minute)
	item, err = store.SetStatus(item.ID, item.Revision, StatusClosed, "admin", "investigation complete")
	if err != nil {
		t.Fatal(err)
	}
	if item.Status != StatusClosed || item.Validate() != nil || len(item.Timeline) != 5 {
		t.Fatalf("invalid closed case: %#v", item)
	}
	reloaded, err := store.Get(item.ID)
	if err != nil || reloaded.Timeline[len(reloaded.Timeline)-1].SHA256 != item.Timeline[len(item.Timeline)-1].SHA256 {
		t.Fatalf("case was not durable: %v", err)
	}
}

func TestPartialHoldIsVisibleAndStaleRevisionFails(t *testing.T) {
	store := &Store{Path: filepath.Join(t.TempDir(), "cases.json")}
	item, err := store.Create("Case", "", "admin", "create")
	if err != nil {
		t.Fatal(err)
	}
	item, err = store.AddEvidence(item.ID, item.Revision, EvidenceCapture, testCaptureID, "Capture", "admin", "attach")
	if err != nil {
		t.Fatal(err)
	}
	result := HoldResult{EvidenceID: item.Evidence[0].ID, ArtifactID: testCaptureID, Protected: false, Failure: "host unavailable"}
	item, err = store.RecordHold(item.ID, item.Revision, true, "preserve", "admin", "case-hold-operation-0003", []HoldResult{result})
	if err != nil {
		t.Fatal(err)
	}
	if item.Hold.State != HoldPartial || !item.Hold.DesiredActive {
		t.Fatalf("partial hold hidden: %#v", item.Hold)
	}
	if _, err := store.SetStatus(item.ID, item.Revision-1, StatusClosed, "admin", "stale"); err == nil {
		t.Fatal("stale revision was accepted")
	}
}

func TestHoldRejectsMissingOrMismatchedCaptureCoverage(t *testing.T) {
	store := &Store{Path: filepath.Join(t.TempDir(), "cases.json")}
	item, err := store.Create("Case", "", "admin", "create")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.RecordHold(item.ID, item.Revision, true, "preserve", "admin", "case-hold-operation-0004", nil); err == nil {
		t.Fatal("case without capture evidence accepted a hold")
	}
	item, err = store.AddEvidence(item.ID, item.Revision, EvidenceCapture, testCaptureID, "Capture", "admin", "attach")
	if err != nil {
		t.Fatal(err)
	}
	wrong := HoldResult{EvidenceID: "evidence-ffffffffffffffffffffffffffffffff", ArtifactID: testCaptureID, Protected: true}
	if _, err := store.RecordHold(item.ID, item.Revision, true, "preserve", "admin", "case-hold-operation-0005", []HoldResult{wrong}); err == nil {
		t.Fatal("mismatched capture result was accepted")
	}
}

func TestAddingEvidenceAfterReleaseClearsThePreviousHoldResultSet(t *testing.T) {
	store := &Store{Path: filepath.Join(t.TempDir(), "cases.json")}
	item, err := store.Create("Case", "", "admin", "create")
	if err != nil {
		t.Fatal(err)
	}
	item, err = store.AddEvidence(item.ID, item.Revision, EvidenceCapture, testCaptureID, "Capture", "admin", "attach")
	if err != nil {
		t.Fatal(err)
	}
	result := HoldResult{EvidenceID: item.Evidence[0].ID, ArtifactID: testCaptureID, Protected: false, Revision: 2}
	item, err = store.RecordHold(item.ID, item.Revision, false, "confirmed release", "admin", "case-hold-operation-0006", []HoldResult{result})
	if err != nil {
		t.Fatal(err)
	}
	item, err = store.AddEvidence(item.ID, item.Revision, EvidenceCaptureExport, "export-0123456789abcdef0123456789abcdef", "Export", "admin", "attach export")
	if err != nil {
		t.Fatal(err)
	}
	if !item.Hold.UpdatedAt.IsZero() || len(item.Hold.Results) != 0 || item.Validate() != nil {
		t.Fatalf("membership change retained a stale hold result: %#v", item.Hold)
	}
}
