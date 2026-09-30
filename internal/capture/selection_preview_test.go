package capture

import (
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/pcapng"
)

func TestSelectionPreviewCountsExactSharedPCAPCollateral(t *testing.T) {
	store, session, _, _ := finalizedRewriteFixture(t, true)
	start, end := session.StartedAt, session.StartedAt.Add(2*time.Minute)
	rule, err := pcapng.CanonicalSelectionRule(nil, []string{"10.77.0.111"}, &start, &end)
	if err != nil {
		t.Fatal(err)
	}
	preview, err := store.PreviewPCAPSelection(t.Context(), rule, end.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if !preview.Exact || preview.SecureErasureGuaranteed || preview.EvaluatedSessions != 1 || preview.EvaluatedFiles != 1 || preview.ScannedBytes == 0 || len(preview.Blockers) != 0 || len(preview.ImpactedFiles) != 1 {
		t.Fatalf("unexpected exact PCAP selection preview: %#v", preview)
	}
	if err := preview.Validate(); err != nil {
		t.Fatalf("exact preview does not validate: %v", err)
	}
	impact := preview.ImpactedFiles[0]
	if impact.PacketsRead != 2 || impact.MatchedPackets != 1 || impact.CollateralPacketsInWholeDelete != 1 || impact.SanitizedBytes >= impact.OriginalBytes || impact.RetainedIPAddresses != 2 || impact.RetainedIdentitySHA256 == "" || len(impact.RetainedIPSample) != 2 {
		t.Fatalf("shared-PCAP collateral was not counted exactly: %#v", impact)
	}
}

func TestSelectionPreviewBlocksInexactMembership(t *testing.T) {
	store, session, _, _ := finalizedRewriteFixture(t, false)
	start, end := session.StartedAt, session.StartedAt.Add(2*time.Minute)
	rule, err := pcapng.CanonicalSelectionRule([]string{"02:00:00:00:00:01"}, nil, &start, &end)
	if err != nil {
		t.Fatal(err)
	}
	preview, err := store.PreviewPCAPSelection(t.Context(), rule, end.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if preview.Exact || len(preview.ImpactedFiles) != 0 || len(preview.Blockers) != 1 || preview.Blockers[0].Code != "MEMBERSHIP_NOT_EXACT" {
		t.Fatalf("inexact manifest was omitted instead of blocking destruction: %#v", preview)
	}
}

func TestSelectionPreviewSkipsNonoverlappingCaptureSessions(t *testing.T) {
	store, session, _, _ := finalizedRewriteFixture(t, true)
	start, end := session.StartedAt.Add(-2*time.Hour), session.StartedAt.Add(-time.Hour)
	rule, err := pcapng.CanonicalSelectionRule(nil, []string{"10.77.0.111"}, &start, &end)
	if err != nil {
		t.Fatal(err)
	}
	preview, err := store.PreviewPCAPSelection(t.Context(), rule, session.StartedAt.Add(time.Hour))
	if err != nil || !preview.Exact || preview.EvaluatedSessions != 0 || preview.EvaluatedFiles != 0 || len(preview.ImpactedFiles) != 0 {
		t.Fatalf("nonoverlapping capture was evaluated: %#v err=%v", preview, err)
	}
}

func TestSelectionPreviewValidationRejectsAggregatePacketOverflow(t *testing.T) {
	store, session, _, _ := finalizedRewriteFixture(t, true)
	start, end := session.StartedAt, session.StartedAt.Add(2*time.Minute)
	rule, err := pcapng.CanonicalSelectionRule(nil, []string{"10.77.0.111"}, &start, &end)
	if err != nil {
		t.Fatal(err)
	}
	preview, err := store.PreviewPCAPSelection(t.Context(), rule, end.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	first := preview.ImpactedFiles[0]
	first.PacketsRead = ^uint64(0)
	first.MatchedPackets = ^uint64(0)
	first.CollateralPacketsInWholeDelete = 0
	second := first
	second.FileName = "overflow.pcapng"
	second.PacketsRead = 1
	second.MatchedPackets = 1
	preview.ImpactedFiles = []PCAPSelectionFileImpact{first, second}
	preview.ScannedBytes += second.OriginalBytes
	if err := preview.Validate(); err == nil {
		t.Fatal("preview accepted aggregate packet-count overflow")
	}
}

func TestSelectionPreviewBlocksActiveCapturePastPlannedStop(t *testing.T) {
	store, session, _, _ := finalizedRewriteFixture(t, true)
	now := session.StopAt.Add(time.Hour)
	status := WorkerStatus{Schema: SchemaVersion, SessionID: session.ID, State: StateRunning, StartedAt: session.StartedAt, UpdatedAt: now}
	if err := store.WriteWorkerStatus(status); err != nil {
		t.Fatal(err)
	}
	start, end := session.StopAt.Add(10*time.Minute), session.StopAt.Add(20*time.Minute)
	rule, err := pcapng.CanonicalSelectionRule(nil, []string{"10.77.0.111"}, &start, &end)
	if err != nil {
		t.Fatal(err)
	}
	preview, err := store.PreviewPCAPSelection(t.Context(), rule, now)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Exact || preview.EvaluatedSessions != 1 || len(preview.Blockers) != 1 || preview.Blockers[0].Code != "ACTIVE_CAPTURE" {
		t.Fatalf("overrunning active capture was omitted from the preview: %#v", preview)
	}
}
