package capture

import (
	"errors"
	"os"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/pcapng"
)

func TestStoreDeletesReviewedWholePCAPAndRebindsManifest(t *testing.T) {
	store, session, manifest, sourcePath := finalizedRewriteFixture(t, true)
	start, end := session.StartedAt, session.StartedAt.Add(2*time.Minute)
	rule, err := pcapng.CanonicalSelectionRule(nil, []string{"10.77.0.111"}, &start, &end)
	if err != nil {
		t.Fatal(err)
	}
	request := PCAPArtifactDeletionRequest{
		Schema: PCAPArtifactDeletionSchema, ID: "pcap-delete-00112233445566778899aabbccddeeff",
		SessionID: session.ID, FileName: manifest.Files[0].Name, OriginalSHA256: manifest.Files[0].SHA256,
		Selection: rule, ExpectedPackets: 2, ExpectedMatchedPackets: 1, ExpectedCollateralPackets: 1,
	}
	record, err := store.DeletePCAPArtifact(t.Context(), request, end.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if record.State != PCAPArtifactDeletionCompleted || !record.ArtifactRemoved || !record.ReindexRequired || record.IndexInvalidationState != "PENDING" || record.PacketsRead != 2 || record.MatchedPacketsRemoved != 1 || record.CollateralPacketsRemoved != 1 || record.SecureErasureGuaranteed || record.OutputManifestSHA256 == "" {
		t.Fatalf("unexpected whole-file deletion record: %#v", record)
	}
	if _, err := os.Lstat(sourcePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("reviewed PCAP still exists after deletion: %v", err)
	}
	updated, err := store.ReadManifest(session.ID)
	if err != nil || len(updated.Files) != 0 || updated.TotalSizeBytes != 0 {
		t.Fatalf("manifest was not rebound after deletion: %#v err=%v", updated, err)
	}
	persisted, err := store.ReadPCAPArtifactDeletionRecord(record.ID)
	if err != nil || persisted.OutputManifestSHA256 != record.OutputManifestSHA256 {
		t.Fatalf("whole-file deletion evidence was not durable: %#v err=%v", persisted, err)
	}
	replayed, err := store.DeletePCAPArtifact(t.Context(), request, end.Add(2*time.Minute))
	if err != nil || replayed.OutputManifestSHA256 != record.OutputManifestSHA256 {
		t.Fatalf("whole-file deletion replay was not stable: %#v err=%v", replayed, err)
	}
}

func TestStoreWholePCAPDeletionRejectsChangedReviewedImpact(t *testing.T) {
	store, session, manifest, sourcePath := finalizedRewriteFixture(t, true)
	start, end := session.StartedAt, session.StartedAt.Add(2*time.Minute)
	rule, err := pcapng.CanonicalSelectionRule(nil, []string{"10.77.0.111"}, &start, &end)
	if err != nil {
		t.Fatal(err)
	}
	record, err := store.DeletePCAPArtifact(t.Context(), PCAPArtifactDeletionRequest{
		Schema: PCAPArtifactDeletionSchema, ID: "pcap-delete-ffeeddccbbaa99887766554433221100",
		SessionID: session.ID, FileName: manifest.Files[0].Name, OriginalSHA256: manifest.Files[0].SHA256,
		Selection: rule, ExpectedPackets: 2, ExpectedMatchedPackets: 2, ExpectedCollateralPackets: 0,
	}, end.Add(time.Minute))
	if err == nil || record.State != PCAPArtifactDeletionFailed || record.Failure != "REVIEWED_IMPACT_CHANGED" {
		t.Fatalf("changed reviewed impact was not rejected: %#v err=%v", record, err)
	}
	if _, err := os.Stat(sourcePath); err != nil {
		t.Fatalf("failed deletion changed the source: %v", err)
	}
	current, err := store.ReadManifest(session.ID)
	if err != nil || len(current.Files) != 1 || current.Files[0].SHA256 != manifest.Files[0].SHA256 {
		t.Fatalf("failed deletion changed the manifest: %#v err=%v", current, err)
	}
}
