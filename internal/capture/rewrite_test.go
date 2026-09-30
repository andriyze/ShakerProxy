package capture

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/pcapng"
)

func TestStoreAtomicallyRewritesAndRebindsFinalManifest(t *testing.T) {
	store, session, manifest, sourcePath := finalizedRewriteFixture(t, true)
	rule, err := pcapng.CanonicalSelectionRule(nil, []string{"10.77.0.111"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := session.StartedAt.Add(2 * time.Minute)
	record, err := store.RewritePCAP(t.Context(), PCAPRewriteRequest{
		Schema: PCAPRewriteSchema, ID: "pcap-rewrite-00112233445566778899aabbccddeeff", SessionID: session.ID,
		FileName: manifest.Files[0].Name, OriginalSHA256: manifest.Files[0].SHA256, Selection: rule, ToolVersion: "test-1",
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if record.State != PCAPRewriteCompleted || !record.ArtifactReplaced || !record.ReindexRequired || record.IndexInvalidationState != "PENDING" || record.SecureErasureGuaranteed || record.PacketsRead != 2 || record.PacketsRemoved != 1 || record.PacketsWritten != 1 || !validSHA256String(record.OutputSHA256) || record.OutputSHA256 == record.OriginalSHA256 || len(record.Failures) != 0 {
		t.Fatalf("unexpected rewrite record: %#v", record)
	}
	contents, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(contents)
	if hex.EncodeToString(digest[:]) != record.OutputSHA256 {
		t.Fatal("installed artifact does not match the independently verified output hash")
	}
	membership, err := pcapng.Inspect(bytes.NewReader(contents))
	if err != nil || membership.PacketCount != 1 || len(membership.IPAddresses) != 2 || membership.IPAddresses[1] != "10.77.0.222" {
		t.Fatalf("installed artifact retained the wrong packet population: %#v err=%v", membership, err)
	}
	updated, err := store.ReadManifest(session.ID)
	if err != nil || updated.Files[0].SHA256 != record.OutputSHA256 || updated.Files[0].RewriteManifestID != record.ID || updated.Files[0].PacketMembership == nil || updated.Files[0].PacketMembership.PacketCount != 1 || updated.TotalSizeBytes != int64(len(contents)) {
		t.Fatalf("capture manifest was not rebound to the rewrite: %#v err=%v", updated, err)
	}
	if _, _, err := store.DeletionFootprint(session.ID, updated); err != nil {
		t.Fatalf("rewritten capture is no longer eligible for manifest-bound deletion: %v", err)
	}
	persisted, err := store.ReadPCAPRewriteRecord(record.ID)
	if err != nil || persisted.OutputManifestSHA256 != record.OutputManifestSHA256 || persisted.SelectionSHA256 != record.SelectionSHA256 {
		t.Fatalf("rewrite chain-of-custody record was not durable: %#v err=%v", persisted, err)
	}
	staging, err := store.pcapRewriteDirectory(".pcap-rewrite-staging")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(staging)
	if err != nil || len(entries) != 0 {
		t.Fatalf("rewrite left an original or replacement in staging: %v %#v", err, entries)
	}
	idempotent, err := store.RewritePCAP(t.Context(), PCAPRewriteRequest{
		Schema: PCAPRewriteSchema, ID: record.ID, SessionID: session.ID, FileName: manifest.Files[0].Name,
		OriginalSHA256: manifest.Files[0].SHA256, Selection: rule, ToolVersion: "test-1",
	}, now.Add(time.Minute))
	if err != nil || idempotent.OutputSHA256 != record.OutputSHA256 {
		t.Fatalf("completed rewrite was not idempotent: %#v err=%v", idempotent, err)
	}
}

func TestStoreRewriteFailsClosedWithoutChangingSource(t *testing.T) {
	store, session, manifest, sourcePath := finalizedRewriteFixture(t, false)
	original, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	rule, err := pcapng.CanonicalSelectionRule([]string{"02:00:00:00:00:01"}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	record, err := store.RewritePCAP(t.Context(), PCAPRewriteRequest{
		Schema: PCAPRewriteSchema, ID: "pcap-rewrite-ffeeddccbbaa99887766554433221100", SessionID: session.ID,
		FileName: manifest.Files[0].Name, OriginalSHA256: manifest.Files[0].SHA256, Selection: rule, ToolVersion: "test-1",
	}, session.StartedAt.Add(2*time.Minute))
	if err == nil || record.State != PCAPRewriteFailed || len(record.Failures) != 1 || record.Failures[0] != "REWRITE_NOT_EXACT" {
		t.Fatalf("inexact rewrite was not durably rejected: %#v err=%v", record, err)
	}
	after, readErr := os.ReadFile(sourcePath)
	currentManifest, manifestErr := store.ReadManifest(session.ID)
	if readErr != nil || manifestErr != nil || string(after) != string(original) || currentManifest.Files[0].SHA256 != manifest.Files[0].SHA256 || currentManifest.Files[0].RewriteManifestID != "" {
		t.Fatalf("failed rewrite changed its only source or manifest: read=%v manifest=%v", readErr, manifestErr)
	}
	if persisted, readErr := store.ReadPCAPRewriteRecord(record.ID); readErr != nil || persisted.State != PCAPRewriteFailed {
		t.Fatalf("failed rewrite evidence was not preserved: %#v err=%v", persisted, readErr)
	}
}

func TestStoreRewritePreservesEmergencyReserve(t *testing.T) {
	store := Store{Root: filepath.Join(t.TempDir(), "pcap")}
	if err := store.ensureRoot(); err != nil {
		t.Fatal(err)
	}
	available, err := store.AvailableBytes()
	if err != nil {
		t.Fatal(err)
	}
	session := validSession(t, store.Root)
	const concurrentFilesystemHeadroom = uint64(1 << 40)
	if available > ^uint64(0)-concurrentFilesystemHeadroom {
		t.Fatal("test filesystem capacity cannot be represented with deterministic headroom")
	}
	// Go runs packages concurrently. Other package fixtures can release space
	// between this observation and the rewrite check, so leave a 1 TiB margin
	// rather than assuming global filesystem availability can only decrease.
	session.ReserveBytes = available + concurrentFilesystemHeadroom
	if err := store.Create(session); err != nil {
		t.Fatal(err)
	}
	status := WorkerStatus{Schema: SchemaVersion, SessionID: session.ID, State: StateStopped, StartedAt: session.StartedAt, EndedAt: session.StartedAt.Add(time.Minute), UpdatedAt: session.StartedAt.Add(time.Minute)}
	if err := store.WriteWorkerStatus(status); err != nil {
		t.Fatal(err)
	}
	directory, _ := store.ArtifactDirectory(session.ID)
	if err := os.WriteFile(filepath.Join(directory, "capture.pcapng"), packetMembershipFixture(), 0o640); err != nil {
		t.Fatal(err)
	}
	manifest, err := store.CollectFiles(session.ID, session.StartedAt.Add(time.Minute))
	if err != nil || store.WriteManifest(manifest) != nil {
		t.Fatalf("finalize capacity fixture: %v", err)
	}
	rule, err := pcapng.CanonicalSelectionRule(nil, []string{"10.77.0.111"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	record, err := store.RewritePCAP(t.Context(), PCAPRewriteRequest{
		Schema: PCAPRewriteSchema, ID: "pcap-rewrite-1234567890abcdef1234567890abcdef", SessionID: session.ID,
		FileName: manifest.Files[0].Name, OriginalSHA256: manifest.Files[0].SHA256, Selection: rule, ToolVersion: "test-1",
	}, session.StartedAt.Add(2*time.Minute))
	if err == nil || record.State != PCAPRewriteFailed || len(record.Failures) != 1 || record.Failures[0] != "INSUFFICIENT_TEMPORARY_CAPACITY" {
		t.Fatalf("rewrite consumed the emergency reserve: %#v err=%v", record, err)
	}
}

func finalizedRewriteFixture(t *testing.T, supported bool) (Store, Session, Manifest, string) {
	t.Helper()
	store := Store{Root: filepath.Join(t.TempDir(), "pcap")}
	session := validSession(t, store.Root)
	if err := store.Create(session); err != nil {
		t.Fatal(err)
	}
	status := WorkerStatus{Schema: SchemaVersion, SessionID: session.ID, State: StateStopped, StartedAt: session.StartedAt, EndedAt: session.StartedAt.Add(time.Minute), UpdatedAt: session.StartedAt.Add(time.Minute)}
	if err := store.WriteWorkerStatus(status); err != nil {
		t.Fatal(err)
	}
	contents := packetMembershipFixture()
	if supported {
		second := append([]byte(nil), contents[48:]...)
		copy(second[54:58], []byte{10, 77, 0, 222})
		contents = append(contents, second...)
	} else {
		// Link type 147 is structurally valid PCAPNG but cannot be classified
		// exactly by the sanitizer.
		contents[36], contents[37] = 147, 0
	}
	firstTimestamp := uint64(session.StartedAt.Add(30*time.Second).Unix()) * 1_000_000
	binary.LittleEndian.PutUint32(contents[60:64], uint32(firstTimestamp>>32))
	binary.LittleEndian.PutUint32(contents[64:68], uint32(firstTimestamp))
	if supported {
		secondTimestamp := uint64(session.StartedAt.Add(90*time.Second).Unix()) * 1_000_000
		binary.LittleEndian.PutUint32(contents[128:132], uint32(secondTimestamp>>32))
		binary.LittleEndian.PutUint32(contents[132:136], uint32(secondTimestamp))
	}
	directory, _ := store.ArtifactDirectory(session.ID)
	sourcePath := filepath.Join(directory, "capture.pcapng")
	if err := os.WriteFile(sourcePath, contents, 0o640); err != nil {
		t.Fatal(err)
	}
	manifest, err := store.CollectFiles(session.ID, session.StartedAt.Add(time.Minute))
	if err != nil || store.WriteManifest(manifest) != nil {
		t.Fatalf("finalize rewrite fixture: %v", err)
	}
	return store, session, manifest, sourcePath
}
