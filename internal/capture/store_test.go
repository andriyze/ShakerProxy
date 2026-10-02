package capture

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/pcapng"
)

func validSession(t *testing.T, root string) Session {
	t.Helper()
	now := time.Date(2026, 9, 1, 12, 0, 0, 123, time.UTC)
	return Session{
		Schema: SchemaVersion, ID: "capture-00112233445566778899aabbccddeeff",
		Request: (StartRequest{Name: "test", Mode: ModeHeaders, Administrator: "admin", IdempotencyKey: "capture-request-0003"}).WithDefaults(),
		Source:  Source{InterfaceName: "lab0", InterfaceStableID: "pci-0000:00:01.0"}, OperatingMode: "ROUTED_PASSTHROUGH",
		SoftwareVersion: "test", StartedAt: now, StopAt: now.Add(time.Hour), ReserveBytes: DefaultReserveBytes,
		OutputBaseName: "capture.pcapng", DumpcapExecutable: "/usr/bin/dumpcap",
	}
}

func TestStoreCollectsDeterministicHashManifest(t *testing.T) {
	store := Store{Root: filepath.Join(t.TempDir(), "pcap")}
	session := validSession(t, store.Root)
	if err := store.Create(session); err != nil {
		t.Fatal(err)
	}
	directory, _ := store.ArtifactDirectory(session.ID)
	contents := []byte("pcapng fixture")
	if err := os.WriteFile(filepath.Join(directory, "capture_00001_20260901120000.pcapng"), contents, 0o640); err != nil {
		t.Fatal(err)
	}
	manifest, err := store.CollectFiles(session.ID, session.StartedAt.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	expected := sha256.Sum256(contents)
	if len(manifest.Files) != 1 || manifest.Files[0].SHA256 != hex.EncodeToString(expected[:]) || manifest.TotalSizeBytes != int64(len(contents)) || manifest.Files[0].PacketMembership == nil || manifest.Files[0].PacketMembership.State != pcapng.MembershipInvalidPCAPNG {
		t.Fatalf("unexpected manifest: %#v", manifest)
	}
}

// Regression from a routed EC2 lab: dumpcap creates 0600 files, so the
// isolated analyzer parsers could not reopen any segment.
func TestStoreGrantsAnalyzersReadOnDumpcapFiles(t *testing.T) {
	store := Store{Root: filepath.Join(t.TempDir(), "pcap")}
	session := validSession(t, store.Root)
	if err := store.Create(session); err != nil {
		t.Fatal(err)
	}
	directory, _ := store.ArtifactDirectory(session.ID)
	path := filepath.Join(directory, "capture_00001_20260901120000.pcapng")
	if err := os.WriteFile(path, []byte("pcapng fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CollectFiles(session.ID, session.StartedAt.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("capture segment mode = %v, %v; want 0644 so the isolated parsers can reopen it", info.Mode().Perm(), err)
	}
	parent, err := os.Stat(directory)
	if err != nil || parent.Mode().Perm()&0o007 != 0 {
		t.Fatalf("capture directory %v must deny other users; the segment mode relies on it", parent.Mode().Perm())
	}
}

// Live analysis reads the segment dumpcap is still writing. dumpcap creates
// it 0600; the capture group (the analyzer containers) may read it, nobody
// else gains anything, and a closed segment's wider mode is left alone.
func TestStoreSharesTheActiveSegmentWithTheCaptureGroupOnly(t *testing.T) {
	store := Store{Root: filepath.Join(t.TempDir(), "pcap")}
	session := validSession(t, store.Root)
	if err := store.Create(session); err != nil {
		t.Fatal(err)
	}
	directory, _ := store.ArtifactDirectory(session.ID)
	name := "capture_00002_20260901120010.pcapng"
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte("pcapng fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.ShareActiveSegment(session.ID, name); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("active segment mode = %v, %v; want 0640", info.Mode().Perm(), err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := store.ShareActiveSegment(session.ID, name); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o644 {
		t.Fatalf("sharing changed a published segment to %v", info.Mode().Perm())
	}
	link := "capture_00003_20260901120020.pcapng"
	if err := os.Symlink(filepath.Join(store.Root, session.ID, "session.json"), filepath.Join(directory, link)); err != nil {
		t.Fatal(err)
	}
	for _, unsafe := range []string{link, "../session.json", "session.json"} {
		if err := store.ShareActiveSegment(session.ID, unsafe); err == nil {
			t.Fatalf("shared %q", unsafe)
		}
	}
}

func TestStorePublishesBoundedClosedSegmentFeed(t *testing.T) {
	store := Store{Root: filepath.Join(t.TempDir(), "pcap")}
	session := validSession(t, store.Root)
	session.Request.MaxFiles = 2
	if err := store.Create(session); err != nil {
		t.Fatal(err)
	}
	status, err := store.ReadWorkerStatus(session.ID)
	if err != nil {
		t.Fatal(err)
	}
	status.State = StateRunning
	if err := store.WriteWorkerStatus(status); err != nil {
		t.Fatal(err)
	}
	directory, _ := store.ArtifactDirectory(session.ID)
	closedAt := session.StartedAt.Add(time.Minute)
	for index, name := range []string{"capture_00001_20260901120000.pcapng", "capture_00002_20260901120100.pcapng", "capture_00003_20260901120200.pcapng"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte{byte(index + 1)}, 0o640); err != nil {
			t.Fatal(err)
		}
		if _, err := store.PublishClosedSegment(session.ID, name, closedAt.Add(time.Duration(index)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	feed, err := store.ReadActiveSegmentFeed(session.ID)
	if err != nil || feed.Revision != 3 || feed.EvictedSegments != 1 || len(feed.Segments) != 2 || feed.Segments[0].Sequence != 2 || feed.Segments[1].Name != "capture_00003_20260901120200.pcapng" {
		t.Fatalf("unexpected active segment feed: %#v err=%v", feed, err)
	}
	unchanged, err := store.PublishClosedSegment(session.ID, feed.Segments[1].Name, closedAt.Add(5*time.Minute))
	if err != nil || unchanged.Revision != feed.Revision {
		t.Fatalf("idempotent segment publication changed revision: %#v err=%v", unchanged, err)
	}
	if err := os.WriteFile(filepath.Join(directory, feed.Segments[1].Name), []byte("changed"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PublishClosedSegment(session.ID, feed.Segments[1].Name, closedAt.Add(6*time.Minute)); err == nil {
		t.Fatal("reused segment name with changed metadata was accepted")
	}
}

func TestStoreBindsExactPacketMembershipIntoManifest(t *testing.T) {
	store := Store{Root: filepath.Join(t.TempDir(), "pcap")}
	session := validSession(t, store.Root)
	if err := store.Create(session); err != nil {
		t.Fatal(err)
	}
	directory, _ := store.ArtifactDirectory(session.ID)
	contents := packetMembershipFixture()
	if err := os.WriteFile(filepath.Join(directory, "capture.pcapng"), contents, 0o640); err != nil {
		t.Fatal(err)
	}
	manifest, err := store.CollectFiles(session.ID, session.StartedAt.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	membership := manifest.Files[0].PacketMembership
	if membership == nil || !membership.Exact() || membership.PacketCount != 1 || len(membership.MACAddresses) != 2 || len(membership.IPAddresses) != 2 {
		t.Fatalf("exact packet membership was not bound into the manifest: %#v", manifest.Files[0])
	}
}

func TestStoreRejectsSymlinkCaptureArtifact(t *testing.T) {
	store := Store{Root: filepath.Join(t.TempDir(), "pcap")}
	session := validSession(t, store.Root)
	if err := store.Create(session); err != nil {
		t.Fatal(err)
	}
	directory, _ := store.ArtifactDirectory(session.ID)
	if err := os.Symlink("session.json", filepath.Join(directory, "capture.pcapng")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CollectFiles(session.ID, time.Now()); err == nil {
		t.Fatal("symlink artifact unexpectedly accepted")
	}
}

func TestStoreReadsOnlyManifestBoundArtifactRanges(t *testing.T) {
	store := Store{Root: filepath.Join(t.TempDir(), "pcap")}
	session := validSession(t, store.Root)
	if err := store.Create(session); err != nil {
		t.Fatal(err)
	}
	directory, _ := store.ArtifactDirectory(session.ID)
	contents := []byte("0123456789abcdef")
	name := "capture_00001_20260901120000.pcapng"
	if err := os.WriteFile(filepath.Join(directory, name), contents, 0o640); err != nil {
		t.Fatal(err)
	}
	manifest, err := store.CollectFiles(session.ID, session.StartedAt.Add(time.Minute))
	if err != nil || store.WriteManifest(manifest) != nil {
		t.Fatalf("write manifest: %v", err)
	}
	chunk, err := store.ReadArtifactChunk(session.ID, name, 4, 6)
	if err != nil {
		t.Fatal(err)
	}
	if string(chunk.Data) != "456789" || chunk.Offset != 4 || chunk.TotalBytes != int64(len(contents)) || chunk.EOF || chunk.FileSHA256 != manifest.Files[0].SHA256 {
		t.Fatalf("unexpected artifact chunk: %#v", chunk)
	}
	last, err := store.ReadArtifactChunk(session.ID, name, 10, MaxArtifactChunkBytes)
	if err != nil || string(last.Data) != "abcdef" || !last.EOF {
		t.Fatalf("unexpected final chunk: %#v err=%v", last, err)
	}
	if _, err := store.ReadArtifactChunk(session.ID, "../session.json", 0, 1); err == nil {
		t.Fatal("path traversal artifact was accepted")
	}
}

func TestStoreRejectsArtifactThatDriftsAfterManifest(t *testing.T) {
	store := Store{Root: filepath.Join(t.TempDir(), "pcap")}
	session := validSession(t, store.Root)
	if err := store.Create(session); err != nil {
		t.Fatal(err)
	}
	directory, _ := store.ArtifactDirectory(session.ID)
	name := "capture.pcapng"
	if err := os.WriteFile(filepath.Join(directory, name), []byte("original"), 0o640); err != nil {
		t.Fatal(err)
	}
	manifest, err := store.CollectFiles(session.ID, session.StartedAt.Add(time.Minute))
	if err != nil || store.WriteManifest(manifest) != nil {
		t.Fatalf("write manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, name), []byte("changed-size"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReadArtifactChunk(session.ID, name, 0, 4); err == nil {
		t.Fatal("artifact drift after finalization was accepted")
	}
}

func TestStoreRejectsSameSizeArtifactMutationAfterManifest(t *testing.T) {
	store := Store{Root: filepath.Join(t.TempDir(), "pcap")}
	session := validSession(t, store.Root)
	if err := store.Create(session); err != nil {
		t.Fatal(err)
	}
	directory, _ := store.ArtifactDirectory(session.ID)
	name := "capture.pcapng"
	if err := os.WriteFile(filepath.Join(directory, name), []byte("original"), 0o640); err != nil {
		t.Fatal(err)
	}
	manifest, err := store.CollectFiles(session.ID, session.StartedAt.Add(time.Minute))
	if err != nil || store.WriteManifest(manifest) != nil {
		t.Fatalf("write manifest: %v", err)
	}
	changed := manifest.Files[0].Modified.Add(time.Second)
	if err := os.WriteFile(filepath.Join(directory, name), []byte("modified"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(filepath.Join(directory, name), changed, changed); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReadArtifactChunk(session.ID, name, 0, 4); err == nil {
		t.Fatal("same-size artifact mutation after finalization was accepted")
	}
}

func packetMembershipFixture() []byte {
	section := make([]byte, 28)
	copy(section[0:4], []byte{0x0a, 0x0d, 0x0d, 0x0a})
	binary.LittleEndian.PutUint32(section[4:8], 28)
	binary.LittleEndian.PutUint32(section[8:12], 0x1a2b3c4d)
	binary.LittleEndian.PutUint16(section[12:14], 1)
	for index := 16; index < 24; index++ {
		section[index] = 0xff
	}
	binary.LittleEndian.PutUint32(section[24:28], 28)
	interfaceBlock := make([]byte, 20)
	binary.LittleEndian.PutUint32(interfaceBlock[0:4], 1)
	binary.LittleEndian.PutUint32(interfaceBlock[4:8], 20)
	binary.LittleEndian.PutUint16(interfaceBlock[8:10], 1)
	binary.LittleEndian.PutUint32(interfaceBlock[12:16], 256)
	binary.LittleEndian.PutUint32(interfaceBlock[16:20], 20)
	packet := make([]byte, 14+20)
	copy(packet[0:6], []byte{0x02, 0, 0, 0, 0, 2})
	copy(packet[6:12], []byte{0x02, 0, 0, 0, 0, 1})
	binary.BigEndian.PutUint16(packet[12:14], 0x0800)
	packet[14] = 0x45
	copy(packet[26:30], []byte{10, 77, 0, 111})
	copy(packet[30:34], []byte{10, 77, 0, 1})
	padded := (len(packet) + 3) &^ 3
	enhanced := make([]byte, 32+padded)
	binary.LittleEndian.PutUint32(enhanced[0:4], 6)
	binary.LittleEndian.PutUint32(enhanced[4:8], uint32(len(enhanced)))
	binary.LittleEndian.PutUint32(enhanced[20:24], uint32(len(packet)))
	binary.LittleEndian.PutUint32(enhanced[24:28], uint32(len(packet)))
	copy(enhanced[28:], packet)
	binary.LittleEndian.PutUint32(enhanced[len(enhanced)-4:], uint32(len(enhanced)))
	contents := append(section, interfaceBlock...)
	return append(contents, enhanced...)
}
