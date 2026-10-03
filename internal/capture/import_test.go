package capture

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/pcapng"
	"shakerproxy.dev/shakerproxy/internal/pcapng/pcapngtest"
)

func importManager(t *testing.T) *ImportManager {
	t.Helper()
	root := t.TempDir()
	return &ImportManager{
		Store:    Store{Root: filepath.Join(root, "pcap")},
		TempRoot: filepath.Join(root, "import-tmp"),
		Now:      func() time.Time { return time.Date(2026, 10, 2, 23, 0, 0, 0, time.UTC) },
	}
}

// ethernetPacket builds a minimal Ethernet frame at a time, so a fixture
// pcapng carries real link-type-1 packets.
func ethernetPacket(at time.Time) pcapngtest.RawPacket {
	frame := make([]byte, 60)
	copy(frame[0:6], []byte{0x02, 0, 0, 0, 0, 0x01})
	copy(frame[6:12], []byte{0x02, 0, 0, 0, 0, 0x02})
	frame[12], frame[13] = 0x08, 0x00 // IPv4 EtherType
	return pcapngtest.RawPacket{At: at, Data: frame}
}

func validImportPCAPNG(count int) []byte {
	base := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	packets := make([]pcapngtest.RawPacket, 0, count)
	for i := 0; i < count; i++ {
		packets = append(packets, ethernetPacket(base.Add(time.Duration(i)*time.Second)))
	}
	return pcapngtest.File(1, packets)
}

// importInChunks uploads data through Begin/Append in the real chunk size.
func importInChunks(t *testing.T, m *ImportManager, data []byte) (ImportResult, error) {
	t.Helper()
	id, err := m.Begin("UniFi gateway capture", "from the router", "operator", "", "")
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	offset := int64(0)
	for offset < int64(len(data)) {
		end := offset + ImportChunkBytes
		if end > int64(len(data)) {
			end = int64(len(data))
		}
		chunk := data[offset:end]
		eof := end == int64(len(data))
		result, err := m.Append(id, offset, chunk, eof)
		if err != nil {
			return ImportResult{}, err
		}
		offset = end
		if eof {
			return result, nil
		}
	}
	// Empty upload: signal EOF explicitly.
	return m.Append(id, 0, nil, true)
}

func TestImportFinalizesAPcapngTheAnalyzerCanLoad(t *testing.T) {
	m := importManager(t)
	data := validImportPCAPNG(5)
	result, err := importInChunks(t, m, data)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if result.Packets != 5 || result.SizeBytes != int64(len(data)) || len(result.LinkTypes) != 1 || result.LinkTypes[0] != 1 {
		t.Fatalf("unexpected result: %#v", result)
	}
	if result.FirstPacket.IsZero() || !result.LastPacket.After(result.FirstPacket) {
		t.Fatalf("packet span not captured: %#v", result)
	}

	session, err := m.Store.ReadSession(result.SessionID)
	if err != nil {
		t.Fatalf("read session: %v", err)
	}
	if !session.Request.Imported || session.DumpcapExecutable != "" {
		t.Fatalf("session is not marked imported: %#v", session.Request)
	}
	status, err := m.Store.ReadWorkerStatus(result.SessionID)
	if err != nil || status.State != StateCompleted {
		t.Fatalf("worker status = %v, %v; want COMPLETED", status.State, err)
	}
	manifest, err := m.Store.ReadManifest(result.SessionID)
	if err != nil || len(manifest.Files) != 1 || manifest.Files[0].Name != "capture.pcapng" {
		t.Fatalf("manifest = %#v, %v", manifest, err)
	}
	artifactDir, _ := m.Store.ArtifactDirectory(result.SessionID)
	info, err := os.Stat(filepath.Join(artifactDir, "capture.pcapng"))
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("artifact mode = %v, %v; want 0644 so the isolated analyzers can read it", info.Mode().Perm(), err)
	}
}

func TestImportRejectsBadUploads(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want error
	}{
		{"garbage", []byte("this is not a capture file at all, really"), ErrNotCapture},
		{"empty", []byte{}, nil},
		{"truncated pcapng header", []byte{0x0a, 0x0d}, ErrNotCapture},
		{"classic pcap", append([]byte{0xd4, 0xc3, 0xb2, 0xa1}, make([]byte, 40)...), ErrClassicPCAP},
		{"pcapng with no packets", pcapngtest.File(1, nil), nil},
		{"unsupported link type", pcapngtest.File(127, []pcapngtest.RawPacket{{At: time.Now(), Data: make([]byte, 40)}}), nil},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			m := importManager(t)
			_, err := importInChunks(t, m, test.data)
			if err == nil {
				t.Fatalf("expected the upload to be refused")
			}
			if test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("error = %v; want %v", err, test.want)
			}
			// A refused import must leave nothing in the store.
			ids, listErr := m.Store.ListSessionIDs()
			if listErr == nil && len(ids) != 0 {
				t.Fatalf("a refused import left sessions behind: %v", ids)
			}
			// ...and no temporary file.
			entries, _ := os.ReadDir(m.TempRoot)
			if len(entries) != 0 {
				t.Fatalf("a refused import left temp files: %v", entries)
			}
		})
	}
}

func TestImportRejectsOversizeAndBadOffset(t *testing.T) {
	m := importManager(t)
	m.MaxBytes = 64 // tiny
	data := validImportPCAPNG(5)
	if _, err := importInChunks(t, m, data); err == nil {
		t.Fatal("expected the oversize import to be refused")
	}

	m2 := importManager(t)
	id, err := m2.Begin("c", "", "op", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m2.Append(id, 10, []byte("x"), false); err == nil {
		t.Fatal("expected a non-continuous offset to be refused")
	}
	// The bad offset aborts the import.
	if _, err := m2.Append(id, 0, []byte("x"), false); err == nil {
		t.Fatal("expected the aborted import to be gone")
	}
}

func TestImportBoundsConcurrentUploads(t *testing.T) {
	m := importManager(t)
	for i := 0; i < maxConcurrentImports; i++ {
		if _, err := m.Begin("c", "", "op", "", ""); err != nil {
			t.Fatalf("begin %d: %v", i, err)
		}
	}
	if _, err := m.Begin("one too many", "", "op", "", ""); err == nil {
		t.Fatal("expected the concurrent-import limit to be enforced")
	}
}

// The uploaded name never reaches the filesystem; the server-generated
// session ID is the only path component.
func TestImportIgnoresTheUploadedNameForPaths(t *testing.T) {
	m := importManager(t)
	id, err := m.Begin("../../etc/passwd", "a name with /slashes/", "op", "", "")
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if !ValidSessionID(id) {
		t.Fatalf("session ID is not store-safe: %q", id)
	}
	entries, _ := os.ReadDir(m.TempRoot)
	if len(entries) != 1 || entries[0].Name() != "import-"+id+".pcapng" {
		t.Fatalf("temp file name derived from the upload name: %v", entries)
	}
}

// A capture whose writer stopped mid-packet keeps its complete packets, and
// the stored file ends on a whole block so the analyzers read it.
func TestImportTrimsACutOffLastBlock(t *testing.T) {
	m := importManager(t)
	whole := validImportPCAPNG(5)
	cut := whole[:len(whole)-10]
	result, err := importInChunks(t, m, cut)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if result.Packets != 4 || result.TruncatedBytes <= 0 || result.SizeBytes+result.TruncatedBytes != int64(len(cut)) {
		t.Fatalf("result = %#v", result)
	}
	artifactDir, _ := m.Store.ArtifactDirectory(result.SessionID)
	stored, err := os.ReadFile(filepath.Join(artifactDir, "capture.pcapng"))
	if err != nil || int64(len(stored)) != result.SizeBytes {
		t.Fatalf("stored %d bytes (%v), want %d", len(stored), err, result.SizeBytes)
	}
	if err := pcapng.ScanPackets(t.Context(), bytes.NewReader(stored), func(pcapng.Packet) error { return nil }); err != nil {
		t.Fatalf("the stored file does not end cleanly: %v", err)
	}
	// A whole file is stored as is.
	clean, err := importInChunks(t, importManager(t), whole)
	if err != nil || clean.TruncatedBytes != 0 || clean.SizeBytes != int64(len(whole)) {
		t.Fatalf("whole file: %#v %v", clean, err)
	}
}

// A name sent with the last chunk (a form field after the file) wins.
func TestImportTakesTheNameFromTheLastChunk(t *testing.T) {
	m := importManager(t)
	data := validImportPCAPNG(2)
	id, err := m.Begin("unifi.pcapng", "Imported from unifi.pcapng", "operator", "", "")
	if err != nil {
		t.Fatal(err)
	}
	result, err := m.AppendNamed(id, 0, data, true, "Router capture", "the gateway's own capture")
	if err != nil {
		t.Fatal(err)
	}
	session, err := m.Store.ReadSession(result.SessionID)
	if err != nil || session.Request.Name != "Router capture" || session.Request.Description != "the gateway's own capture" {
		t.Fatalf("session request = %#v (%v)", session.Request, err)
	}
}

// Temporary files of uploads the daemon was handling when it stopped are
// removed; uploads still in progress are not.
func TestImportSweepsOrphanedTemporaryFiles(t *testing.T) {
	m := importManager(t)
	live, err := m.Begin("live", "", "operator", "", "")
	if err != nil {
		t.Fatal(err)
	}
	orphan := filepath.Join(m.TempRoot, "import-capture-00112233445566778899aabbccddeeff.pcapng")
	if err := os.WriteFile(orphan, []byte("partial"), 0o640); err != nil {
		t.Fatal(err)
	}
	m.SweepOrphans()
	if _, err := os.Stat(orphan); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("orphan kept: %v", err)
	}
	if _, err := os.Stat(filepath.Join(m.TempRoot, "import-"+live+".pcapng")); err != nil {
		t.Fatalf("the live upload's file was removed: %v", err)
	}
	m.Abort(live)
	if _, err := os.Stat(filepath.Join(m.TempRoot, "import-"+live+".pcapng")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("abort kept the file: %v", err)
	}
}
