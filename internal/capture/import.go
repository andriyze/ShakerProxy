package capture

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"shakerproxy.dev/shakerproxy/internal/pcapng"
)

const (
	// DefaultMaxImportBytes bounds a single imported capture. A tester
	// uploads a capture taken elsewhere (the UniFi gateway's own packet
	// capture, tcpdump on another box); this keeps one import within the
	// capture quota without a full ring.
	DefaultMaxImportBytes = int64(512) << 20
	// ImportChunkBytes is the most raw capture data one AppendImport RPC
	// carries. The gateway RPC request line is bounded at 64 KiB, and the
	// chunk travels base64-encoded with the session ID and offset, so 32 KiB
	// of raw bytes stays well inside that frame.
	ImportChunkBytes = 32 << 10
	// maxConcurrentImports bounds half-finished uploads held on disk.
	maxConcurrentImports = 4
	// importExpiry drops an upload that stops partway so its temp file does
	// not linger.
	importExpiry = 15 * time.Minute
	// importSegmentSizeMiB and importMaxFiles size the import session's ring
	// allowance (see Store.CollectFiles). The product is the 8 GiB session
	// cap; one imported file far smaller than that always fits.
	importSegmentSizeMiB = 512
	importMaxFiles       = 16
)

// importableLinkTypes are the PCAP link-layer types the offline analyzers and
// the membership/flow readers handle. Everything else is refused so a capture
// that would analyze incorrectly is never stored.
//
//	0   LINKTYPE_NULL / BSD loopback
//	1   LINKTYPE_ETHERNET
//	12  LINKTYPE_RAW (some stacks)
//	101 LINKTYPE_RAW (IPv4/IPv6 with no link header)
//	108 LINKTYPE_LOOP (OpenBSD loopback)
//	113 LINKTYPE_LINUX_SLL (the "any" device)
//	276 LINKTYPE_LINUX_SLL2
var importableLinkTypes = map[uint16]bool{0: true, 1: true, 12: true, 101: true, 108: true, 113: true, 276: true}

// ErrClassicPCAP marks an upload that is a classic .pcap, not a .pcapng, so
// the caller can tell the tester exactly how to convert it.
var ErrClassicPCAP = errors.New("the file is a classic .pcap; convert it to .pcapng (for example: editcap in.pcap out.pcapng) and import that")

// ErrNotCapture marks an upload whose bytes are not a capture file at all.
var ErrNotCapture = errors.New("the file is not a .pcapng capture")

// ImportResult describes a finalized imported capture.
type ImportResult struct {
	SessionID   string    `json:"session_id"`
	Packets     uint64    `json:"packets"`
	SizeBytes   int64     `json:"size_bytes"`
	LinkTypes   []uint16  `json:"link_types"`
	FirstPacket time.Time `json:"first_packet,omitzero"`
	LastPacket  time.Time `json:"last_packet,omitzero"`
	// TruncatedBytes is how much of a cut-off last block was dropped: a
	// capture whose writer was stopped mid-packet keeps its complete
	// packets, and the stored file ends cleanly so the analyzers read it.
	TruncatedBytes int64 `json:"truncated_bytes,omitempty"`
}

type pendingImport struct {
	sessionID       string
	file            *os.File
	path            string
	written         int64
	name            string
	description     string
	administrator   string
	operatingMode   string
	softwareVersion string
	startedAt       time.Time
}

// ImportManager assembles an uploaded .pcapng in bounded chunks and, once the
// upload finishes, places it in the capture store as a finalized capture the
// offline analyzers pick up like any other. It owns no privileged state
// beyond the capture store and its own temporary directory.
type ImportManager struct {
	Store    Store
	TempRoot string
	MaxBytes int64
	Now      func() time.Time

	mu      sync.Mutex
	pending map[string]*pendingImport
}

func (m *ImportManager) now() time.Time {
	if m.Now != nil {
		return m.Now().UTC()
	}
	return time.Now().UTC()
}

func (m *ImportManager) maxBytes() int64 {
	if m.MaxBytes > 0 {
		return m.MaxBytes
	}
	return DefaultMaxImportBytes
}

// Begin starts an import and returns its server-generated session ID. The
// uploaded file name is never used for any path; the session ID is the only
// identifier that reaches the filesystem.
func (m *ImportManager) Begin(name, description, administrator, operatingMode, softwareVersion string) (string, error) {
	if err := validateText("capture name", name, 1, 96); err != nil {
		return "", err
	}
	if err := validateText("capture description", description, 0, 1024); err != nil {
		return "", err
	}
	if err := validateText("administrator", administrator, 1, 96); err != nil {
		return "", err
	}
	if err := m.Store.Validate(); err != nil {
		return "", err
	}
	if m.TempRoot == "" {
		return "", errors.New("import temporary directory is not configured")
	}
	if err := os.MkdirAll(m.TempRoot, 0o770); err != nil {
		return "", fmt.Errorf("prepare import temporary directory: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.sweepLocked()
	if m.pending == nil {
		m.pending = map[string]*pendingImport{}
	}
	if len(m.pending) >= maxConcurrentImports {
		return "", errors.New("too many imports are in progress; try again shortly")
	}
	sessionID, err := newImportSessionID()
	if err != nil {
		return "", err
	}
	path := filepath.Join(m.TempRoot, "import-"+sessionID+".pcapng")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		return "", fmt.Errorf("open import temporary file: %w", err)
	}
	m.pending[sessionID] = &pendingImport{
		sessionID: sessionID, file: file, path: path,
		name: name, description: description, administrator: administrator,
		operatingMode: operatingMode, softwareVersion: softwareVersion, startedAt: m.now(),
	}
	return sessionID, nil
}

// Append writes the next chunk at the expected offset. When eof is set it
// validates and finalizes the capture and returns the result; otherwise the
// returned result is zero.
func (m *ImportManager) Append(sessionID string, offset int64, data []byte, eof bool) (ImportResult, error) {
	return m.AppendNamed(sessionID, offset, data, eof, "", "")
}

// AppendNamed is Append whose final chunk may also set the capture's name
// and description, for an upload that sends them after the file.
func (m *ImportManager) AppendNamed(sessionID string, offset int64, data []byte, eof bool, name, description string) (ImportResult, error) {
	if !ValidSessionID(sessionID) {
		return ImportResult{}, errors.New("invalid import session ID")
	}
	if len(data) > ImportChunkBytes {
		return ImportResult{}, errors.New("import chunk exceeds the allowed size")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	pending, ok := m.pending[sessionID]
	if !ok {
		return ImportResult{}, errors.New("no import is in progress for this session")
	}
	if offset != pending.written {
		m.abortLocked(pending)
		return ImportResult{}, fmt.Errorf("import chunk offset %d does not continue the upload at %d", offset, pending.written)
	}
	if pending.written+int64(len(data)) > m.maxBytes() {
		m.abortLocked(pending)
		return ImportResult{}, fmt.Errorf("import exceeds the %d MiB limit", m.maxBytes()>>20)
	}
	if len(data) > 0 {
		if _, err := pending.file.Write(data); err != nil {
			m.abortLocked(pending)
			return ImportResult{}, fmt.Errorf("write import chunk: %w", err)
		}
		pending.written += int64(len(data))
	}
	if !eof {
		return ImportResult{}, nil
	}
	if name != "" {
		if err := validateText("capture name", name, 1, 96); err != nil {
			m.abortLocked(pending)
			return ImportResult{}, err
		}
		pending.name = name
	}
	if description != "" {
		if err := validateText("capture description", description, 0, 1024); err != nil {
			m.abortLocked(pending)
			return ImportResult{}, err
		}
		pending.description = description
	}
	result, err := m.finalizeLocked(pending)
	if err != nil {
		m.abortLocked(pending)
		return ImportResult{}, err
	}
	delete(m.pending, sessionID)
	return result, nil
}

// Abort discards an in-progress import.
func (m *ImportManager) Abort(sessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if pending, ok := m.pending[sessionID]; ok {
		m.abortLocked(pending)
	}
}

func (m *ImportManager) abortLocked(pending *pendingImport) {
	pending.file.Close()
	os.Remove(pending.path)
	delete(m.pending, pending.sessionID)
}

func (m *ImportManager) sweepLocked() {
	cutoff := m.now().Add(-importExpiry)
	for _, pending := range m.pending {
		if pending.startedAt.Before(cutoff) {
			m.abortLocked(pending)
		}
	}
	m.removeOrphansLocked()
}

// SweepOrphans removes temporary files of imports this manager is not
// tracking: uploads that were in flight when the daemon stopped, which can
// never finish and would otherwise hold up to the import limit each.
func (m *ImportManager) SweepOrphans() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.removeOrphansLocked()
}

func (m *ImportManager) removeOrphansLocked() {
	if m.TempRoot == "" {
		return
	}
	matches, err := filepath.Glob(filepath.Join(m.TempRoot, "import-capture-*.pcapng"))
	if err != nil {
		return
	}
	for _, path := range matches {
		sessionID := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(path), "import-"), ".pcapng")
		if _, tracked := m.pending[sessionID]; !tracked {
			os.Remove(path)
		}
	}
}

func (m *ImportManager) finalizeLocked(pending *pendingImport) (ImportResult, error) {
	if err := pending.file.Sync(); err != nil {
		return ImportResult{}, fmt.Errorf("flush import file: %w", err)
	}
	if err := pending.file.Close(); err != nil {
		return ImportResult{}, fmt.Errorf("close import file: %w", err)
	}
	if pending.written < 1 {
		return ImportResult{}, errors.New("the uploaded capture is empty")
	}

	stats, err := inspectImport(pending.path)
	if err != nil {
		return ImportResult{}, err
	}
	size, truncatedBytes := pending.written, int64(0)
	if stats.completeBytes < pending.written {
		// Drop the cut-off last block so Zeek and Suricata read a file that
		// ends cleanly.
		if err := os.Truncate(pending.path, stats.completeBytes); err != nil {
			return ImportResult{}, fmt.Errorf("trim the cut-off last block: %w", err)
		}
		size, truncatedBytes = stats.completeBytes, pending.written-stats.completeBytes
	}

	now := m.now()
	session := Session{
		Schema:          SchemaVersion,
		ID:              pending.sessionID,
		Request:         importStartRequest(pending.name, pending.description, pending.administrator),
		Source:          Source{InterfaceName: "import", InterfaceStableID: "import:" + pending.sessionID},
		OperatingMode:   importOperatingMode(pending.operatingMode),
		SoftwareVersion: importSoftwareVersion(pending.softwareVersion),
		StartedAt:       now, StopAt: now.Add(10 * time.Second), ReserveBytes: DefaultReserveBytes,
		OutputBaseName: "capture.pcapng",
	}
	if err := m.Store.Create(session); err != nil {
		return ImportResult{}, err
	}
	// From here on, a failure must not leave a half-built session behind.
	finalize := func() (ImportResult, error) {
		artifactDir, err := m.Store.ArtifactDirectory(session.ID)
		if err != nil {
			return ImportResult{}, err
		}
		artifactPath := filepath.Join(artifactDir, "capture.pcapng")
		if err := copyFile(pending.path, artifactPath, 0o640); err != nil {
			return ImportResult{}, err
		}
		status := WorkerStatus{
			Schema: SchemaVersion, SessionID: session.ID, State: StateCompleted,
			StartedAt: now, EndedAt: now, UpdatedAt: now, StopReason: "imported capture",
			PacketsCaptured: stats.packets, PacketsReceived: stats.packets,
		}
		if err := m.Store.WriteWorkerStatus(status); err != nil {
			return ImportResult{}, err
		}
		manifest, err := m.Store.CollectFiles(session.ID, now)
		if err != nil {
			return ImportResult{}, err
		}
		if len(manifest.Files) != 1 {
			return ImportResult{}, errors.New("imported capture did not store exactly one artifact")
		}
		if err := m.Store.WriteManifest(manifest); err != nil {
			return ImportResult{}, err
		}
		os.Remove(pending.path)
		return ImportResult{
			SessionID: session.ID, Packets: stats.packets, SizeBytes: size,
			LinkTypes: stats.linkTypes, FirstPacket: stats.first, LastPacket: stats.last,
			TruncatedBytes: truncatedBytes,
		}, nil
	}
	result, err := finalize()
	if err != nil {
		if directory, dirErr := m.Store.SessionDirectory(session.ID); dirErr == nil {
			os.RemoveAll(directory)
		}
		return ImportResult{}, err
	}
	return result, nil
}

type importStats struct {
	packets   uint64
	linkTypes []uint16
	first     time.Time
	last      time.Time
	// completeBytes ends the last whole block: the file size, or less when
	// the last block is cut off.
	completeBytes int64
}

// countingReader counts the bytes read through it; the PCAPNG scanner
// reads blocks without buffering ahead, so the count after a block is
// where that block ends.
type countingReader struct {
	reader io.Reader
	read   int64
}

func (c *countingReader) Read(buffer []byte) (int, error) {
	read, err := c.reader.Read(buffer)
	c.read += int64(read)
	return read, err
}

// inspectImport validates the file is a well-formed .pcapng of an importable
// link type and gathers its packet count, link types and time span. It never
// trusts the content; a malformed file is refused, not stored.
func inspectImport(path string) (importStats, error) {
	file, err := os.Open(path)
	if err != nil {
		return importStats{}, err
	}
	defer file.Close()

	header := make([]byte, 4)
	if _, err := io.ReadFull(file, header); err != nil {
		return importStats{}, ErrNotCapture
	}
	switch {
	case header[0] == 0x0a && header[1] == 0x0d && header[2] == 0x0d && header[3] == 0x0a:
		// PCAPNG section header block.
	case isClassicPCAPMagic(header):
		return importStats{}, ErrClassicPCAP
	default:
		return importStats{}, ErrNotCapture
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return importStats{}, err
	}

	stats := importStats{}
	seen := map[uint16]bool{}
	counter := &countingReader{reader: file}
	scanErr := pcapng.ScanPackets(context.Background(), counter, func(packet pcapng.Packet) error {
		stats.completeBytes = counter.read
		if !importableLinkTypes[packet.LinkType] {
			return fmt.Errorf("the capture uses link type %d, which ShakerProxy cannot analyze", packet.LinkType)
		}
		if !seen[packet.LinkType] {
			seen[packet.LinkType] = true
			stats.linkTypes = append(stats.linkTypes, packet.LinkType)
		}
		stats.packets++
		if !packet.At.IsZero() {
			if stats.first.IsZero() || packet.At.Before(stats.first) {
				stats.first = packet.At.UTC()
			}
			if packet.At.After(stats.last) {
				stats.last = packet.At.UTC()
			}
		}
		return nil
	})
	if scanErr != nil && !errors.Is(scanErr, io.ErrUnexpectedEOF) {
		if errors.Is(scanErr, pcapng.ErrInvalidPCAPNG) {
			return importStats{}, ErrNotCapture
		}
		return importStats{}, scanErr
	}
	if scanErr == nil {
		// Every block is whole, including any after the last packet.
		stats.completeBytes = counter.read
	}
	if stats.packets < 1 {
		return importStats{}, errors.New("the capture holds no packets")
	}
	sort.Slice(stats.linkTypes, func(i, j int) bool { return stats.linkTypes[i] < stats.linkTypes[j] })
	return stats, nil
}

func isClassicPCAPMagic(header []byte) bool {
	switch {
	case header[0] == 0xa1 && header[1] == 0xb2 && header[2] == 0xc3 && header[3] == 0xd4, // microsecond, big-endian
		header[0] == 0xd4 && header[1] == 0xc3 && header[2] == 0xb2 && header[3] == 0xa1, // microsecond, little-endian
		header[0] == 0xa1 && header[1] == 0xb2 && header[2] == 0x3c && header[3] == 0x4d, // nanosecond, big-endian
		header[0] == 0x4d && header[1] == 0x3c && header[2] == 0xb2 && header[3] == 0xa1: // nanosecond, little-endian
		return true
	}
	return false
}

func importStartRequest(name, description, administrator string) StartRequest {
	return StartRequest{
		Name: name, Description: description, Mode: ModeFull,
		SegmentSizeMiB: importSegmentSizeMiB, MaxFiles: importMaxFiles, StopAfterSeconds: 10,
		IdempotencyKey: "import-" + mustSuffix(name), Administrator: administrator,
		StartReason: "imported capture", Imported: true,
	}
}

func importOperatingMode(mode string) string {
	if mode == "" {
		return "IMPORTED"
	}
	return mode
}

func importSoftwareVersion(version string) string {
	if version == "" {
		return "imported"
	}
	return version
}

func newImportSessionID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return "capture-" + hex.EncodeToString(raw), nil
}

func mustSuffix(seed string) string {
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err == nil {
		return hex.EncodeToString(raw)
	}
	// rand.Read does not fail in practice; a fixed suffix keeps the key valid.
	return "0000000000000000"
}

func copyFile(source, destination string, mode os.FileMode) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(destination)
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		os.Remove(destination)
		return err
	}
	return out.Close()
}
