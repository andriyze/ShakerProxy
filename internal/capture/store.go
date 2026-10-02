package capture

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"shakerproxy.dev/shakerproxy/internal/pcapng"
)

const (
	maxMetadataBytes      = 1 << 20
	maxCaptureFiles       = 128
	maxActiveFeedSegments = 64
)

type Store struct{ Root string }

func (s Store) Validate() error {
	if s.Root == "" || !filepath.IsAbs(s.Root) || filepath.Clean(s.Root) == "/" {
		return errors.New("capture root must be an absolute non-root path")
	}
	return nil
}

func (s Store) Create(session Session) error {
	if err := s.Validate(); err != nil {
		return err
	}
	if err := session.Validate(); err != nil {
		return err
	}
	if err := s.ensureRoot(); err != nil {
		return err
	}
	if deleted, err := s.HasDeletionReceipt(session.ID); err != nil {
		return err
	} else if deleted {
		return errors.New("capture session ID has a deletion receipt")
	}
	directory, err := s.SessionDirectory(session.ID)
	if err != nil {
		return err
	}
	if err := os.Mkdir(directory, 0o770); err != nil {
		return fmt.Errorf("create capture session directory: %w", err)
	}
	// The package-owned setgid root must propagate the dedicated capture group.
	// RestrictSUIDSGID deliberately prevents gatewayd from setting this bit itself.
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSetgid == 0 {
		return errors.New("capture session directory did not inherit safe group ownership")
	}
	artifacts := filepath.Join(directory, "artifacts")
	runtime := filepath.Join(directory, "runtime")
	for _, child := range []string{artifacts, runtime} {
		if err := os.Mkdir(child, 0o770); err != nil {
			return fmt.Errorf("create capture worker directory: %w", err)
		}
		// gatewayd's umask must not remove the deliberate capture-group write bit.
		if err := os.Chmod(child, 0o770); err != nil {
			return fmt.Errorf("set capture worker directory mode: %w", err)
		}
	}
	if err := writeJSONAtomic(directory, "session.json", session, 0o640); err != nil {
		return err
	}
	status := WorkerStatus{Schema: SchemaVersion, SessionID: session.ID, State: StateStarting, UpdatedAt: session.StartedAt}
	return writeJSONAtomic(runtime, "worker-status.json", status, 0o640)
}

func (s Store) SessionDirectory(id string) (string, error) {
	if err := s.Validate(); err != nil {
		return "", err
	}
	if !ValidSessionID(id) {
		return "", errors.New("invalid capture session ID")
	}
	return filepath.Join(s.Root, id), nil
}

func (s Store) ReadSession(id string) (Session, error) {
	var session Session
	if err := s.readJSON(id, "session.json", &session); err != nil {
		return session, err
	}
	if session.ID != id || session.Validate() != nil {
		return Session{}, errors.New("stored capture session is invalid")
	}
	return session, nil
}

func (s Store) ReadWorkerStatus(id string) (WorkerStatus, error) {
	var status WorkerStatus
	if err := s.readJSON(id, "worker-status.json", &status); err != nil {
		return status, err
	}
	if status.Schema != SchemaVersion || status.SessionID != id {
		return WorkerStatus{}, errors.New("stored capture worker status is invalid")
	}
	return status, nil
}

func (s Store) WriteWorkerStatus(status WorkerStatus) error {
	if status.Schema != SchemaVersion || !ValidSessionID(status.SessionID) {
		return errors.New("capture worker status identity is invalid")
	}
	directory, err := s.RuntimeDirectory(status.SessionID)
	if err != nil {
		return err
	}
	return writeJSONAtomic(directory, "worker-status.json", status, 0o640)
}

func (s Store) ReadManifest(id string) (Manifest, error) {
	var manifest Manifest
	if err := s.readJSON(id, "manifest.json", &manifest); err != nil {
		return manifest, err
	}
	if manifest.Schema != SchemaVersion || manifest.SessionID != id {
		return Manifest{}, errors.New("stored capture manifest is invalid")
	}
	return manifest, nil
}

func (s Store) WriteManifest(manifest Manifest) error {
	if manifest.Schema != SchemaVersion || !ValidSessionID(manifest.SessionID) {
		return errors.New("capture manifest identity is invalid")
	}
	directory, err := s.RuntimeDirectory(manifest.SessionID)
	if err != nil {
		return err
	}
	return writeJSONAtomic(directory, "manifest.json", manifest, 0o640)
}

func (s Store) ReadActiveSegmentFeed(id string) (ActiveSegmentFeed, error) {
	var feed ActiveSegmentFeed
	if err := s.readJSON(id, "active-segments.json", &feed); err != nil {
		return feed, err
	}
	if err := validateActiveSegmentFeed(feed, id); err != nil {
		return ActiveSegmentFeed{}, err
	}
	return feed, nil
}

func (s Store) PublishClosedSegment(id, name string, closedAt time.Time) (ActiveSegmentFeed, error) {
	if !ValidSessionID(id) || !captureFileName(name) || name != filepath.Base(name) || closedAt.IsZero() {
		return ActiveSegmentFeed{}, errors.New("closed capture segment identity is invalid")
	}
	session, err := s.ReadSession(id)
	if err != nil {
		return ActiveSegmentFeed{}, err
	}
	status, err := s.ReadWorkerStatus(id)
	if err != nil || status.State != StateRunning {
		return ActiveSegmentFeed{}, errors.New("closed capture segments may only be published while capture is running")
	}
	artifactDirectory, err := s.ArtifactDirectory(id)
	if err != nil {
		return ActiveSegmentFeed{}, err
	}
	path := filepath.Join(artifactDirectory, name)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 {
		return ActiveSegmentFeed{}, errors.New("closed capture segment is not a non-empty regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return ActiveSegmentFeed{}, err
	}
	opened, statErr := file.Stat()
	var readErr error
	if statErr == nil {
		readErr = grantAnalyzerRead(file, opened)
	}
	closeErr := file.Close()
	if readErr != nil {
		return ActiveSegmentFeed{}, readErr
	}
	if statErr != nil || closeErr != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) || opened.Size() != info.Size() || !opened.ModTime().Equal(info.ModTime()) {
		return ActiveSegmentFeed{}, errors.New("closed capture segment changed during publication")
	}
	feed, err := s.ReadActiveSegmentFeed(id)
	if errors.Is(err, os.ErrNotExist) {
		feed = ActiveSegmentFeed{Schema: SchemaVersion, SessionID: id, Segments: []ClosedCaptureSegment{}}
	} else if err != nil {
		return ActiveSegmentFeed{}, err
	}
	for _, existing := range feed.Segments {
		if existing.Name != name {
			continue
		}
		if existing.SizeBytes == info.Size() && existing.Modified.Equal(info.ModTime()) {
			return feed, nil
		}
		return ActiveSegmentFeed{}, errors.New("closed capture segment name was reused with different metadata")
	}
	feed.Revision++
	feed.PublishedAt = closedAt.UTC()
	feed.Segments = append(feed.Segments, ClosedCaptureSegment{Sequence: feed.Revision, Name: name, SizeBytes: info.Size(), Modified: info.ModTime().UTC(), ClosedAt: closedAt.UTC()})
	limit := session.Request.MaxFiles
	if limit > maxActiveFeedSegments {
		limit = maxActiveFeedSegments
	}
	if overflow := len(feed.Segments) - limit; overflow > 0 {
		feed.EvictedSegments += uint64(overflow)
		feed.Segments = append([]ClosedCaptureSegment(nil), feed.Segments[overflow:]...)
	}
	if err := validateActiveSegmentFeed(feed, id); err != nil {
		return ActiveSegmentFeed{}, err
	}
	runtimeDirectory, err := s.RuntimeDirectory(id)
	if err != nil {
		return ActiveSegmentFeed{}, err
	}
	if err := writeJSONAtomic(runtimeDirectory, "active-segments.json", feed, 0o640); err != nil {
		return ActiveSegmentFeed{}, err
	}
	return feed, nil
}

func validateActiveSegmentFeed(feed ActiveSegmentFeed, sessionID string) error {
	if feed.Schema != SchemaVersion || feed.SessionID != sessionID || !ValidSessionID(sessionID) || feed.Revision == 0 || feed.PublishedAt.IsZero() || len(feed.Segments) < 1 || len(feed.Segments) > maxActiveFeedSegments || feed.EvictedSegments > feed.Revision {
		return errors.New("active capture segment feed is invalid")
	}
	seen := make(map[string]struct{}, len(feed.Segments))
	var previousSequence uint64
	for _, segment := range feed.Segments {
		if segment.Sequence == 0 || segment.Sequence > feed.Revision || segment.Sequence <= previousSequence || !captureFileName(segment.Name) || segment.Name != filepath.Base(segment.Name) || segment.SizeBytes < 1 || segment.Modified.IsZero() || segment.ClosedAt.IsZero() || segment.ClosedAt.After(feed.PublishedAt) {
			return errors.New("active capture segment feed member is invalid")
		}
		if _, exists := seen[segment.Name]; exists {
			return errors.New("active capture segment feed contains duplicate names")
		}
		seen[segment.Name] = struct{}{}
		previousSequence = segment.Sequence
	}
	return nil
}

func (s Store) ListSessionIDs() ([]string, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(s.Root)
	if errors.Is(err, os.ErrNotExist) {
		return []string{}, nil
	}
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() && ValidSessionID(entry.Name()) {
			ids = append(ids, entry.Name())
		}
	}
	sort.Strings(ids)
	return ids, nil
}

func (s Store) CollectFiles(id string, now time.Time) (Manifest, error) {
	session, err := s.ReadSession(id)
	if err != nil {
		return Manifest{}, err
	}
	directory, err := s.ArtifactDirectory(id)
	if err != nil {
		return Manifest{}, err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return Manifest{}, err
	}
	manifest := Manifest{Schema: SchemaVersion, SessionID: id, CreatedAt: now.UTC()}
	sessionDirectory, err := s.SessionDirectory(id)
	if err != nil {
		return Manifest{}, err
	}
	sessionBytes, err := os.ReadFile(filepath.Join(sessionDirectory, "session.json"))
	if err != nil || len(sessionBytes) > maxMetadataBytes {
		return Manifest{}, errors.New("capture session provenance is unavailable")
	}
	sessionSum := sha256.Sum256(sessionBytes)
	manifest.SessionSHA256 = hex.EncodeToString(sessionSum[:])
	for _, entry := range entries {
		if entry.IsDir() || !captureFileName(entry.Name()) {
			continue
		}
		if len(manifest.Files) >= maxCaptureFiles {
			return Manifest{}, errors.New("capture file count exceeds safety limit")
		}
		path := filepath.Join(directory, entry.Name())
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			return Manifest{}, errors.New("capture artifact is not a regular file")
		}
		file, err := os.Open(path)
		if err != nil {
			return Manifest{}, err
		}
		opened, err := file.Stat()
		if err != nil || !os.SameFile(info, opened) || opened.Size() != info.Size() || !opened.ModTime().Equal(info.ModTime()) {
			file.Close()
			return Manifest{}, errors.New("capture artifact changed while it was opened")
		}
		if err := grantAnalyzerRead(file, opened); err != nil {
			file.Close()
			return Manifest{}, err
		}
		hash := sha256.New()
		contents := io.TeeReader(file, hash)
		membership, membershipErr := pcapng.Inspect(contents)
		_, copyErr := io.Copy(io.Discard, contents)
		after, statErr := file.Stat()
		closeErr := file.Close()
		if copyErr != nil || statErr != nil || closeErr != nil {
			return Manifest{}, errors.Join(copyErr, statErr, closeErr)
		}
		if !os.SameFile(opened, after) || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
			return Manifest{}, errors.New("capture artifact changed during membership inspection")
		}
		if membershipErr != nil {
			if !errors.Is(membershipErr, pcapng.ErrInvalidPCAPNG) {
				return Manifest{}, membershipErr
			}
			membership = pcapng.Unavailable(pcapng.MembershipInvalidPCAPNG)
		}
		manifest.Files = append(manifest.Files, CaptureFile{Name: entry.Name(), SizeBytes: info.Size(), SHA256: hex.EncodeToString(hash.Sum(nil)), Modified: info.ModTime().UTC(), PacketMembership: &membership})
		manifest.TotalSizeBytes += info.Size()
	}
	sort.Slice(manifest.Files, func(i, j int) bool { return manifest.Files[i].Name < manifest.Files[j].Name })
	if status, statusErr := s.ReadWorkerStatus(id); statusErr == nil {
		manifest.PacketsCaptured = status.PacketsCaptured
		manifest.PacketsReceived = status.PacketsReceived
		manifest.KernelDrops = status.KernelDrops
		manifest.DumpcapDrops = status.DumpcapDrops
	}
	if manifest.TotalSizeBytes > int64(session.Request.SegmentSizeMiB*session.Request.MaxFiles+session.Request.SegmentSizeMiB)*1<<20 {
		return Manifest{}, errors.New("capture artifacts exceed the bounded ring allowance")
	}
	return manifest, nil
}

func (s Store) Usage(id string) (int, int64, error) {
	directory, err := s.ArtifactDirectory(id)
	if err != nil {
		return 0, 0, err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return 0, 0, err
	}
	count := 0
	var bytes int64
	for _, entry := range entries {
		if entry.IsDir() || !captureFileName(entry.Name()) {
			continue
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return 0, 0, errors.New("capture artifact is not a regular file")
		}
		count++
		bytes += info.Size()
	}
	return count, bytes, nil
}

func (s Store) ReadArtifactChunk(id, requestedName string, offset int64, length int) (ArtifactChunk, error) {
	if offset < 0 || length < 1 || length > MaxArtifactChunkBytes {
		return ArtifactChunk{}, errors.New("capture artifact range is invalid")
	}
	if !captureFileName(requestedName) || strings.ContainsAny(requestedName, `/\`) {
		return ArtifactChunk{}, errors.New("capture artifact name is invalid")
	}
	manifest, err := s.ReadManifest(id)
	if err != nil {
		return ArtifactChunk{}, errors.New("capture artifact manifest is unavailable")
	}
	var selected *CaptureFile
	for index := range manifest.Files {
		if manifest.Files[index].Name == requestedName {
			selected = &manifest.Files[index]
			break
		}
	}
	if selected == nil || !captureFileName(selected.Name) || strings.Contains(selected.Name, "/") || strings.Contains(selected.Name, `\`) {
		return ArtifactChunk{}, errors.New("capture artifact is not present in the final manifest")
	}
	if offset >= selected.SizeBytes {
		return ArtifactChunk{}, errors.New("capture artifact range starts beyond the file")
	}
	directory, err := s.ArtifactDirectory(id)
	if err != nil {
		return ArtifactChunk{}, err
	}
	path := filepath.Join(directory, selected.Name)
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() != selected.SizeBytes || !before.ModTime().Equal(selected.Modified) {
		return ArtifactChunk{}, errors.New("capture artifact no longer matches its manifest")
	}
	file, err := os.Open(path)
	if err != nil {
		return ArtifactChunk{}, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || after.Size() != selected.SizeBytes || !after.ModTime().Equal(selected.Modified) {
		return ArtifactChunk{}, errors.New("capture artifact changed during validation")
	}
	remaining := selected.SizeBytes - offset
	if int64(length) > remaining {
		length = int(remaining)
	}
	data := make([]byte, length)
	n, readErr := file.ReadAt(data, offset)
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return ArtifactChunk{}, readErr
	}
	data = data[:n]
	return ArtifactChunk{SessionID: id, FileName: selected.Name, FileSHA256: selected.SHA256, Offset: offset, TotalBytes: selected.SizeBytes, Data: data, EOF: offset+int64(n) == selected.SizeBytes}, nil
}

func (s Store) AvailableBytes() (uint64, error) {
	if err := s.Validate(); err != nil {
		return 0, err
	}
	if err := s.ensureRoot(); err != nil {
		return 0, err
	}
	var stat syscall.Statfs_t
	if err := syscall.Statfs(s.Root, &stat); err != nil {
		return 0, err
	}
	return stat.Bavail * uint64(stat.Bsize), nil
}

func (s Store) ensureRoot() error {
	info, err := os.Lstat(s.Root)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(s.Root, 0o770); err != nil {
			return err
		}
		if err := os.Chmod(s.Root, os.ModeSetgid|0o770); err != nil {
			return err
		}
		info, err = os.Lstat(s.Root)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSetgid == 0 {
		return errors.New("capture storage root is not a safe setgid directory")
	}
	return nil
}

func (s Store) readJSON(id, name string, dst any) error {
	directory, err := s.SessionDirectory(id)
	if err != nil {
		return err
	}
	if name == "worker-status.json" || name == "manifest.json" || name == "active-segments.json" {
		directory = filepath.Join(directory, "runtime")
	}
	path := filepath.Join(directory, name)
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > maxMetadataBytes {
		return errors.New("capture metadata is not a bounded regular file")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("capture metadata contains multiple JSON values")
	}
	return nil
}

func (s Store) ArtifactDirectory(id string) (string, error) {
	directory, err := s.SessionDirectory(id)
	if err != nil {
		return "", err
	}
	return filepath.Join(directory, "artifacts"), nil
}

func (s Store) RuntimeDirectory(id string) (string, error) {
	directory, err := s.SessionDirectory(id)
	if err != nil {
		return "", err
	}
	return filepath.Join(directory, "runtime"), nil
}

func writeJSONAtomic(directory, name string, value any, mode os.FileMode) error {
	if strings.Contains(name, "/") || name == "" {
		return errors.New("invalid capture metadata filename")
	}
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if len(b) > maxMetadataBytes {
		return errors.New("capture metadata exceeds size limit")
	}
	temporary, err := os.CreateTemp(directory, ".metadata-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(b); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, filepath.Join(directory, name)); err != nil {
		return err
	}
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func captureFileName(name string) bool {
	return strings.HasPrefix(name, "capture_") && strings.HasSuffix(name, ".pcapng") || name == "capture.pcapng"
}

// ShareActiveSegment lets the capture group, and so the Zeek analyzer
// container, read the segment dumpcap has just started, so live analysis can
// follow it while it is written. dumpcap creates it 0600; it becomes 0640,
// narrower than the 0644 a closed segment gets, and the analyzer only pipes
// its packets to the isolated parser. Like grantAnalyzerRead, it changes the
// open file, never a path.
func (s Store) ShareActiveSegment(id, name string) error {
	if !ValidSessionID(id) || !captureFileName(name) || name != filepath.Base(name) {
		return errors.New("active capture segment identity is invalid")
	}
	artifactDirectory, err := s.ArtifactDirectory(id)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(filepath.Join(artifactDirectory, name), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("active capture segment is not a regular file")
	}
	if info.Mode().Perm()&0o040 != 0 {
		return nil
	}
	return file.Chmod(info.Mode().Perm() | 0o040)
}

// grantAnalyzerRead makes a sealed segment readable by the analyzers. dumpcap
// always creates its files 0600. The analyzer hands its isolated parser
// (uid 65533, no groups) only an open descriptor, but Zeek and Suricata reopen
// it through /proc/self/fd, which checks the file mode, so the file must be
// world-readable. Nothing can reach it by path: every capture directory
// denies other users (2770/2750/0770, group shakerproxy-capture). It changes
// the open file, never a path.
func grantAnalyzerRead(file *os.File, info os.FileInfo) error {
	if info.Mode().Perm() == 0o644 {
		return nil
	}
	if err := file.Chmod(0o644); err != nil {
		return fmt.Errorf("grant analyzers read access to %s: %w", filepath.Base(file.Name()), err)
	}
	return nil
}
