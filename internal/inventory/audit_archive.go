package inventory

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

const (
	// AuditArchiveBatch is how many of the oldest audit events move to the
	// archive file when the in-document audit ledger is full.
	AuditArchiveBatch       = MaxAuditEvents / 4
	auditArchiveName        = "inventory-audit-archive.jsonl"
	maxAuditArchiveBytes    = 32 << 20
	MaxAuditPageLimit       = 500
	auditArchiveRotatedName = auditArchiveName + ".1"
)

// ErrCapacity marks a bounded inventory collection that is full. It also
// matches ErrMutationRejected so older callers keep treating it as a rejected
// mutation.
var ErrCapacity = errors.New("inventory capacity reached")

// ErrAuditCursorUnavailable reports a device-audit cursor that is not in the
// retained ledger (it was archived or never existed).
var ErrAuditCursorUnavailable = errors.New("device audit cursor is not in the retained ledger")

type capacityError struct{ message string }

func (e capacityError) Error() string { return e.message }

func (e capacityError) Is(target error) bool {
	return target == ErrCapacity || target == ErrMutationRejected
}

func newCapacityError(format string, args ...any) error {
	return capacityError{message: fmt.Sprintf(format, args...)}
}

// AuditPage is one newest-first page of the retained device audit ledger.
type AuditPage struct {
	Schema         int          `json:"schema"`
	Events         []AuditEvent `json:"events"`
	NextCursor     string       `json:"next_cursor,omitempty"`
	RetainedEvents int          `json:"retained_events"`
	ArchivedEvents uint64       `json:"archived_events"`
}

// AuditPage returns up to limit events older than the event with ID before
// (newest first). An empty before starts at the newest event.
func (s *Store) AuditPage(limit int, before string) (AuditPage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit < 1 || limit > MaxAuditPageLimit {
		return AuditPage{}, fmt.Errorf("device audit limit must be between 1 and %d", MaxAuditPageLimit)
	}
	if before != "" && !auditIDPattern.MatchString(before) {
		return AuditPage{}, ErrAuditCursorUnavailable
	}
	doc, err := s.load()
	if err != nil {
		return AuditPage{}, err
	}
	end := len(doc.AuditEvents)
	if before != "" {
		end = -1
		for index, event := range doc.AuditEvents {
			if event.ID == before {
				end = index
				break
			}
		}
		if end < 0 {
			return AuditPage{}, ErrAuditCursorUnavailable
		}
	}
	start := max(0, end-limit)
	events := make([]AuditEvent, 0, end-start)
	for index := end - 1; index >= start; index-- {
		events = append(events, doc.AuditEvents[index])
	}
	page := AuditPage{Schema: SchemaVersion, Events: events, RetainedEvents: len(doc.AuditEvents), ArchivedEvents: doc.AuditArchivedCount}
	if start > 0 && len(events) > 0 {
		page.NextCursor = events[len(events)-1].ID
	}
	return page, nil
}

// rollAuditArchive moves the oldest batch of audit events out of the document
// so a new event can be appended. The moved events are written to the archive
// file by save before the document is replaced.
func rollAuditArchive(doc *document) {
	batch := min(AuditArchiveBatch, len(doc.AuditEvents))
	if batch == 0 {
		return
	}
	moved := append([]AuditEvent(nil), doc.AuditEvents[:batch]...)
	doc.archive = append(doc.archive, moved...)
	doc.AuditEvents = append([]AuditEvent(nil), doc.AuditEvents[batch:]...)
	doc.AuditArchivedCount += uint64(batch)
	doc.AuditAnchorSHA256 = moved[len(moved)-1].EntrySHA256
}

// appendAuditArchive appends events as JSON lines to the archive next to the
// inventory file and syncs it. The archive rotates once to ".1" when it would
// exceed its size bound, keeping disk use bounded.
func (s *Store) appendAuditArchive(events []AuditEvent) error {
	if len(events) == 0 {
		return nil
	}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	for _, event := range events {
		if err := encoder.Encode(event); err != nil {
			return err
		}
	}
	directory := filepath.Dir(s.Path)
	path := filepath.Join(directory, auditArchiveName)
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return errors.New("device audit archive is not a regular file")
		}
		if info.Size()+int64(buffer.Len()) > maxAuditArchiveBytes {
			if err := os.Rename(path, filepath.Join(directory, auditArchiveRotatedName)); err != nil {
				return fmt.Errorf("rotate device audit archive: %w", err)
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	descriptor, err := unix.Open(path, unix.O_WRONLY|unix.O_APPEND|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("open device audit archive: %w", err)
	}
	file := os.NewFile(uintptr(descriptor), path)
	if _, err := file.Write(buffer.Bytes()); err != nil {
		file.Close()
		return fmt.Errorf("append device audit archive: %w", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

// reconcileFingerprint hashes the inventory evidence while ignoring the
// timestamps every reconciliation refreshes (last seen, observed, reconciled),
// so an unchanged lease set can skip rewriting and fsyncing the whole file.
func reconcileFingerprint(doc document) ([sha256.Size]byte, error) {
	devices := make([]Device, len(doc.Devices))
	for index, device := range doc.Devices {
		device.LastReconciled, device.LastSeen = time.Time{}, time.Time{}
		identities := make([]Identity, len(device.Identities))
		for identityIndex, identity := range device.Identities {
			identity.LastSeen = time.Time{}
			identities[identityIndex] = identity
		}
		device.Identities = identities
		hostnames := make([]HostnameObservation, len(device.Hostnames))
		for hostnameIndex, hostname := range device.Hostnames {
			hostname.LastSeen = time.Time{}
			hostnames[hostnameIndex] = hostname
		}
		device.Hostnames = hostnames
		addresses := make([]AddressObservation, len(device.Addresses))
		for addressIndex, address := range device.Addresses {
			address.ObservedAt = time.Time{}
			addresses[addressIndex] = address
		}
		device.Addresses = addresses
		if device.Vendor != nil {
			vendor := *device.Vendor
			vendor.ObservedAt = time.Time{}
			device.Vendor = &vendor
		}
		devices[index] = device
	}
	encoded, err := json.Marshal(struct {
		Devices []Device       `json:"devices"`
		Aliases []AddressAlias `json:"address_aliases"`
		Audit   int            `json:"audit_events"`
	}{devices, doc.AddressAliases, len(doc.AuditEvents)})
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}
