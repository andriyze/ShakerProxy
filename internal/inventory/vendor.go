package inventory

import (
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

const (
	MaxVendorFileBytes           = 32 << 20
	MaxVendorRecords             = 200000
	DefaultVendorRefreshInterval = time.Hour
)

type VendorState string

const (
	VendorStateMatched             VendorState = "MATCHED"
	VendorStateNoMatch             VendorState = "NO_MATCH"
	VendorStateLocallyAdministered VendorState = "LOCALLY_ADMINISTERED"
	VendorStateAmbiguous           VendorState = "AMBIGUOUS"
)

type VendorObservation struct {
	Name           string    `json:"name"`
	Registry       string    `json:"registry"`
	Assignment     string    `json:"assignment"`
	Confidence     int       `json:"confidence"`
	DatabaseSHA256 string    `json:"database_sha256"`
	ObservedAt     time.Time `json:"observed_at"`
}

type VendorLookup struct {
	State          VendorState
	Name           string
	Registry       string
	Assignment     string
	DatabaseSHA256 string
}

type VendorResolver interface {
	LookupMAC(string) (VendorLookup, error)
}

type vendorEntry struct {
	name           string
	registry       string
	assignment     string
	databaseSHA256 string
	ambiguous      bool
}

type VendorRegistry struct {
	Directory       string
	RefreshInterval time.Duration
	Now             func() time.Time

	mu       sync.Mutex
	loadedAt time.Time
	entries  map[string]vendorEntry
}

var assignmentPattern = regexp.MustCompile(`^[0-9A-F]+$`)

func (r *VendorRegistry) LookupMAC(value string) (VendorLookup, error) {
	if r == nil {
		return VendorLookup{}, errors.New("vendor registry is required")
	}
	parsed, err := net.ParseMAC(value)
	if err != nil || len(parsed) != 6 {
		return VendorLookup{}, errors.New("vendor lookup MAC is invalid")
	}
	if parsed[0]&0x01 != 0 {
		return VendorLookup{}, errors.New("vendor lookup MAC must be unicast")
	}
	if parsed[0]&0x02 != 0 {
		return VendorLookup{State: VendorStateLocallyAdministered}, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now().UTC()
	if r.Now != nil {
		now = r.Now().UTC()
	}
	interval := r.RefreshInterval
	if interval == 0 {
		interval = DefaultVendorRefreshInterval
	}
	if interval < time.Minute || interval > 24*time.Hour || r.Directory == "" || !filepath.IsAbs(r.Directory) {
		return VendorLookup{}, errors.New("vendor registry configuration is invalid")
	}
	if r.entries == nil || now.Before(r.loadedAt) || now.Sub(r.loadedAt) >= interval {
		entries, loadErr := loadVendorRegistry(r.Directory)
		if loadErr != nil {
			r.entries = nil
			return VendorLookup{}, loadErr
		}
		r.entries, r.loadedAt = entries, now
	}
	macHex := strings.ToUpper(hex.EncodeToString(parsed))
	for _, digits := range []int{9, 7, 6} {
		entry, ok := r.entries[macHex[:digits]]
		if !ok {
			continue
		}
		if entry.ambiguous {
			return VendorLookup{State: VendorStateAmbiguous, Registry: entry.registry, Assignment: entry.assignment, DatabaseSHA256: entry.databaseSHA256}, nil
		}
		return VendorLookup{State: VendorStateMatched, Name: entry.name, Registry: entry.registry, Assignment: entry.assignment, DatabaseSHA256: entry.databaseSHA256}, nil
	}
	return VendorLookup{State: VendorStateNoMatch}, nil
}

func loadVendorRegistry(directory string) (map[string]vendorEntry, error) {
	entries := make(map[string]vendorEntry)
	for _, source := range []struct {
		name     string
		registry string
		digits   int
	}{{"oui.csv", "MA-L", 6}, {"mam.csv", "MA-M", 7}, {"oui36.csv", "MA-S", 9}} {
		data, digest, err := readVendorFile(filepath.Join(directory, source.name))
		if err != nil {
			return nil, fmt.Errorf("read IEEE %s registry: %w", source.registry, err)
		}
		if err := parseVendorCSV(data, source.registry, source.digits, digest, entries); err != nil {
			return nil, fmt.Errorf("parse IEEE %s registry: %w", source.registry, err)
		}
	}
	return entries, nil
}

func readVendorFile(path string) ([]byte, string, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 2 || info.Size() > MaxVendorFileBytes {
		return nil, "", errors.New("registry is not a bounded regular file")
	}
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, "", errors.New("registry could not be opened safely")
	}
	file := os.NewFile(uintptr(descriptor), filepath.Base(path))
	if file == nil {
		unix.Close(descriptor)
		return nil, "", errors.New("registry descriptor is invalid")
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) || openedInfo.Size() < 2 || openedInfo.Size() > MaxVendorFileBytes {
		return nil, "", errors.New("registry changed during validation")
	}
	data, err := io.ReadAll(io.LimitReader(file, MaxVendorFileBytes+1))
	if err != nil || len(data) > MaxVendorFileBytes || int64(len(data)) != openedInfo.Size() || !utf8.Valid(data) {
		return nil, "", errors.New("registry content is invalid or exceeds its limit")
	}
	finalInfo, err := file.Stat()
	if err != nil || !os.SameFile(openedInfo, finalInfo) || finalInfo.Size() != openedInfo.Size() || !finalInfo.ModTime().Equal(openedInfo.ModTime()) {
		return nil, "", errors.New("registry changed while it was read")
	}
	digest := sha256.Sum256(data)
	return data, hex.EncodeToString(digest[:]), nil
}

func parseVendorCSV(data []byte, registry string, digits int, digest string, entries map[string]vendorEntry) error {
	reader := csv.NewReader(bytes.NewReader(data))
	reader.FieldsPerRecord = 4
	header, err := reader.Read()
	if err != nil || !sameStrings(header, []string{"Registry", "Assignment", "Organization Name", "Organization Address"}) {
		return errors.New("registry header is invalid")
	}
	records := 0
	for {
		record, readErr := reader.Read()
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return readErr
		}
		records++
		if records > MaxVendorRecords {
			return errors.New("registry record limit exceeded")
		}
		assignment := strings.ToUpper(strings.TrimSpace(record[1]))
		name := strings.TrimSpace(record[2])
		if record[0] != registry || len(assignment) != digits || !assignmentPattern.MatchString(assignment) || !validSingleLine(name, 1, 256) || len(record[3]) > 4096 {
			return errors.New("registry record is invalid")
		}
		entry := vendorEntry{name: name, registry: registry, assignment: assignment, databaseSHA256: digest}
		if existing, duplicate := entries[assignment]; duplicate {
			if existing.name != entry.name || existing.registry != entry.registry {
				entry.ambiguous = true
				entries[assignment] = entry
			}
			continue
		}
		entries[assignment] = entry
	}
	if records == 0 {
		return errors.New("registry contains no assignments")
	}
	return nil
}

func applyVendor(device *Device, resolver VendorResolver, observedAt time.Time) error {
	if resolver == nil {
		return nil
	}
	lookups := make(map[string]VendorLookup)
	local := false
	for _, identity := range device.Identities {
		if identity.Kind != IdentityMAC {
			continue
		}
		lookup, err := resolver.LookupMAC(identity.Value)
		if err != nil {
			return err
		}
		if lookup.State == VendorStateLocallyAdministered {
			local = true
			continue
		}
		if lookup.State == VendorStateMatched {
			lookups[lookup.Registry+"\x00"+lookup.Assignment+"\x00"+lookup.Name] = lookup
		} else if lookup.State == VendorStateAmbiguous {
			device.VendorState, device.Vendor = VendorStateAmbiguous, nil
			return nil
		}
	}
	if len(lookups) > 1 {
		device.VendorState, device.Vendor = VendorStateAmbiguous, nil
		return nil
	}
	for _, lookup := range lookups {
		device.VendorState = VendorStateMatched
		device.Vendor = &VendorObservation{Name: lookup.Name, Registry: lookup.Registry, Assignment: lookup.Assignment, Confidence: 80, DatabaseSHA256: lookup.DatabaseSHA256, ObservedAt: observedAt.UTC()}
		return nil
	}
	device.Vendor = nil
	if local {
		device.VendorState = VendorStateLocallyAdministered
	} else {
		device.VendorState = VendorStateNoMatch
	}
	return nil
}
