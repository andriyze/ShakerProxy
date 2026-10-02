package inventory

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const maxInventoryBytes = 64 << 20

type document struct {
	Schema         int            `json:"schema"`
	UpdatedAt      time.Time      `json:"updated_at"`
	EvidenceAsOf   time.Time      `json:"evidence_as_of"`
	Devices        []Device       `json:"devices"`
	AddressAliases []AddressAlias `json:"address_aliases,omitempty"`
	AuditEvents    []AuditEvent   `json:"audit_events,omitempty"`
	// AuditArchivedCount and AuditAnchorSHA256 describe audit events moved to
	// the append-only archive file. The anchor is the entry hash of the last
	// archived event, so the retained hash chain stays verifiable.
	AuditArchivedCount uint64 `json:"audit_archived_count,omitempty"`
	AuditAnchorSHA256  string `json:"audit_anchor_sha256,omitempty"`
	// archive holds events rolled out of AuditEvents by this mutation; save
	// appends them to the archive file before replacing the document.
	archive []AuditEvent
}

type Store struct {
	Path    string
	Now     func() time.Time
	Random  func([]byte) (int, error)
	Vendors VendorResolver
	mu      sync.Mutex
	// pending is a reconciled document whose only changes are refresh
	// timestamps (last seen, observed, reconciled). It is served by load()
	// instead of the file and written by the next save.
	pending *pendingDocument
}

type pendingDocument struct {
	encoded []byte
	// base is the inventory file the pending document was derived from (nil
	// when no file existed); a different file on disk discards the pending
	// document.
	base                  fs.FileInfo
	persistedEvidenceAsOf time.Time
}

// reconcileHeartbeat bounds how long refresh-only reconciliation results stay
// in memory before they are written to disk.
const reconcileHeartbeat = 5 * time.Minute

func (s *Store) ReconcileDHCP4(leases []DHCP4Lease) (Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	doc, err := s.load()
	if err != nil {
		return Snapshot{}, err
	}
	if len(doc.Devices) > MaxDevices {
		return Snapshot{}, errors.New("device inventory limit exceeded")
	}
	persistedEvidenceAsOf := doc.EvidenceAsOf
	if s.pending != nil {
		persistedEvidenceAsOf = s.pending.persistedEvidenceAsOf
	}
	before, err := reconcileFingerprint(doc)
	if err != nil {
		return Snapshot{}, err
	}
	macIndex, clientIndex := identityIndexes(doc.Devices)
	seenActive := make(map[string]bool)
	for deviceIndex := range doc.Devices {
		for addressIndex := range doc.Devices[deviceIndex].Addresses {
			doc.Devices[deviceIndex].Addresses[addressIndex].Active = false
		}
		refreshNeighborActivity(&doc.Devices[deviceIndex], now)
	}
	for _, lease := range leases {
		deviceIndex, macMatched, clientMatched := -1, false, false
		clientDeviceIndex := -1
		if lease.HardwareAddr != "" {
			if matchedIndex, ok := macIndex[lease.HardwareAddr]; ok {
				deviceIndex, macMatched = matchedIndex, true
			}
		}
		if lease.ClientID != "" {
			if matchedIndex, ok := clientIndex[lease.ClientID]; ok {
				clientDeviceIndex, clientMatched = matchedIndex, true
			}
			if !macMatched && clientMatched {
				deviceIndex = clientDeviceIndex
			}
		}
		if deviceIndex < 0 {
			if index, ok := pinnedDevice(doc.Devices, lease.Address); ok {
				deviceIndex = index
			}
		}
		if deviceIndex < 0 {
			if len(doc.Devices) >= MaxDevices {
				return Snapshot{}, errors.New("device inventory limit exceeded")
			}
			id, idErr := s.newUniqueDeviceID(doc.Devices)
			if idErr != nil {
				return Snapshot{}, idErr
			}
			firstSeen := lease.ExpiresAt.Add(-lease.ValidLifetime)
			if firstSeen.After(now) {
				firstSeen = now
			}
			doc.Devices = append(doc.Devices, Device{Schema: SchemaVersion, ID: id, FirstSeen: firstSeen, LastSeen: firstSeen, LastReconciled: now})
			deviceIndex = len(doc.Devices) - 1
		}
		device := &doc.Devices[deviceIndex]
		firstObserved := lease.ExpiresAt.Add(-lease.ValidLifetime)
		if firstObserved.After(now) {
			firstObserved = now
		}
		lastObserved := lease.ExpiresAt
		if lastObserved.After(now) {
			lastObserved = now
		}
		if lease.Active(now) {
			seenActive[device.ID] = true
		}
		if lease.HardwareAddr != "" {
			upsertIdentity(device, IdentityMAC, lease.HardwareAddr, 95, firstObserved, lastObserved)
			macIndex[lease.HardwareAddr] = deviceIndex
		}
		if lease.ClientID != "" && (!clientMatched || clientDeviceIndex == deviceIndex) {
			upsertIdentity(device, IdentityDHCPClientID, lease.ClientID, 85, firstObserved, lastObserved)
			clientIndex[lease.ClientID] = deviceIndex
		} else if lease.ClientID != "" && clientMatched && clientDeviceIndex != deviceIndex {
			addWarning(device, fmt.Sprintf("DHCP client identity conflicts with %s; devices were not merged", doc.Devices[clientDeviceIndex].ID))
			addWarning(&doc.Devices[clientDeviceIndex], fmt.Sprintf("DHCP client identity appeared with %s; devices were not merged", device.ID))
		}
		confidence := 85
		if lease.HardwareAddr != "" {
			confidence = 95
		}
		upsertAddress(device, lease, confidence, now)
		if lease.Hostname != "" {
			upsertHostname(device, lease.Hostname, 75, firstObserved, lastObserved)
		}
		if firstObserved.Before(device.FirstSeen) {
			device.FirstSeen = firstObserved
		}
		if lastObserved.After(device.LastSeen) {
			device.LastSeen = lastObserved
		}
		if confidence > device.AttributionConfidence {
			device.AttributionConfidence = confidence
		}
		device.LastReconciled = now
	}
	for index := range doc.Devices {
		doc.Devices[index].Online = seenActive[doc.Devices[index].ID] || hasActiveNeighborAddress(doc.Devices[index])
		doc.Devices[index].LastReconciled = now
		sortDeviceEvidence(&doc.Devices[index])
		if err := applyVendor(&doc.Devices[index], s.Vendors, now); err != nil {
			return Snapshot{}, fmt.Errorf("enrich device %s vendor: %w", doc.Devices[index].ID, err)
		}
		if err := validateDevice(doc.Devices[index]); err != nil {
			return Snapshot{}, fmt.Errorf("validate device %s: %w", doc.Devices[index].ID, err)
		}
	}
	refreshFriendlyNameConflicts(doc.Devices)
	sort.Slice(doc.Devices, func(i, j int) bool {
		if doc.Devices[i].Online != doc.Devices[j].Online {
			return doc.Devices[i].Online
		}
		if !doc.Devices[i].LastSeen.Equal(doc.Devices[j].LastSeen) {
			return doc.Devices[i].LastSeen.After(doc.Devices[j].LastSeen)
		}
		return doc.Devices[i].ID < doc.Devices[j].ID
	})
	after, err := reconcileFingerprint(doc)
	if err != nil {
		return Snapshot{}, err
	}
	doc.Schema = SchemaVersion
	doc.EvidenceAsOf = now
	if before == after && !persistedEvidenceAsOf.IsZero() && !now.Before(persistedEvidenceAsOf) && now.Sub(persistedEvidenceAsOf) < reconcileHeartbeat {
		// Only refresh timestamps changed: keep the result in memory and skip
		// rewriting and fsyncing the (potentially large) inventory file.
		if err := s.keepPending(doc, persistedEvidenceAsOf); err != nil {
			return Snapshot{}, err
		}
		return snapshot(doc, now), nil
	}
	doc.UpdatedAt = now
	if err := s.save(doc); err != nil {
		return Snapshot{}, err
	}
	return snapshot(doc, now), nil
}

func (s *Store) keepPending(doc document, persistedEvidenceAsOf time.Time) error {
	encoded, err := json.Marshal(doc)
	if err != nil || len(encoded) > maxInventoryBytes {
		return errors.New("device inventory serialization exceeds its size limit")
	}
	var base fs.FileInfo
	if info, statErr := os.Lstat(s.Path); statErr == nil {
		base = info
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	s.pending = &pendingDocument{encoded: encoded, base: base, persistedEvidenceAsOf: persistedEvidenceAsOf}
	return nil
}

func (p *pendingDocument) matches(info fs.FileInfo, statErr error) bool {
	if p.base == nil {
		return errors.Is(statErr, os.ErrNotExist)
	}
	return statErr == nil && os.SameFile(p.base, info) && info.Size() == p.base.Size() && info.ModTime().Equal(p.base.ModTime())
}

func (s *Store) Snapshot() (Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	doc, err := s.load()
	if err != nil {
		return Snapshot{}, err
	}
	return snapshot(doc, s.now()), nil
}

func (s *Store) Get(id string) (Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !ValidDeviceID(id) {
		return Device{}, errors.New("invalid device ID")
	}
	doc, err := s.load()
	if err != nil {
		return Device{}, err
	}
	refreshFriendlyNameConflicts(doc.Devices)
	for _, device := range doc.Devices {
		if device.ID == id {
			projectSuggestedNames(&device)
			return device, nil
		}
	}
	return Device{}, os.ErrNotExist
}

func identityIndexes(devices []Device) (map[string]int, map[string]int) {
	macs := make(map[string]int)
	clients := make(map[string]int)
	for index, device := range devices {
		for _, identity := range device.Identities {
			switch identity.Kind {
			case IdentityMAC:
				macs[identity.Value] = index
			case IdentityDHCPClientID:
				clients[identity.Value] = index
			}
		}
	}
	return macs, clients
}

func upsertIdentity(device *Device, kind IdentityKind, value string, confidence int, firstSeen, lastSeen time.Time) {
	for index := range device.Identities {
		if device.Identities[index].Kind == kind && device.Identities[index].Value == value {
			if firstSeen.Before(device.Identities[index].FirstSeen) {
				device.Identities[index].FirstSeen = firstSeen
			}
			if lastSeen.After(device.Identities[index].LastSeen) {
				device.Identities[index].LastSeen = lastSeen
			}
			return
		}
	}
	if len(device.Identities) < MaxIdentities {
		device.Identities = append(device.Identities, Identity{Kind: kind, Value: value, Source: SourceDHCP4Lease, Confidence: confidence, FirstSeen: firstSeen, LastSeen: lastSeen})
	}
}

func upsertAddress(device *Device, lease DHCP4Lease, confidence int, observed time.Time) {
	validFrom := lease.ExpiresAt.Add(-lease.ValidLifetime)
	for index := range device.Addresses {
		item := &device.Addresses[index]
		if item.Address == lease.Address.String() && item.ValidFrom.Equal(validFrom) && item.ValidUntil.Equal(lease.ExpiresAt) && addressScopeKey(item.Interface, item.VLANID, item.ScopePlanSHA256) == addressScopeKey(lease.Interface, lease.VLANID, lease.ScopePlanSHA256) {
			item.ObservedAt = observed
			item.Active = lease.Active(observed)
			return
		}
	}
	if len(device.Addresses) >= MaxAddresses {
		device.Addresses = append([]AddressObservation(nil), device.Addresses[len(device.Addresses)-MaxAddresses+1:]...)
	}
	device.Addresses = append(device.Addresses, AddressObservation{Address: lease.Address.String(), Family: "IPv4", Source: SourceDHCP4Lease, Confidence: confidence, ValidFrom: validFrom, ValidUntil: lease.ExpiresAt, ObservedAt: observed, Active: lease.Active(observed), Interface: lease.Interface, VLANID: cloneInt(lease.VLANID), ScopePlanSHA256: lease.ScopePlanSHA256})
}

func upsertHostname(device *Device, hostname string, confidence int, firstSeen, lastSeen time.Time) {
	for index := range device.Hostnames {
		if device.Hostnames[index].Hostname == hostname {
			if firstSeen.Before(device.Hostnames[index].FirstSeen) {
				device.Hostnames[index].FirstSeen = firstSeen
			}
			if lastSeen.After(device.Hostnames[index].LastSeen) {
				device.Hostnames[index].LastSeen = lastSeen
			}
			return
		}
	}
	if len(device.Hostnames) < MaxHostnames {
		device.Hostnames = append(device.Hostnames, HostnameObservation{Hostname: hostname, Source: SourceDHCP4Lease, Confidence: confidence, FirstSeen: firstSeen, LastSeen: lastSeen})
	}
}

func addWarning(device *Device, warning string) {
	for _, existing := range device.AttributionWarnings {
		if existing == warning {
			return
		}
	}
	if len(device.AttributionWarnings) < MaxWarnings {
		device.AttributionWarnings = append(device.AttributionWarnings, warning)
	}
}

func (s *Store) load() (document, error) {
	if s.Path == "" || !filepath.IsAbs(s.Path) {
		return document{}, errors.New("inventory path must be absolute")
	}
	info, err := os.Lstat(s.Path)
	if s.pending != nil {
		if s.pending.matches(info, err) {
			return decodeDocument(s.pending.encoded)
		}
		// The file changed underneath (for example a restore); trust it.
		s.pending = nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return document{Schema: SchemaVersion, Devices: []Device{}, AuditEvents: []AuditEvent{}}, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 2 || info.Size() > maxInventoryBytes {
		return document{}, errors.New("device inventory is unavailable or exceeds its size limit")
	}
	descriptor, err := unix.Open(s.Path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return document{}, errors.New("device inventory is unavailable or exceeds its size limit")
	}
	file := os.NewFile(uintptr(descriptor), filepath.Base(s.Path))
	if file == nil {
		unix.Close(descriptor)
		return document{}, errors.New("device inventory is unavailable or exceeds its size limit")
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) || openedInfo.Size() < 2 || openedInfo.Size() > maxInventoryBytes {
		return document{}, errors.New("device inventory changed during validation")
	}
	b, err := io.ReadAll(io.LimitReader(file, maxInventoryBytes+1))
	if err != nil || len(b) > maxInventoryBytes || int64(len(b)) != openedInfo.Size() {
		return document{}, errors.New("device inventory is unavailable or exceeds its size limit")
	}
	return decodeDocument(b)
}

// decodeDocument strictly decodes and validates an inventory document.
func decodeDocument(b []byte) (document, error) {
	var doc document
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&doc); err != nil || decoder.Decode(&struct{}{}) != io.EOF || doc.Schema != SchemaVersion || len(doc.Devices) > MaxDevices || len(doc.AddressAliases) > MaxAddressAliases || len(doc.AuditEvents) > MaxAuditEvents {
		return document{}, errors.New("device inventory is invalid")
	}
	addressAliasIDs := make(map[string]struct{}, len(doc.AddressAliases))
	for _, alias := range doc.AddressAliases {
		if err := validateAddressAlias(alias); err != nil {
			return document{}, err
		}
		if _, duplicate := addressAliasIDs[alias.ID]; duplicate {
			return document{}, errors.New("device inventory contains duplicate address alias IDs")
		}
		addressAliasIDs[alias.ID] = struct{}{}
	}
	deviceIDs := make(map[string]struct{}, len(doc.Devices))
	for _, device := range doc.Devices {
		if err := validateDevice(device); err != nil {
			return document{}, err
		}
		if _, duplicate := deviceIDs[device.ID]; duplicate {
			return document{}, errors.New("device inventory contains duplicate IDs")
		}
		deviceIDs[device.ID] = struct{}{}
	}
	if doc.AuditAnchorSHA256 != "" && (!sha256Pattern.MatchString(doc.AuditAnchorSHA256) || doc.AuditArchivedCount == 0) || doc.AuditAnchorSHA256 == "" && doc.AuditArchivedCount != 0 {
		return document{}, errors.New("device audit archive anchor is invalid")
	}
	operationIDs := make(map[string]struct{}, len(doc.AuditEvents))
	previousAuditSHA256 := doc.AuditAnchorSHA256
	for _, event := range doc.AuditEvents {
		if err := validateAuditEvent(event); err != nil {
			return document{}, err
		}
		if event.PreviousSHA256 != previousAuditSHA256 {
			return document{}, errors.New("device audit hash chain is invalid")
		}
		if _, duplicate := operationIDs[event.OperationID]; duplicate {
			return document{}, errors.New("device audit contains duplicate operation IDs")
		}
		operationIDs[event.OperationID] = struct{}{}
		previousAuditSHA256 = event.EntrySHA256
	}
	return doc, nil
}

func (s *Store) save(doc document) error {
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o750); err != nil {
		return err
	}
	if err := s.appendAuditArchive(doc.archive); err != nil {
		return err
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil || len(b) > maxInventoryBytes {
		return errors.New("device inventory serialization exceeds its size limit")
	}
	b = append(b, '\n')
	temporary, err := os.CreateTemp(filepath.Dir(s.Path), ".inventory-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
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
	if err := os.Rename(temporaryName, s.Path); err != nil {
		return err
	}
	s.pending = nil
	directory, err := os.Open(filepath.Dir(s.Path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func (s *Store) newDeviceID() (string, error) {
	random := s.Random
	if random == nil {
		random = rand.Read
	}
	b := make([]byte, 16)
	if _, err := random(b); err != nil {
		return "", errors.New("generate device ID")
	}
	return fmt.Sprintf("device-%x", b), nil
}

func (s *Store) newUniqueDeviceID(devices []Device) (string, error) {
	for attempt := 0; attempt < 8; attempt++ {
		id, err := s.newDeviceID()
		if err != nil {
			return "", err
		}
		if deviceIndex(devices, id) < 0 {
			return id, nil
		}
	}
	return "", errors.New("generate unique device ID")
}

func (s *Store) newUniqueAddressAliasID(aliases []AddressAlias) (string, error) {
	for attempt := 0; attempt < 8; attempt++ {
		id, err := s.newDeviceID()
		if err != nil {
			return "", err
		}
		id = "address-alias-" + strings.TrimPrefix(id, "device-")
		found := false
		for _, alias := range aliases {
			if alias.ID == id {
				found = true
				break
			}
		}
		if !found {
			return id, nil
		}
	}
	return "", errors.New("generate unique address alias ID")
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func snapshot(doc document, now time.Time) Snapshot {
	devices := make([]Device, len(doc.Devices))
	copy(devices, doc.Devices)
	refreshFriendlyNameConflicts(devices)
	for index := range devices {
		projectSuggestedNames(&devices[index])
	}
	aliases := append([]AddressAlias(nil), doc.AddressAliases...)
	annotateAddressAliasConflicts(aliases, devices)
	return Snapshot{Schema: SchemaVersion, GeneratedAt: now, EvidenceAsOf: doc.EvidenceAsOf, Devices: devices, AddressAliases: aliases}
}
