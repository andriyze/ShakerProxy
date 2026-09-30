package inventory

import (
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	MaxAliasTagImportBytes = 1 << 20
	AliasTagPreviewTTL     = 10 * time.Minute
)

var ErrAliasTagImportStale = errors.New("device alias/tag import preview is stale")

type AliasTagImportEntry = AliasTagExportEntry

type PreparedAliasTagImportEntry struct {
	AliasTagImportEntry
	ExpectedTagsSHA256 string `json:"expected_tags_sha256"`
}

type AliasTagImportChange struct {
	DeviceID             string   `json:"device_id"`
	CurrentFriendlyName  string   `json:"current_friendly_name"`
	ProposedFriendlyName string   `json:"proposed_friendly_name"`
	CurrentTags          []string `json:"current_tags"`
	ProposedTags         []string `json:"proposed_tags"`
	NameChanged          bool     `json:"name_changed"`
	TagsChanged          bool     `json:"tags_changed"`
	Warnings             []string `json:"warnings"`
}

type AliasTagImportBlocker struct {
	DeviceID string `json:"device_id"`
	Code     string `json:"code"`
	Message  string `json:"message"`
}

type AliasTagImportPreview struct {
	Schema        int                           `json:"schema"`
	PreviewSHA256 string                        `json:"preview_sha256"`
	GeneratedAt   time.Time                     `json:"generated_at"`
	ExpiresAt     time.Time                     `json:"expires_at"`
	Reason        string                        `json:"reason"`
	Entries       []PreparedAliasTagImportEntry `json:"entries"`
	Changes       []AliasTagImportChange        `json:"changes"`
	Blockers      []AliasTagImportBlocker       `json:"blockers"`
	Ready         bool                          `json:"ready"`
}

type AliasTagImportResult struct {
	Schema         int        `json:"schema"`
	UpdatedDevices int        `json:"updated_devices"`
	Audit          AuditEvent `json:"audit"`
	Replayed       bool       `json:"replayed"`
}

func ParseAliasTagImport(format string, content []byte) ([]AliasTagImportEntry, error) {
	if len(content) == 0 || len(content) > MaxAliasTagImportBytes {
		return nil, errors.New("device alias/tag import content is empty or exceeds 1 MiB")
	}
	var entries []AliasTagImportEntry
	switch format {
	case "json":
		var document AliasTagExport
		decoder := json.NewDecoder(bytes.NewReader(content))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&document); err != nil || decoder.Decode(&struct{}{}) != io.EOF || document.Schema != SchemaVersion {
			return nil, errors.New("device alias/tag JSON must match the exported schema")
		}
		entries = document.Entries
	case "csv":
		reader := csv.NewReader(bytes.NewReader(content))
		reader.ReuseRecord = false
		records, err := reader.ReadAll()
		if err != nil || len(records) < 2 || !sameStrings(records[0], []string{"device_id", "friendly_name", "alias_revision", "tags_json"}) {
			return nil, errors.New("device alias/tag CSV header or records are invalid")
		}
		entries = make([]AliasTagImportEntry, 0, len(records)-1)
		for index, record := range records[1:] {
			if len(record) != 4 {
				return nil, fmt.Errorf("device alias/tag CSV row %d has the wrong field count", index+2)
			}
			revision, err := strconv.ParseUint(record[2], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("device alias/tag CSV row %d has an invalid alias revision", index+2)
			}
			var tags []string
			tagDecoder := json.NewDecoder(strings.NewReader(record[3]))
			if err := tagDecoder.Decode(&tags); err != nil || tagDecoder.Decode(&struct{}{}) != io.EOF || tags == nil {
				return nil, fmt.Errorf("device alias/tag CSV row %d has invalid tags_json", index+2)
			}
			entries = append(entries, AliasTagImportEntry{DeviceID: record[0], FriendlyName: record[1], AliasRevision: revision, Tags: tags})
		}
	default:
		return nil, errors.New("device alias/tag import format must be json or csv")
	}
	return normalizeAliasTagImportEntries(entries)
}

func normalizeAliasTagImportEntries(entries []AliasTagImportEntry) ([]AliasTagImportEntry, error) {
	if len(entries) < 1 || len(entries) > MaxAliasTagImport {
		return nil, fmt.Errorf("device alias/tag import must contain between 1 and %d entries", MaxAliasTagImport)
	}
	normalized := make([]AliasTagImportEntry, len(entries))
	seen := make(map[string]struct{}, len(entries))
	for index, entry := range entries {
		if !ValidDeviceID(entry.DeviceID) || !validFriendlyName(normalizeFriendlyName(entry.FriendlyName)) || entry.Tags == nil {
			return nil, fmt.Errorf("device alias/tag import entry %d has an invalid device ID, friendly name, or tag array", index+1)
		}
		if _, duplicate := seen[entry.DeviceID]; duplicate {
			return nil, errors.New("device alias/tag import contains a duplicate device ID")
		}
		seen[entry.DeviceID] = struct{}{}
		metadata, err := normalizeMetadata(DeviceMetadata{Tags: entry.Tags})
		if err != nil {
			return nil, fmt.Errorf("device alias/tag import entry %d: %w", index+1, err)
		}
		normalized[index] = AliasTagImportEntry{DeviceID: entry.DeviceID, FriendlyName: normalizeFriendlyName(entry.FriendlyName), AliasRevision: entry.AliasRevision, Tags: append([]string{}, metadata.Tags...)}
	}
	sort.Slice(normalized, func(i, j int) bool { return normalized[i].DeviceID < normalized[j].DeviceID })
	return normalized, nil
}

func (s *Store) PreviewAliasTagImport(entries []AliasTagImportEntry, reason string) (AliasTagImportPreview, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	normalized, err := normalizeAliasTagImportEntries(entries)
	if err != nil {
		return AliasTagImportPreview{}, fmt.Errorf("%w: %v", ErrMutationRejected, err)
	}
	reason = strings.TrimSpace(reason)
	if !validSingleLine(reason, 1, 256) {
		return AliasTagImportPreview{}, fmt.Errorf("%w: import reason is invalid", ErrMutationRejected)
	}
	doc, err := s.load()
	if err != nil {
		return AliasTagImportPreview{}, err
	}
	return buildAliasTagImportPreview(doc, normalized, reason, s.now())
}

func (s *Store) ApplyAliasTagImport(actor, operationID string, reviewed AliasTagImportPreview) (AliasTagImportResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := validateMutationIdentity(actor, operationID); err != nil {
		return AliasTagImportResult{}, fmt.Errorf("%w: %v", ErrMutationRejected, err)
	}
	if reviewed.Schema != SchemaVersion || reviewed.PreviewSHA256 == "" {
		return AliasTagImportResult{}, fmt.Errorf("%w: import preview identity is invalid", ErrMutationRejected)
	}
	digest, err := aliasTagImportPreviewDigest(reviewed)
	if err != nil || digest != reviewed.PreviewSHA256 {
		return AliasTagImportResult{}, fmt.Errorf("%w: import preview digest is invalid", ErrMutationRejected)
	}
	entries := make([]AliasTagImportEntry, len(reviewed.Entries))
	for index := range reviewed.Entries {
		entries[index] = reviewed.Entries[index].AliasTagImportEntry
	}
	entries, err = normalizeAliasTagImportEntries(entries)
	if err != nil {
		return AliasTagImportResult{}, fmt.Errorf("%w: %v", ErrMutationRejected, err)
	}
	if strings.TrimSpace(reviewed.Reason) != reviewed.Reason || !validSingleLine(reviewed.Reason, 1, 256) || len(entries) != len(reviewed.Entries) {
		return AliasTagImportResult{}, fmt.Errorf("%w: import preview reason or entries are invalid", ErrMutationRejected)
	}
	for index, entry := range entries {
		reviewedEntry := reviewed.Entries[index]
		if entry.DeviceID != reviewedEntry.DeviceID || entry.FriendlyName != reviewedEntry.FriendlyName || entry.AliasRevision != reviewedEntry.AliasRevision || !sameStrings(entry.Tags, reviewedEntry.Tags) || !sha256Pattern.MatchString(reviewedEntry.ExpectedTagsSHA256) {
			return AliasTagImportResult{}, fmt.Errorf("%w: import preview entries are not canonical", ErrMutationRejected)
		}
	}
	sourceIDs := make([]string, len(entries))
	for index := range entries {
		sourceIDs[index] = entries[index].DeviceID
	}
	requestSHA256, err := mutationRequestDigest(AuditAliasTagsImported, sourceIDs, reviewed.PreviewSHA256)
	if err != nil {
		return AliasTagImportResult{}, err
	}
	doc, err := s.load()
	if err != nil {
		return AliasTagImportResult{}, err
	}
	if replay, found, replayErr := mutationReplay(doc, operationID, AuditAliasTagsImported, sourceIDs, requestSHA256); found || replayErr != nil {
		if replayErr != nil {
			return AliasTagImportResult{}, replayErr
		}
		return AliasTagImportResult{Schema: SchemaVersion, UpdatedDevices: len(replay.Audit.ResultDeviceIDs), Audit: replay.Audit, Replayed: true}, nil
	}
	now := s.now()
	if !reviewed.Ready || len(reviewed.Blockers) != 0 || len(reviewed.Changes) == 0 || reviewed.GeneratedAt.IsZero() || !reviewed.ExpiresAt.Equal(reviewed.GeneratedAt.Add(AliasTagPreviewTTL)) || now.Before(reviewed.GeneratedAt) || !now.Before(reviewed.ExpiresAt) {
		return AliasTagImportResult{}, ErrAliasTagImportStale
	}
	prepared := make(map[string]PreparedAliasTagImportEntry, len(reviewed.Entries))
	for _, entry := range reviewed.Entries {
		prepared[entry.DeviceID] = entry
	}
	nameChanges, tagChanges := 0, 0
	for _, entry := range entries {
		index := deviceIndex(doc.Devices, entry.DeviceID)
		if index < 0 || doc.Devices[index].AliasRevision != entry.AliasRevision || tagsDigest(doc.Devices[index].Tags) != prepared[entry.DeviceID].ExpectedTagsSHA256 {
			return AliasTagImportResult{}, ErrAliasTagImportStale
		}
		device := &doc.Devices[index]
		if device.FriendlyName != entry.FriendlyName {
			if err := appendAliasChange(device, entry.FriendlyName, actor, reviewed.Reason, now); err != nil {
				return AliasTagImportResult{}, fmt.Errorf("%w: %v", ErrMutationRejected, err)
			}
			nameChanges++
		}
		if !sameStrings(device.Tags, entry.Tags) {
			device.Tags = append([]string{}, entry.Tags...)
			tagChanges++
		}
		if err := validateDevice(*device); err != nil {
			return AliasTagImportResult{}, err
		}
	}
	if nameChanges == 0 && tagChanges == 0 {
		return AliasTagImportResult{}, ErrAliasTagImportStale
	}
	refreshFriendlyNameConflicts(doc.Devices)
	changes := make([]string, 0, 2)
	if nameChanges > 0 {
		changes = append(changes, fmt.Sprintf("updated %d device aliases", nameChanges))
	}
	if tagChanges > 0 {
		changes = append(changes, fmt.Sprintf("updated %d device tag sets", tagChanges))
	}
	audit := newAuditEvent(operationID, requestSHA256, AuditAliasTagsImported, actor, now, sourceIDs, sourceIDs, changes)
	if err := appendAudit(&doc, &audit); err != nil {
		return AliasTagImportResult{}, err
	}
	doc.UpdatedAt = now
	if err := s.save(doc); err != nil {
		return AliasTagImportResult{}, err
	}
	return AliasTagImportResult{Schema: SchemaVersion, UpdatedDevices: len(sourceIDs), Audit: audit}, nil
}

func buildAliasTagImportPreview(doc document, entries []AliasTagImportEntry, reason string, now time.Time) (AliasTagImportPreview, error) {
	preview := AliasTagImportPreview{Schema: SchemaVersion, GeneratedAt: now.UTC(), ExpiresAt: now.UTC().Add(AliasTagPreviewTTL), Reason: reason, Entries: make([]PreparedAliasTagImportEntry, 0, len(entries)), Changes: []AliasTagImportChange{}, Blockers: []AliasTagImportBlocker{}}
	proposedNames := make(map[string]string, len(entries))
	for _, entry := range entries {
		proposedNames[entry.DeviceID] = entry.FriendlyName
	}
	nameCounts := make(map[string]int)
	for _, device := range doc.Devices {
		name := device.FriendlyName
		if proposed, ok := proposedNames[device.ID]; ok {
			name = proposed
		}
		if name != "" {
			nameCounts[strings.ToLower(name)]++
		}
	}
	for _, entry := range entries {
		index := deviceIndex(doc.Devices, entry.DeviceID)
		prepared := PreparedAliasTagImportEntry{AliasTagImportEntry: entry}
		if index < 0 {
			preview.Blockers = append(preview.Blockers, AliasTagImportBlocker{DeviceID: entry.DeviceID, Code: "DEVICE_NOT_FOUND", Message: "The immutable device ID is not present in this inventory."})
			preview.Entries = append(preview.Entries, prepared)
			continue
		}
		device := doc.Devices[index]
		prepared.ExpectedTagsSHA256 = tagsDigest(device.Tags)
		preview.Entries = append(preview.Entries, prepared)
		if device.AliasRevision != entry.AliasRevision {
			preview.Blockers = append(preview.Blockers, AliasTagImportBlocker{DeviceID: entry.DeviceID, Code: "ALIAS_REVISION_STALE", Message: fmt.Sprintf("Expected alias revision %d but the current revision is %d.", entry.AliasRevision, device.AliasRevision)})
			continue
		}
		nameChanged, tagsChanged := device.FriendlyName != entry.FriendlyName, !sameStrings(device.Tags, entry.Tags)
		if !nameChanged && !tagsChanged {
			continue
		}
		change := AliasTagImportChange{DeviceID: entry.DeviceID, CurrentFriendlyName: device.FriendlyName, ProposedFriendlyName: entry.FriendlyName, CurrentTags: append([]string{}, device.Tags...), ProposedTags: append([]string{}, entry.Tags...), NameChanged: nameChanged, TagsChanged: tagsChanged, Warnings: []string{}}
		if entry.FriendlyName != "" && nameCounts[strings.ToLower(entry.FriendlyName)] > 1 {
			change.Warnings = append(change.Warnings, "The proposed friendly name is also used by another device; duplicate names remain visibly flagged.")
		}
		preview.Changes = append(preview.Changes, change)
	}
	preview.Ready = len(preview.Blockers) == 0 && len(preview.Changes) > 0
	digest, err := aliasTagImportPreviewDigest(preview)
	if err != nil {
		return AliasTagImportPreview{}, err
	}
	preview.PreviewSHA256 = digest
	return preview, nil
}

func aliasTagImportPreviewDigest(preview AliasTagImportPreview) (string, error) {
	preview.PreviewSHA256 = ""
	encoded, err := json.Marshal(preview)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func tagsDigest(tags []string) string {
	encoded, _ := json.Marshal(append([]string{}, tags...))
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
