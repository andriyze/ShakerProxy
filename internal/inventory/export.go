package inventory

import (
	"sort"
	"time"
)

const MaxAliasTagExportBytes = 64 << 20

type AliasTagExportEntry struct {
	DeviceID      string   `json:"device_id"`
	FriendlyName  string   `json:"friendly_name"`
	AliasRevision uint64   `json:"alias_revision"`
	Tags          []string `json:"tags"`
}

type AliasTagExport struct {
	Schema      int                   `json:"schema"`
	GeneratedAt time.Time             `json:"generated_at"`
	Entries     []AliasTagExportEntry `json:"entries"`
}

func (s *Store) ExportAliasesTags() (AliasTagExport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	doc, err := s.load()
	if err != nil {
		return AliasTagExport{}, err
	}
	entries := make([]AliasTagExportEntry, 0, len(doc.Devices))
	for _, device := range doc.Devices {
		entries = append(entries, AliasTagExportEntry{DeviceID: device.ID, FriendlyName: device.FriendlyName, AliasRevision: device.AliasRevision, Tags: append([]string{}, device.Tags...)})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].DeviceID < entries[j].DeviceID })
	return AliasTagExport{Schema: SchemaVersion, GeneratedAt: s.now(), Entries: entries}, nil
}
