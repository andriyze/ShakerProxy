package inventory

import (
	"errors"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const defaultNameResolverRefreshInterval = 2 * time.Second

const (
	MaxResolvedAliasValues   = 32
	MaxResolvedAliasIDs      = 256
	MaxQueryValueCompletions = 20
)

var ErrAliasResolutionLimit = errors.New("device friendly-name query matches too many bounded aliases")

// NameProjection keeps the mutable display name separate from the name that was
// in effect when evidence was captured.
type NameProjection struct {
	CurrentFriendlyName           string
	FriendlyNameAtCapture         string
	FriendlyNameAtCaptureKnown    bool
	AliasRevision                 uint64
	CurrentFriendlyNameConflicted bool
}

type QueryValueCompletion struct {
	Value              string `json:"value"`
	DeviceCount        int    `json:"device_count"`
	IncludesHistorical bool   `json:"includes_historical"`
}

// NameResolver maintains a small, read-only cache so traffic projection does
// not decode the bounded inventory document once per event.
type NameResolver struct {
	Store           *Store
	RefreshInterval time.Duration
	Now             func() time.Time

	mu       sync.Mutex
	loadedAt time.Time
	devices  map[string]Device
}

func (r *NameResolver) Resolve(deviceID string, capturedAt time.Time) (NameProjection, bool, error) {
	if !ValidDeviceID(deviceID) || capturedAt.IsZero() {
		return NameProjection{}, false, errors.New("device name projection input is invalid")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.refreshLocked(); err != nil {
		return NameProjection{}, false, err
	}
	device, found := r.devices[deviceID]
	if !found {
		return NameProjection{}, false, nil
	}
	return projectDeviceName(device, capturedAt.UTC()), true, nil
}

func (r *NameResolver) Ready() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.refreshLocked()
}

// ResolveAliases resolves current and retained historical friendly names to
// immutable device IDs from one cached inventory snapshot. The wildcard value
// resolves devices with any retained name. Results are sorted and never
// truncated; excessive ambiguity is reported to the caller.
func (r *NameResolver) ResolveAliases(values []string) (map[string][]string, error) {
	aliases, _, err := r.ResolveSelectors(values, nil)
	return aliases, err
}

// ResolveSelectors resolves current/retained aliases and current device tags
// against one cached inventory revision. This keeps every selector in a query
// on the same immutable control-plane view before only device IDs cross the
// storage boundary.
func (r *NameResolver) ResolveSelectors(aliasValues, tagValues []string) (map[string][]string, map[string][]string, error) {
	if len(aliasValues)+len(tagValues) > MaxResolvedAliasValues {
		return nil, nil, ErrAliasResolutionLimit
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.refreshLocked(); err != nil {
		return nil, nil, err
	}
	aliases := make(map[string][]string, len(aliasValues))
	tags := make(map[string][]string, len(tagValues))
	total := 0
	for _, value := range aliasValues {
		if value == "" || len(value) > 128 || value != strings.TrimSpace(value) {
			return nil, nil, errors.New("device friendly-name query is invalid")
		}
		if _, duplicate := aliases[value]; duplicate {
			continue
		}
		ids := make([]string, 0, 4)
		for id, device := range r.devices {
			if deviceHasAlias(device, value) {
				ids = append(ids, id)
			}
		}
		sort.Strings(ids)
		total += len(ids)
		if total > MaxResolvedAliasIDs {
			return nil, nil, ErrAliasResolutionLimit
		}
		aliases[value] = ids
	}
	for _, value := range tagValues {
		if value == "" || len(value) > 64 || value != strings.ToLower(value) || value != strings.TrimSpace(value) {
			return nil, nil, errors.New("device tag query is invalid")
		}
		if _, duplicate := tags[value]; duplicate {
			continue
		}
		ids := make([]string, 0, 4)
		for id, device := range r.devices {
			if deviceHasTag(device, value) {
				ids = append(ids, id)
			}
		}
		sort.Strings(ids)
		total += len(ids)
		if total > MaxResolvedAliasIDs {
			return nil, nil, ErrAliasResolutionLimit
		}
		tags[value] = ids
	}
	return aliases, tags, nil
}

// CompleteQueryValues returns deterministic, bounded values from the same
// cached inventory used to resolve queries. Historical aliases remain visible
// and are explicitly marked; tags are current metadata only.
func (r *NameResolver) CompleteQueryValues(field, prefix string, limit int) ([]QueryValueCompletion, bool, error) {
	if field != "device.name" && field != "device.tag" || limit < 1 || limit > MaxQueryValueCompletions || len(prefix) > 128 || !utf8.ValidString(prefix) {
		return nil, false, errors.New("device query completion request is invalid")
	}
	for _, character := range prefix {
		if character < 0x20 || character == 0x7f {
			return nil, false, errors.New("device query completion prefix is invalid")
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.refreshLocked(); err != nil {
		return nil, false, err
	}
	type candidate struct {
		value      string
		current    bool
		historical bool
		devices    map[string]struct{}
	}
	candidates := make(map[string]*candidate)
	add := func(deviceID, value string, current bool) {
		if value == "" || !strings.HasPrefix(strings.ToLower(value), strings.ToLower(prefix)) {
			return
		}
		key := strings.ToLower(value)
		item := candidates[key]
		if item == nil {
			item = &candidate{value: value, devices: make(map[string]struct{})}
			candidates[key] = item
		}
		if current && (!item.current || value < item.value) {
			item.value = value
		}
		item.current = item.current || current
		item.historical = item.historical || !current
		item.devices[deviceID] = struct{}{}
	}
	for id, device := range r.devices {
		if field == "device.tag" {
			for _, tag := range device.Tags {
				add(id, tag, true)
			}
			continue
		}
		add(id, device.FriendlyName, true)
		for _, change := range device.AliasHistory {
			add(id, change.FriendlyName, change.FriendlyName == device.FriendlyName)
			add(id, change.PreviousFriendlyName, change.PreviousFriendlyName == device.FriendlyName)
		}
	}
	ordered := make([]*candidate, 0, len(candidates))
	for _, item := range candidates {
		ordered = append(ordered, item)
	}
	sort.Slice(ordered, func(left, right int) bool {
		if ordered[left].current != ordered[right].current {
			return ordered[left].current
		}
		leftValue, rightValue := strings.ToLower(ordered[left].value), strings.ToLower(ordered[right].value)
		if leftValue != rightValue {
			return leftValue < rightValue
		}
		return ordered[left].value < ordered[right].value
	})
	truncated := len(ordered) > limit
	if truncated {
		ordered = ordered[:limit]
	}
	result := make([]QueryValueCompletion, 0, len(ordered))
	for _, item := range ordered {
		result = append(result, QueryValueCompletion{Value: item.value, DeviceCount: len(item.devices), IncludesHistorical: item.historical})
	}
	return result, truncated, nil
}

func (r *NameResolver) Invalidate() {
	r.mu.Lock()
	r.loadedAt = time.Time{}
	r.mu.Unlock()
}

func (r *NameResolver) refreshLocked() error {
	if r.Store == nil {
		return errors.New("device inventory is not configured")
	}
	now := time.Now().UTC()
	if r.Now != nil {
		now = r.Now().UTC()
	}
	interval := r.RefreshInterval
	if interval <= 0 {
		interval = defaultNameResolverRefreshInterval
	}
	age := now.Sub(r.loadedAt)
	if r.devices != nil && !r.loadedAt.IsZero() && age >= 0 && age < interval {
		return nil
	}
	snapshot, err := r.Store.Snapshot()
	if err != nil {
		return err
	}
	devices := make(map[string]Device, len(snapshot.Devices))
	for _, device := range snapshot.Devices {
		devices[device.ID] = device
	}
	r.devices = devices
	r.loadedAt = now
	return nil
}

func projectDeviceName(device Device, capturedAt time.Time) NameProjection {
	projection := NameProjection{
		CurrentFriendlyName:           device.FriendlyName,
		FriendlyNameAtCapture:         device.FriendlyName,
		FriendlyNameAtCaptureKnown:    true,
		AliasRevision:                 device.AliasRevision,
		CurrentFriendlyNameConflicted: device.FriendlyNameConflict,
	}
	if device.AliasRevision == 0 {
		// Legacy friendly names predate revision timestamps, so their capture-time
		// value cannot be asserted even though the current value is still useful.
		projection.FriendlyNameAtCaptureKnown = device.FriendlyName == ""
		return projection
	}
	for index := len(device.AliasHistory) - 1; index >= 0; index-- {
		change := device.AliasHistory[index]
		if capturedAt.Before(change.ChangedAt) {
			projection.FriendlyNameAtCapture = change.PreviousFriendlyName
		}
	}
	first := device.AliasHistory[0]
	if capturedAt.Before(first.ChangedAt) && (device.AliasHistoryTruncated || first.Revision == 1 && first.PreviousFriendlyName != "") {
		projection.FriendlyNameAtCaptureKnown = false
	}
	return projection
}

func deviceHasAlias(device Device, value string) bool {
	matches := func(candidate string) bool {
		return candidate != "" && (value == "*" || strings.EqualFold(candidate, value))
	}
	if matches(device.FriendlyName) {
		return true
	}
	for _, change := range device.AliasHistory {
		if matches(change.FriendlyName) || matches(change.PreviousFriendlyName) {
			return true
		}
	}
	return false
}

func deviceHasTag(device Device, value string) bool {
	for _, tag := range device.Tags {
		if value == "*" || strings.EqualFold(tag, value) {
			return true
		}
	}
	return false
}
