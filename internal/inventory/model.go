package inventory

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	SchemaVersion     = 1
	MaxDevices        = 50000
	MaxAddresses      = 256
	MaxIdentities     = 32
	MaxHostnames      = 32
	MaxWarnings       = 32
	MaxTags           = 32
	MaxAliasHistory   = 256
	MaxSuggestedNames = 8
	MaxAliasTagImport = 256
	MaxAddressAliases = 4096
	MaxAuditEvents    = 4096
)

type EvidenceSource string

const (
	SourceDHCP4Lease EvidenceSource = "DHCP4_LEASE"
)

type IdentityKind string

const (
	IdentityMAC          IdentityKind = "MAC"
	IdentityDHCPClientID IdentityKind = "DHCP_CLIENT_ID"
)

var deviceIDPattern = regexp.MustCompile(`^device-[a-f0-9]{32}$`)
var auditIDPattern = regexp.MustCompile(`^audit-[a-f0-9]{32}$`)
var addressAliasIDPattern = regexp.MustCompile(`^address-alias-[a-f0-9]{32}$`)
var operationIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{15,127}$`)
var sha256Pattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var categoryPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
var interfaceScopePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}$`)

var allowedDeviceIcons = map[string]struct{}{
	"": {}, "device": {}, "camera": {}, "sensor": {}, "tv": {}, "speaker": {},
	"phone": {}, "tablet": {}, "computer": {}, "console": {}, "router": {}, "appliance": {},
}

type DHCP4Lease struct {
	Address         netip.Addr
	HardwareAddr    string
	ClientID        string
	Hostname        string
	ValidLifetime   time.Duration
	ExpiresAt       time.Time
	State           int
	Interface       string
	VLANID          *int
	ScopePlanSHA256 string
}

func (l DHCP4Lease) Active(at time.Time) bool {
	return l.State == 0 && l.ExpiresAt.After(at)
}

type Identity struct {
	Kind       IdentityKind   `json:"kind"`
	Value      string         `json:"value"`
	Source     EvidenceSource `json:"source"`
	Confidence int            `json:"confidence"`
	FirstSeen  time.Time      `json:"first_seen"`
	LastSeen   time.Time      `json:"last_seen"`
}

type AddressObservation struct {
	Address         string         `json:"address"`
	Family          string         `json:"family"`
	Source          EvidenceSource `json:"source"`
	Confidence      int            `json:"confidence"`
	ValidFrom       time.Time      `json:"valid_from"`
	ValidUntil      time.Time      `json:"valid_until"`
	ObservedAt      time.Time      `json:"observed_at"`
	Active          bool           `json:"active"`
	Interface       string         `json:"interface,omitempty"`
	VLANID          *int           `json:"vlan_id,omitempty"`
	ScopePlanSHA256 string         `json:"scope_plan_sha256,omitempty"`
}

type HostnameObservation struct {
	Hostname   string         `json:"hostname"`
	Source     EvidenceSource `json:"source"`
	Confidence int            `json:"confidence"`
	FirstSeen  time.Time      `json:"first_seen"`
	LastSeen   time.Time      `json:"last_seen"`
}

type AliasChange struct {
	Revision             uint64    `json:"revision"`
	FriendlyName         string    `json:"friendly_name"`
	PreviousFriendlyName string    `json:"previous_friendly_name"`
	Actor                string    `json:"actor"`
	Reason               string    `json:"reason"`
	ChangedAt            time.Time `json:"changed_at"`
}

type SuggestedName struct {
	Name       string         `json:"name"`
	Source     EvidenceSource `json:"source"`
	Confidence int            `json:"confidence"`
	FirstSeen  time.Time      `json:"first_seen"`
	LastSeen   time.Time      `json:"last_seen"`
}

type AddressAlias struct {
	Schema           int        `json:"schema"`
	ID               string     `json:"id"`
	Revision         uint64     `json:"revision"`
	Name             string     `json:"name"`
	Prefix           string     `json:"prefix"`
	Interface        string     `json:"interface"`
	VLANID           *int       `json:"vlan_id,omitempty"`
	ValidFrom        time.Time  `json:"valid_from"`
	ValidUntil       *time.Time `json:"valid_until,omitempty"`
	Priority         int        `json:"priority"`
	Confidence       int        `json:"confidence"`
	Reason           string     `json:"reason"`
	CreatedBy        string     `json:"created_by"`
	UpdatedBy        string     `json:"updated_by"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
	Conflict         bool       `json:"conflict,omitempty"`
	ConflictWarnings []string   `json:"conflict_warnings,omitempty"`
}

type AddressAliasInput struct {
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	Interface  string     `json:"interface"`
	VLANID     *int       `json:"vlan_id,omitempty"`
	ValidFrom  time.Time  `json:"valid_from"`
	ValidUntil *time.Time `json:"valid_until,omitempty"`
	Priority   int        `json:"priority"`
	Confidence int        `json:"confidence"`
	Reason     string     `json:"reason"`
}

type AddressAliasUpdate struct {
	AddressAliasInput
	ExpectedRevision uint64 `json:"expected_revision"`
}

type AddressAliasMutationResult struct {
	Schema    int          `json:"schema"`
	Alias     AddressAlias `json:"alias"`
	Audit     AuditEvent   `json:"audit,omitzero"`
	Replayed  bool         `json:"replayed"`
	Unchanged bool         `json:"unchanged,omitempty"`
	Deleted   bool         `json:"deleted,omitempty"`
}

type AddressAliasResolution struct {
	Schema     int            `json:"schema"`
	Address    string         `json:"address"`
	Interface  string         `json:"interface"`
	VLANID     *int           `json:"vlan_id,omitempty"`
	OccurredAt time.Time      `json:"occurred_at"`
	Matched    bool           `json:"matched"`
	Conflict   bool           `json:"conflict"`
	Alias      *AddressAlias  `json:"alias,omitempty"`
	Candidates []AddressAlias `json:"candidates,omitempty"`
}

type Device struct {
	Schema                int                   `json:"schema"`
	ID                    string                `json:"id"`
	FriendlyName          string                `json:"friendly_name,omitempty"`
	AliasRevision         uint64                `json:"alias_revision,omitempty"`
	AliasHistory          []AliasChange         `json:"alias_history,omitempty"`
	AliasHistoryTruncated bool                  `json:"alias_history_truncated,omitempty"`
	FriendlyNameConflict  bool                  `json:"friendly_name_conflict,omitempty"`
	SuggestedNames        []SuggestedName       `json:"suggested_names,omitempty"`
	Owner                 string                `json:"owner,omitempty"`
	Location              string                `json:"location,omitempty"`
	Category              string                `json:"category,omitempty"`
	Icon                  string                `json:"icon,omitempty"`
	Tags                  []string              `json:"tags,omitempty"`
	Notes                 string                `json:"notes,omitempty"`
	CATrust               string                `json:"ca_trust,omitempty"`
	VendorState           VendorState           `json:"vendor_state,omitempty"`
	Vendor                *VendorObservation    `json:"vendor,omitempty"`
	Identities            []Identity            `json:"identities"`
	Addresses             []AddressObservation  `json:"addresses"`
	Hostnames             []HostnameObservation `json:"hostnames"`
	FirstSeen             time.Time             `json:"first_seen"`
	LastSeen              time.Time             `json:"last_seen"`
	Online                bool                  `json:"online"`
	AttributionConfidence int                   `json:"attribution_confidence"`
	AttributionWarnings   []string              `json:"attribution_warnings,omitempty"`
	LastReconciled        time.Time             `json:"last_reconciled"`
}

// MarshalJSON always writes identities, addresses and hostnames as lists:
// a device seen only in the ARP table has no hostname, and clients rely on
// an empty list rather than null.
func (d Device) MarshalJSON() ([]byte, error) {
	type plain Device
	p := plain(d)
	if p.Identities == nil {
		p.Identities = []Identity{}
	}
	if p.Addresses == nil {
		p.Addresses = []AddressObservation{}
	}
	if p.Hostnames == nil {
		p.Hostnames = []HostnameObservation{}
	}
	return json.Marshal(p)
}

type DeviceMetadata struct {
	FriendlyName string   `json:"friendly_name,omitempty"`
	Owner        string   `json:"owner,omitempty"`
	Location     string   `json:"location,omitempty"`
	Category     string   `json:"category,omitempty"`
	Icon         string   `json:"icon,omitempty"`
	Tags         []string `json:"tags,omitempty"`
	Notes        string   `json:"notes,omitempty"`
}

type DeviceMetadataPatch struct {
	FriendlyName *string   `json:"friendly_name,omitempty"`
	Owner        *string   `json:"owner,omitempty"`
	Location     *string   `json:"location,omitempty"`
	Category     *string   `json:"category,omitempty"`
	Icon         *string   `json:"icon,omitempty"`
	Tags         *[]string `json:"tags,omitempty"`
	Notes        *string   `json:"notes,omitempty"`
}

type AliasUpdate struct {
	FriendlyName     string `json:"friendly_name"`
	Reason           string `json:"reason"`
	ExpectedRevision uint64 `json:"expected_revision"`
}

type AuditAction string

const (
	AuditMetadataUpdated     AuditAction = "DEVICE_METADATA_UPDATED"
	AuditAliasUpdated        AuditAction = "DEVICE_ALIAS_UPDATED"
	AuditDevicesMerged       AuditAction = "DEVICES_MERGED"
	AuditDeviceSplit         AuditAction = "DEVICE_SPLIT"
	AuditAddressAliasCreated AuditAction = "ADDRESS_ALIAS_CREATED"
	AuditAddressAliasUpdated AuditAction = "ADDRESS_ALIAS_UPDATED"
	AuditAliasTagsImported   AuditAction = "DEVICE_ALIAS_TAGS_IMPORTED"
	AuditAddressAliasDeleted AuditAction = "ADDRESS_ALIAS_DELETED"
)

type AuditEvent struct {
	Schema                int         `json:"schema"`
	ID                    string      `json:"id"`
	OperationID           string      `json:"operation_id"`
	RequestSHA256         string      `json:"request_sha256"`
	Action                AuditAction `json:"action"`
	Actor                 string      `json:"actor"`
	OccurredAt            time.Time   `json:"occurred_at"`
	SourceDeviceIDs       []string    `json:"source_device_ids"`
	ResultDeviceIDs       []string    `json:"result_device_ids"`
	SourceAddressAliasIDs []string    `json:"source_address_alias_ids,omitempty"`
	ResultAddressAliasIDs []string    `json:"result_address_alias_ids,omitempty"`
	Changes               []string    `json:"changes"`
	PreviousSHA256        string      `json:"previous_sha256,omitempty"`
	EntrySHA256           string      `json:"entry_sha256"`
}

type IdentitySelector struct {
	Kind   IdentityKind   `json:"kind"`
	Value  string         `json:"value"`
	Source EvidenceSource `json:"source"`
}

type AddressSelector struct {
	Address         string         `json:"address"`
	Source          EvidenceSource `json:"source"`
	ValidFrom       time.Time      `json:"valid_from"`
	ValidUntil      time.Time      `json:"valid_until"`
	Interface       string         `json:"interface,omitempty"`
	VLANID          *int           `json:"vlan_id,omitempty"`
	ScopePlanSHA256 string         `json:"scope_plan_sha256,omitempty"`
}

type HostnameSelector struct {
	Hostname string         `json:"hostname"`
	Source   EvidenceSource `json:"source"`
}

type SplitSelection struct {
	Identities []IdentitySelector `json:"identities"`
	Addresses  []AddressSelector  `json:"addresses,omitempty"`
	Hostnames  []HostnameSelector `json:"hostnames,omitempty"`
	Metadata   DeviceMetadata     `json:"metadata"`
}

type MutationResult struct {
	Schema   int        `json:"schema"`
	Devices  []Device   `json:"devices"`
	Audit    AuditEvent `json:"audit,omitzero"`
	Replayed bool       `json:"replayed"`
	// Unchanged is true when the request matched the stored values; nothing
	// was written and no audit event was recorded.
	Unchanged bool `json:"unchanged,omitempty"`
}

type Snapshot struct {
	Schema         int            `json:"schema"`
	GeneratedAt    time.Time      `json:"generated_at"`
	EvidenceAsOf   time.Time      `json:"evidence_as_of"`
	Devices        []Device       `json:"devices"`
	AddressAliases []AddressAlias `json:"address_aliases,omitempty"`
}

func ValidDeviceID(id string) bool { return deviceIDPattern.MatchString(id) }

func ValidOperationID(id string) bool { return operationIDPattern.MatchString(id) }

func ValidAddressAliasID(id string) bool { return addressAliasIDPattern.MatchString(id) }

func validateDevice(device Device) error {
	if device.Schema != SchemaVersion || !ValidDeviceID(device.ID) || device.FirstSeen.IsZero() || device.LastSeen.Before(device.FirstSeen) || device.LastReconciled.IsZero() {
		return errors.New("device identity or timestamps are invalid")
	}
	if len(device.Identities) == 0 || len(device.Identities) > MaxIdentities || len(device.Addresses) > MaxAddresses || len(device.Hostnames) > MaxHostnames || len(device.AttributionWarnings) > MaxWarnings || len(device.AliasHistory) > MaxAliasHistory || len(device.SuggestedNames) != 0 {
		return errors.New("device evidence exceeds bounds")
	}
	normalizedMetadata, err := normalizeMetadata(DeviceMetadata{FriendlyName: device.FriendlyName, Owner: device.Owner, Location: device.Location, Category: device.Category, Icon: device.Icon, Tags: device.Tags, Notes: device.Notes})
	if err != nil || normalizedMetadata.FriendlyName != device.FriendlyName || normalizedMetadata.Owner != device.Owner || normalizedMetadata.Location != device.Location || normalizedMetadata.Category != device.Category || normalizedMetadata.Icon != device.Icon || normalizedMetadata.Notes != device.Notes || !sameStrings(normalizedMetadata.Tags, device.Tags) {
		return errors.New("device administrator metadata is invalid")
	}
	if err := validateAliasHistory(device); err != nil {
		return err
	}
	if !validCATrust(device.CATrust) {
		return errors.New("device CA trust state is invalid")
	}
	for _, identity := range device.Identities {
		if identity.Value == "" || identity.Confidence < 1 || identity.Confidence > 100 || !validIdentitySource(identity.Source) || identity.LastSeen.Before(identity.FirstSeen) {
			return errors.New("device identity evidence is invalid")
		}
		switch identity.Kind {
		case IdentityMAC:
			parsed, parseErr := net.ParseMAC(identity.Value)
			if parseErr != nil || len(parsed) != 6 || parsed.String() != identity.Value {
				return errors.New("device MAC identity evidence is invalid")
			}
		case IdentityDHCPClientID:
			if !validClientID(identity.Value) {
				return errors.New("device client identity evidence is invalid")
			}
		default:
			return errors.New("device identity kind is invalid")
		}
	}
	for _, address := range device.Addresses {
		if !validAddressEvidence(address) || address.Confidence < 1 || address.Confidence > 100 || !address.ValidUntil.After(address.ValidFrom) || address.ObservedAt.IsZero() || !validAddressScope(address.Interface, address.VLANID, address.ScopePlanSHA256) {
			return errors.New("device address evidence is invalid")
		}
	}
	for _, hostname := range device.Hostnames {
		if normalizeHostname(hostname.Hostname) != hostname.Hostname || hostname.Source != SourceDHCP4Lease || hostname.Confidence < 1 || hostname.Confidence > 100 || hostname.LastSeen.Before(hostname.FirstSeen) {
			return errors.New("device hostname evidence is invalid")
		}
	}
	switch device.VendorState {
	case "":
		if device.Vendor != nil {
			return errors.New("device vendor state is missing")
		}
	case VendorStateMatched:
		if device.Vendor == nil || !validSingleLine(device.Vendor.Name, 1, 256) || device.Vendor.Confidence < 1 || device.Vendor.Confidence > 100 || device.Vendor.ObservedAt.IsZero() || !sha256Pattern.MatchString(device.Vendor.DatabaseSHA256) {
			return errors.New("device vendor evidence is invalid")
		}
		expectedDigits := map[string]int{"MA-L": 6, "MA-M": 7, "MA-S": 9}[device.Vendor.Registry]
		if expectedDigits == 0 || len(device.Vendor.Assignment) != expectedDigits || !assignmentPattern.MatchString(device.Vendor.Assignment) {
			return errors.New("device vendor assignment is invalid")
		}
	case VendorStateNoMatch, VendorStateLocallyAdministered, VendorStateAmbiguous:
		if device.Vendor != nil {
			return errors.New("device vendor evidence conflicts with its state")
		}
	default:
		return errors.New("device vendor state is invalid")
	}
	return nil
}

func validAddressScope(interfaceName string, vlanID *int, planSHA256 string) bool {
	if interfaceName == "" {
		return vlanID == nil && planSHA256 == ""
	}
	return interfaceScopePattern.MatchString(interfaceName) && (vlanID == nil || *vlanID >= 1 && *vlanID <= 4094) && sha256Pattern.MatchString(planSHA256)
}

func validateAuditEvent(event AuditEvent) error {
	if event.Schema != SchemaVersion || !auditIDPattern.MatchString(event.ID) || !operationIDPattern.MatchString(event.OperationID) || !sha256Pattern.MatchString(event.RequestSHA256) || !validSingleLine(event.Actor, 1, 96) || event.OccurredAt.IsZero() || !sha256Pattern.MatchString(event.EntrySHA256) || event.PreviousSHA256 != "" && !sha256Pattern.MatchString(event.PreviousSHA256) {
		return errors.New("device audit identity or actor is invalid")
	}
	switch event.Action {
	case AuditMetadataUpdated, AuditAliasUpdated, AuditDevicesMerged, AuditDeviceSplit, AuditCATrustUpdated:
		if len(event.SourceDeviceIDs) < 1 || len(event.SourceDeviceIDs) > 2 || len(event.ResultDeviceIDs) < 1 || len(event.ResultDeviceIDs) > 2 || len(event.SourceAddressAliasIDs) != 0 || len(event.ResultAddressAliasIDs) != 0 {
			return errors.New("device audit evidence exceeds bounds")
		}
	case AuditAddressAliasCreated:
		if len(event.SourceDeviceIDs) != 0 || len(event.ResultDeviceIDs) != 0 || len(event.SourceAddressAliasIDs) != 0 || len(event.ResultAddressAliasIDs) != 1 {
			return errors.New("address alias creation audit evidence is invalid")
		}
	case AuditAddressAliasUpdated:
		if len(event.SourceDeviceIDs) != 0 || len(event.ResultDeviceIDs) != 0 || len(event.SourceAddressAliasIDs) != 1 || len(event.ResultAddressAliasIDs) != 1 || event.SourceAddressAliasIDs[0] != event.ResultAddressAliasIDs[0] {
			return errors.New("address alias update audit evidence is invalid")
		}
	case AuditAddressAliasDeleted:
		if len(event.SourceDeviceIDs) != 0 || len(event.ResultDeviceIDs) != 0 || len(event.SourceAddressAliasIDs) != 1 || len(event.ResultAddressAliasIDs) != 0 {
			return errors.New("address alias deletion audit evidence is invalid")
		}
	case AuditAliasTagsImported:
		if len(event.SourceDeviceIDs) < 1 || len(event.SourceDeviceIDs) > MaxAliasTagImport || len(event.ResultDeviceIDs) != len(event.SourceDeviceIDs) || !sameStrings(event.SourceDeviceIDs, event.ResultDeviceIDs) || len(event.SourceAddressAliasIDs) != 0 || len(event.ResultAddressAliasIDs) != 0 {
			return errors.New("device alias/tag import audit evidence is invalid")
		}
	default:
		return errors.New("device audit action is invalid")
	}
	if len(event.Changes) < 1 || len(event.Changes) > 32 {
		return errors.New("device audit evidence exceeds bounds")
	}
	for _, group := range [][]string{event.SourceDeviceIDs, event.ResultDeviceIDs} {
		seen := make(map[string]struct{}, len(group))
		for _, id := range group {
			if !ValidDeviceID(id) {
				return errors.New("device audit contains an invalid device ID")
			}
			if _, duplicate := seen[id]; duplicate {
				return errors.New("device audit contains a duplicate device ID")
			}
			seen[id] = struct{}{}
		}
	}
	for _, group := range [][]string{event.SourceAddressAliasIDs, event.ResultAddressAliasIDs} {
		seen := make(map[string]struct{}, len(group))
		for _, id := range group {
			if !ValidAddressAliasID(id) {
				return errors.New("device audit contains an invalid address alias ID")
			}
			if _, duplicate := seen[id]; duplicate {
				return errors.New("device audit contains a duplicate address alias ID")
			}
			seen[id] = struct{}{}
		}
	}
	for _, change := range event.Changes {
		if !validSingleLine(change, 1, 128) {
			return errors.New("device audit change is invalid")
		}
	}
	digest, err := auditEventDigest(event)
	if err != nil || digest != event.EntrySHA256 {
		return errors.New("device audit hash is invalid")
	}
	return nil
}

func validateAliasHistory(device Device) error {
	if device.AliasRevision == 0 {
		if len(device.AliasHistory) != 0 || device.AliasHistoryTruncated {
			return errors.New("device alias revision is invalid")
		}
		return nil
	}
	if len(device.AliasHistory) == 0 {
		return errors.New("device alias history is missing")
	}
	first := device.AliasHistory[0]
	if first.Revision == 0 || first.Revision > device.AliasRevision || first.Revision > 1 && !device.AliasHistoryTruncated || first.Revision == 1 && device.AliasHistoryTruncated {
		return errors.New("device alias history boundary is invalid")
	}
	for index, change := range device.AliasHistory {
		if change.Revision == 0 || change.ChangedAt.IsZero() || !validSingleLine(change.Actor, 1, 96) || !validSingleLine(change.Reason, 1, 256) || !validFriendlyName(change.FriendlyName) || !validFriendlyName(change.PreviousFriendlyName) || change.FriendlyName == change.PreviousFriendlyName {
			return errors.New("device alias history entry is invalid")
		}
		if index > 0 {
			previous := device.AliasHistory[index-1]
			if change.Revision != previous.Revision+1 || change.ChangedAt.Before(previous.ChangedAt) || change.PreviousFriendlyName != previous.FriendlyName {
				return errors.New("device alias history chain is invalid")
			}
		}
	}
	last := device.AliasHistory[len(device.AliasHistory)-1]
	if last.Revision != device.AliasRevision || last.FriendlyName != device.FriendlyName {
		return errors.New("device alias history does not match the current name")
	}
	return nil
}

func normalizeMetadata(metadata DeviceMetadata) (DeviceMetadata, error) {
	metadata.FriendlyName = normalizeFriendlyName(metadata.FriendlyName)
	metadata.Owner = strings.TrimSpace(metadata.Owner)
	metadata.Location = strings.TrimSpace(metadata.Location)
	metadata.Category = strings.ToLower(strings.TrimSpace(metadata.Category))
	metadata.Icon = strings.ToLower(strings.TrimSpace(metadata.Icon))
	metadata.Notes = strings.TrimSpace(metadata.Notes)
	if !validFriendlyName(metadata.FriendlyName) {
		return DeviceMetadata{}, errors.New("friendly name is invalid")
	}
	if metadata.Owner != "" && !validSingleLine(metadata.Owner, 1, 128) {
		return DeviceMetadata{}, errors.New("owner is invalid")
	}
	if metadata.Location != "" && !validSingleLine(metadata.Location, 1, 128) {
		return DeviceMetadata{}, errors.New("location is invalid")
	}
	if metadata.Category != "" && !categoryPattern.MatchString(metadata.Category) {
		return DeviceMetadata{}, errors.New("category is invalid")
	}
	if _, allowed := allowedDeviceIcons[metadata.Icon]; !allowed {
		return DeviceMetadata{}, errors.New("icon is invalid")
	}
	if len(metadata.Notes) > 4096 {
		return DeviceMetadata{}, errors.New("notes exceed their size limit")
	}
	for _, char := range metadata.Notes {
		if (char < 0x20 && char != '\n' && char != '\t') || char == 0x7f {
			return DeviceMetadata{}, errors.New("notes contain control characters")
		}
	}
	if len(metadata.Tags) > MaxTags {
		return DeviceMetadata{}, errors.New("tag limit exceeded")
	}
	tags := make([]string, 0, len(metadata.Tags))
	seen := make(map[string]struct{}, len(metadata.Tags))
	for _, tag := range metadata.Tags {
		tag = strings.ToLower(strings.TrimSpace(tag))
		if !validSingleLine(tag, 1, 64) {
			return DeviceMetadata{}, errors.New("tag is invalid")
		}
		if _, duplicate := seen[tag]; duplicate {
			continue
		}
		seen[tag] = struct{}{}
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	metadata.Tags = tags
	return metadata, nil
}

func normalizeFriendlyName(value string) string {
	return strings.TrimSpace(value)
}

func validFriendlyName(value string) bool {
	return value == "" || validSingleLine(value, 1, 128)
}

func validSingleLine(value string, min, max int) bool {
	if len(value) < min || len(value) > max || value != strings.TrimSpace(value) {
		return false
	}
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			return false
		}
	}
	return true
}

func sortDeviceEvidence(device *Device) {
	sort.Slice(device.Identities, func(i, j int) bool {
		if device.Identities[i].Kind != device.Identities[j].Kind {
			return device.Identities[i].Kind < device.Identities[j].Kind
		}
		return device.Identities[i].Value < device.Identities[j].Value
	})
	sort.Slice(device.Addresses, func(i, j int) bool {
		if device.Addresses[i].ValidFrom.Equal(device.Addresses[j].ValidFrom) {
			left, right := device.Addresses[i], device.Addresses[j]
			return left.Address+"\x00"+addressScopeKey(left.Interface, left.VLANID, left.ScopePlanSHA256) < right.Address+"\x00"+addressScopeKey(right.Interface, right.VLANID, right.ScopePlanSHA256)
		}
		return device.Addresses[i].ValidFrom.Before(device.Addresses[j].ValidFrom)
	})
	sort.Slice(device.Hostnames, func(i, j int) bool { return device.Hostnames[i].Hostname < device.Hostnames[j].Hostname })
	sort.Strings(device.Tags)
	sort.Strings(device.AttributionWarnings)
}

func addressScopeKey(interfaceName string, vlanID *int, planSHA256 string) string {
	vlan := ""
	if vlanID != nil {
		vlan = fmt.Sprintf("%d", *vlanID)
	}
	return interfaceName + "\x00" + vlan + "\x00" + planSHA256
}

func refreshFriendlyNameConflicts(devices []Device) {
	counts := make(map[string]int)
	for index := range devices {
		devices[index].FriendlyNameConflict = false
		if devices[index].FriendlyName != "" {
			counts[strings.ToLower(devices[index].FriendlyName)]++
		}
	}
	for index := range devices {
		if name := devices[index].FriendlyName; name != "" && counts[strings.ToLower(name)] > 1 {
			devices[index].FriendlyNameConflict = true
		}
	}
}

func projectSuggestedNames(device *Device) {
	device.SuggestedNames = nil
	seen := make(map[string]struct{})
	hostnames := append([]HostnameObservation(nil), device.Hostnames...)
	sort.Slice(hostnames, func(i, j int) bool {
		if hostnames[i].Confidence != hostnames[j].Confidence {
			return hostnames[i].Confidence > hostnames[j].Confidence
		}
		if !hostnames[i].LastSeen.Equal(hostnames[j].LastSeen) {
			return hostnames[i].LastSeen.After(hostnames[j].LastSeen)
		}
		return hostnames[i].Hostname < hostnames[j].Hostname
	})
	for _, hostname := range hostnames {
		name := normalizeFriendlyName(hostname.Hostname)
		key := strings.ToLower(name)
		if !validFriendlyName(name) || name == "" || strings.EqualFold(name, device.FriendlyName) {
			continue
		}
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		device.SuggestedNames = append(device.SuggestedNames, SuggestedName{Name: name, Source: hostname.Source, Confidence: hostname.Confidence, FirstSeen: hostname.FirstSeen, LastSeen: hostname.LastSeen})
		if len(device.SuggestedNames) == MaxSuggestedNames {
			break
		}
	}
}

func projectDevice(device Device) Device {
	projectSuggestedNames(&device)
	return device
}

func normalizeHostname(value string) string {
	value = strings.TrimSpace(strings.TrimSuffix(value, "."))
	if len(value) > 253 {
		return ""
	}
	for _, r := range value {
		if r < 0x21 || r == 0x7f {
			return ""
		}
	}
	return strings.ToLower(value)
}
