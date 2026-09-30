package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"unicode/utf8"

	"shakerproxy.dev/shakerproxy/internal/apitoken"
	deviceinventory "shakerproxy.dev/shakerproxy/internal/inventory"
)

const (
	maxDeviceReferenceBytes = 128
	maxDeviceMatches        = 20
)

// Match kinds, in resolution order.
const (
	deviceMatchID           = "id"
	deviceMatchMAC          = "mac"
	deviceMatchIP           = "ip"
	deviceMatchName         = "name"
	deviceMatchNamePrefix   = "name_prefix"
	deviceMatchNameContains = "name_contains"
)

type deviceMatch struct {
	DeviceID          string   `json:"device_id"`
	FriendlyName      string   `json:"friendly_name"`
	Vendor            string   `json:"vendor"`
	Addresses         []string `json:"addresses"`
	HardwareAddresses []string `json:"hardware_addresses"`
	Online            bool     `json:"online"`
	Match             string   `json:"match"`
}

type deviceResolution struct {
	Schema  int           `json:"schema"`
	Query   string        `json:"query"`
	Unique  bool          `json:"unique"`
	Matches []deviceMatch `json:"matches"`
}

// deviceRefError is a device-reference failure that carries the HTTP status,
// a stable code, a sentence that says what to do next, and candidates when
// the reference was ambiguous.
type deviceRefError struct {
	status     int
	code       string
	message    string
	candidates []deviceMatch
}

func (e *deviceRefError) Error() string { return e.message }

func (s *Server) resolveDevice(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	values := r.URL.Query()
	for key, entries := range values {
		if key != "q" || len(entries) != 1 {
			writeError(w, http.StatusBadRequest, "invalid_query", "Use exactly one ?q= with a device name, IP address, MAC address, or device ID.")
			return
		}
	}
	query := strings.TrimSpace(values.Get("q"))
	if err := validateDeviceReference(query); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_query", err.Error())
		return
	}
	devices, err := s.inventoryDevices()
	if err != nil {
		writeDeviceRefError(w, err)
		return
	}
	matches := matchDevices(devices, query)
	writeJSON(w, http.StatusOK, deviceResolution{Schema: 1, Query: query, Unique: len(matches) == 1, Matches: matches})
}

// resolveDeviceRef resolves a friendly name, IP address, MAC address, or
// device ID to exactly one device. Errors are *deviceRefError values.
func (s *Server) resolveDeviceRef(ctx context.Context, ref string) (deviceinventory.Device, error) {
	if err := ctx.Err(); err != nil {
		return deviceinventory.Device{}, err
	}
	ref = strings.TrimSpace(ref)
	if err := validateDeviceReference(ref); err != nil {
		return deviceinventory.Device{}, &deviceRefError{status: http.StatusBadRequest, code: "invalid_device", message: err.Error()}
	}
	devices, err := s.inventoryDevices()
	if err != nil {
		return deviceinventory.Device{}, err
	}
	matches := matchDevices(devices, ref)
	switch len(matches) {
	case 0:
		return deviceinventory.Device{}, &deviceRefError{
			status: http.StatusNotFound, code: "device_not_found",
			message: fmt.Sprintf("No device matches %q. Run `shakerproxy devices` or open Devices to see device names, addresses, and IDs.", ref),
		}
	case 1:
		for _, device := range devices {
			if device.ID == matches[0].DeviceID {
				return device, nil
			}
		}
		return deviceinventory.Device{}, &deviceRefError{status: http.StatusNotFound, code: "device_not_found", message: fmt.Sprintf("No device matches %q. Run `shakerproxy devices` or open Devices.", ref)}
	default:
		names := make([]string, 0, min(len(matches), 5))
		for _, match := range matches[:min(len(matches), 5)] {
			names = append(names, match.FriendlyName)
		}
		more := ""
		if len(matches) > 5 {
			more = ", …"
		}
		return deviceinventory.Device{}, &deviceRefError{
			status: http.StatusConflict, code: "device_ambiguous", candidates: matches,
			message: fmt.Sprintf("%q matches %d devices (%s%s). Use the full name, the IP or MAC address, or the device ID.", ref, len(matches), strings.Join(names, ", "), more),
		}
	}
}

func (s *Server) inventoryDevices() ([]deviceinventory.Device, error) {
	if s.inventory == nil {
		return nil, &deviceRefError{status: http.StatusServiceUnavailable, code: "inventory_unavailable", message: "The device inventory is not configured. Check System → Status."}
	}
	snapshot, err := s.inventory.Snapshot()
	if err != nil {
		return nil, &deviceRefError{status: http.StatusServiceUnavailable, code: "inventory_unavailable", message: "The device inventory is unavailable right now. Try again, or check System → Status."}
	}
	return snapshot.Devices, nil
}

func writeDeviceRefError(w http.ResponseWriter, err error) {
	var refErr *deviceRefError
	if !errors.As(err, &refErr) {
		writeError(w, http.StatusServiceUnavailable, "inventory_unavailable", "The device inventory is unavailable right now. Try again, or check System → Status.")
		return
	}
	body := map[string]any{"code": refErr.code, "message": refErr.message}
	if len(refErr.candidates) > 0 {
		body["candidates"] = refErr.candidates
	}
	writeJSON(w, refErr.status, map[string]any{"error": body})
}

// requireDeviceAccess re-checks API token device restrictions against the
// resolved device. Session users and unrestricted tokens always pass.
func requireDeviceAccess(ctx context.Context, deviceID string) error {
	principal, ok := ctx.Value(apiPrincipalContextKey{}).(apitoken.Principal)
	if !ok || len(principal.Restrictions.DeviceIDs) == 0 {
		return nil
	}
	for _, allowed := range principal.Restrictions.DeviceIDs {
		if allowed == deviceID {
			return nil
		}
	}
	return &deviceRefError{status: http.StatusForbidden, code: "resource_restricted", message: "This API token is not allowed to read this device. Use a token without device restrictions."}
}

func validateDeviceReference(ref string) error {
	if ref == "" {
		return errors.New("Give a device name, IP address, MAC address, or device ID.")
	}
	if len(ref) > maxDeviceReferenceBytes || !utf8.ValidString(ref) {
		return errors.New("Device references are limited to 128 characters.")
	}
	for _, character := range ref {
		if character < 0x20 || character == 0x7f {
			return errors.New("Device references cannot contain control characters.")
		}
	}
	return nil
}

// matchDevices applies the resolution order: exact device ID, exact MAC (any
// case or separator), exact current IP (then the most recent past holder of
// that IP), exact name (case-insensitive), unique name prefix, then name
// substring. It returns the matches of the first level that matched.
func matchDevices(devices []deviceinventory.Device, ref string) []deviceMatch {
	lowered := strings.ToLower(strings.TrimSpace(ref))
	if deviceinventory.ValidDeviceID(lowered) {
		for _, device := range devices {
			if device.ID == lowered {
				return []deviceMatch{newDeviceMatch(device, deviceMatchID)}
			}
		}
		return []deviceMatch{}
	}
	if mac, ok := normalizeMACReference(ref); ok {
		matches := []deviceMatch{}
		for _, device := range devices {
			for _, identity := range device.Identities {
				if identity.Kind == deviceinventory.IdentityMAC {
					if value, valid := normalizeMACReference(identity.Value); valid && value == mac {
						matches = append(matches, newDeviceMatch(device, deviceMatchMAC))
						break
					}
				}
			}
		}
		if len(matches) > 0 {
			return boundMatches(matches)
		}
	}
	if address, err := netip.ParseAddr(strings.Trim(ref, "[]")); err == nil {
		return matchDeviceAddress(devices, address.Unmap().String())
	}
	return matchDeviceNames(devices, ref)
}

func matchDeviceAddress(devices []deviceinventory.Device, address string) []deviceMatch {
	current := []deviceMatch{}
	var recent *deviceinventory.Device
	var recentAt int64
	for index := range devices {
		device := devices[index]
		for _, observation := range device.Addresses {
			if observation.Address != address {
				continue
			}
			if observation.Active {
				current = append(current, newDeviceMatch(device, deviceMatchIP))
				break
			}
			if seen := observation.ObservedAt.UnixNano(); recent == nil || seen > recentAt {
				recent, recentAt = &devices[index], seen
			}
		}
	}
	if len(current) > 0 {
		return boundMatches(current)
	}
	if recent != nil {
		return []deviceMatch{newDeviceMatch(*recent, deviceMatchIP)}
	}
	return []deviceMatch{}
}

func matchDeviceNames(devices []deviceinventory.Device, ref string) []deviceMatch {
	wanted := looseName(ref)
	if wanted == "" {
		return []deviceMatch{}
	}
	levels := [][]deviceMatch{{}, {}, {}, {}}
	for _, device := range devices {
		friendly := looseName(device.FriendlyName)
		others := []string{}
		for _, suggestion := range device.SuggestedNames {
			others = append(others, looseName(suggestion.Name))
		}
		for _, hostname := range device.Hostnames {
			others = append(others, looseName(hostname.Hostname))
		}
		all := append([]string{friendly}, others...)
		switch {
		case friendly != "" && friendly == wanted:
			levels[0] = append(levels[0], newDeviceMatch(device, deviceMatchName))
		case hasExactName(others, wanted):
			levels[1] = append(levels[1], newDeviceMatch(device, deviceMatchName))
		case anyName(all, func(name string) bool { return strings.HasPrefix(name, wanted) }):
			levels[2] = append(levels[2], newDeviceMatch(device, deviceMatchNamePrefix))
		case anyName(all, func(name string) bool { return strings.Contains(name, wanted) }):
			levels[3] = append(levels[3], newDeviceMatch(device, deviceMatchNameContains))
		}
	}
	for _, level := range levels {
		if len(level) > 0 {
			return boundMatches(level)
		}
	}
	return []deviceMatch{}
}

// looseName lowercases a name and treats spaces, hyphens, underscores, and
// dots alike so "living-room-tv" matches "Living room TV".
func looseName(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	fields := strings.FieldsFunc(value, func(character rune) bool {
		return character == ' ' || character == '-' || character == '_' || character == '.' || character == '\t'
	})
	return strings.Join(fields, " ")
}

func hasExactName(values []string, wanted string) bool {
	for _, value := range values {
		if value != "" && value == wanted {
			return true
		}
	}
	return false
}

func anyName(values []string, predicate func(string) bool) bool {
	for _, value := range values {
		if value != "" && predicate(value) {
			return true
		}
	}
	return false
}

func boundMatches(matches []deviceMatch) []deviceMatch {
	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].Online != matches[j].Online {
			return matches[i].Online
		}
		if matches[i].FriendlyName != matches[j].FriendlyName {
			return strings.ToLower(matches[i].FriendlyName) < strings.ToLower(matches[j].FriendlyName)
		}
		return matches[i].DeviceID < matches[j].DeviceID
	})
	if len(matches) > maxDeviceMatches {
		matches = matches[:maxDeviceMatches]
	}
	return matches
}

// normalizeMACReference accepts aa:bb:cc:dd:ee:ff, AA-BB-CC-DD-EE-FF,
// aabb.ccdd.eeff, or aabbccddeeff and returns the canonical colon form.
func normalizeMACReference(value string) (string, bool) {
	var digits strings.Builder
	for _, character := range strings.TrimSpace(value) {
		switch {
		case character == ':' || character == '-' || character == '.' || character == ' ':
			continue
		case character >= '0' && character <= '9', character >= 'a' && character <= 'f':
			digits.WriteRune(character)
		case character >= 'A' && character <= 'F':
			digits.WriteRune(character + ('a' - 'A'))
		default:
			return "", false
		}
		if digits.Len() > 12 {
			return "", false
		}
	}
	raw := digits.String()
	if len(raw) != 12 {
		return "", false
	}
	parts := make([]string, 0, 6)
	for index := 0; index < 12; index += 2 {
		parts = append(parts, raw[index:index+2])
	}
	return strings.Join(parts, ":"), true
}

func newDeviceMatch(device deviceinventory.Device, kind string) deviceMatch {
	vendor := ""
	if device.Vendor != nil {
		vendor = device.Vendor.Name
	}
	return deviceMatch{
		DeviceID:          device.ID,
		FriendlyName:      deviceDisplayName(device),
		Vendor:            vendor,
		Addresses:         deviceCurrentAddresses(device),
		HardwareAddresses: deviceHardwareAddresses(device),
		Online:            device.Online,
		Match:             kind,
	}
}

// deviceCurrentAddresses returns active addresses, or the most recently
// observed one when none is active.
func deviceCurrentAddresses(device deviceinventory.Device) []string {
	addresses := []string{}
	var latest string
	var latestAt int64
	for _, observation := range device.Addresses {
		if observation.Active && !hasExactName(addresses, observation.Address) {
			addresses = append(addresses, observation.Address)
		}
		if seen := observation.ObservedAt.UnixNano(); latest == "" || seen > latestAt {
			latest, latestAt = observation.Address, seen
		}
	}
	if len(addresses) == 0 && latest != "" {
		addresses = append(addresses, latest)
	}
	sort.Strings(addresses)
	return addresses
}

func deviceHardwareAddresses(device deviceinventory.Device) []string {
	addresses := []string{}
	for _, identity := range device.Identities {
		if identity.Kind == deviceinventory.IdentityMAC && !hasExactName(addresses, identity.Value) {
			addresses = append(addresses, identity.Value)
		}
	}
	sort.Strings(addresses)
	return addresses
}
