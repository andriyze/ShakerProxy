package trafficpolicy

import (
	"errors"
	"net/netip"
	"regexp"
	"time"

	deviceinventory "shakerproxy.dev/shakerproxy/internal/inventory"
)

var standaloneDeviceIDPattern = regexp.MustCompile(`^device-[a-f0-9]{32}$`)

type StandaloneDeviceRuntime struct {
	SchemaVersion int               `json:"schema_version"`
	GeneratedAt   time.Time         `json:"generated_at"`
	DeviceByIP    map[string]string `json:"device_by_ip"`
}

func EmptyStandaloneDeviceRuntime() StandaloneDeviceRuntime {
	return StandaloneDeviceRuntime{SchemaVersion: SchemaVersion, DeviceByIP: map[string]string{}}
}

// LoadStandaloneDeviceRuntimeFromInventory runs only in the privileged host
// policy process. It derives the narrow IP->stable-device map that may be
// published to mitmproxy; friendly names, MACs, owner, notes, tags, hostnames,
// and historical addresses never cross that runtime boundary.
func LoadStandaloneDeviceRuntimeFromInventory(path string, now time.Time) (StandaloneDeviceRuntime, error) {
	snapshot, err := (&deviceinventory.Store{Path: path}).Snapshot()
	if err != nil {
		return StandaloneDeviceRuntime{}, err
	}
	return ProjectStandaloneDeviceRuntime(snapshot, now)
}

// ProjectStandaloneDeviceRuntime accepts only currently valid, unambiguous
// address evidence. The persisted Active bit is necessary but not sufficient:
// a stalled inventory refresh must not allow an expired lease to keep mapping a
// newly reassigned IP to the prior device. Any stale, future, malformed, or
// ambiguous evidence is omitted so selective TLS interception fails open to
// passthrough instead of decrypting against uncertain identity.
func ProjectStandaloneDeviceRuntime(snapshot deviceinventory.Snapshot, now time.Time) (StandaloneDeviceRuntime, error) {
	now = now.UTC()
	if now.IsZero() || now.Year() < 2000 || now.Year() > 3000 {
		return StandaloneDeviceRuntime{}, errors.New("standalone device runtime time is invalid")
	}
	owners := make(map[string]string)
	ambiguous := make(map[string]bool)
	for _, device := range snapshot.Devices {
		if !deviceinventory.ValidDeviceID(device.ID) {
			return StandaloneDeviceRuntime{}, errors.New("inventory contains an invalid device ID")
		}
		for _, observed := range device.Addresses {
			if !observed.Active || observed.ValidFrom.IsZero() || observed.ValidUntil.IsZero() || observed.ValidFrom.After(now) || !observed.ValidUntil.After(now) {
				continue
			}
			address, parseErr := netip.ParseAddr(observed.Address)
			if parseErr != nil || address.IsUnspecified() || address.IsMulticast() {
				continue
			}
			canonical := address.String()
			if ambiguous[canonical] {
				continue
			}
			if previous, exists := owners[canonical]; exists && previous != device.ID {
				delete(owners, canonical)
				ambiguous[canonical] = true
				continue
			}
			owners[canonical] = device.ID
			if len(owners) > 8192 {
				return StandaloneDeviceRuntime{}, errors.New("standalone device runtime exceeds its address bound")
			}
		}
	}
	return StandaloneDeviceRuntime{SchemaVersion: SchemaVersion, GeneratedAt: now, DeviceByIP: owners}, nil
}

func (r StandaloneDeviceRuntime) Validate() error {
	if r.SchemaVersion != SchemaVersion || len(r.DeviceByIP) > 8192 {
		return errors.New("standalone device runtime schema or size is invalid")
	}
	for rawAddress, deviceID := range r.DeviceByIP {
		address, err := netip.ParseAddr(rawAddress)
		if err != nil || address.String() != rawAddress || address.IsUnspecified() || address.IsMulticast() || !standaloneDeviceIDPattern.MatchString(deviceID) {
			return errors.New("standalone device runtime contains an invalid device mapping")
		}
	}
	return nil
}
