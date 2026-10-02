package wifi

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

// ScopeSchema is the version of the scope file gatewayd writes for the
// Wi-Fi worker.
const ScopeSchema = 1

const (
	// MaxScopeMACs bounds the lab device addresses in a scope.
	MaxScopeMACs      = 4096
	maxScopeNetworks  = 16
	maxScopeFileBytes = 1 << 20
)

// Event scopes: frames of lab devices and the lab's own network, or of
// devices and networks nearby (recorded only when the tester opts in).
const (
	ScopeLab    = "lab"
	ScopeNearby = "nearby"
)

// ScopeFile is what the worker may record. gatewayd writes it from the
// confirmed lab (its access point and SSID), the lab's neighbor tables
// (every lab device's current address) and the tester's settings.
type ScopeFile struct {
	Schema int `json:"schema"`
	// LabBSSIDs are ShakerProxy's own access point addresses.
	LabBSSIDs []string `json:"lab_bssids"`
	// LabSSIDs are the lab Wi-Fi network names.
	LabSSIDs []string `json:"lab_ssids"`
	// LabMACs are the hardware addresses of lab devices.
	LabMACs []string `json:"lab_macs"`
	// Nearby is the tester's opt-in to record devices and networks that are
	// not part of the lab.
	Nearby      bool      `json:"nearby"`
	GeneratedAt time.Time `json:"generated_at"`
}

// Validate checks the bounds and formats of a scope file.
func (s ScopeFile) Validate() error {
	if s.Schema != ScopeSchema || s.GeneratedAt.IsZero() {
		return errors.New("Wi-Fi scope schema or time is invalid")
	}
	if len(s.LabBSSIDs) > maxScopeNetworks || len(s.LabSSIDs) > maxScopeNetworks || len(s.LabMACs) > MaxScopeMACs {
		return errors.New("Wi-Fi scope exceeds its bounds")
	}
	for _, values := range [][]string{s.LabBSSIDs, s.LabMACs} {
		for _, value := range values {
			if mac, ok := ParseMAC(value); !ok || mac.Group() || mac.Zero() {
				return fmt.Errorf("Wi-Fi scope address %q is invalid", value)
			}
		}
	}
	for _, ssid := range s.LabSSIDs {
		if ssid == "" || len(ssid) > 4*MaxSSIDBytes {
			return errors.New("Wi-Fi scope network name is invalid")
		}
	}
	return nil
}

// ReadScopeFile reads and validates a scope file.
func ReadScopeFile(path string) (ScopeFile, error) {
	file, err := os.Open(path)
	if err != nil {
		return ScopeFile{}, err
	}
	defer file.Close()
	decoder := json.NewDecoder(&limitedReader{reader: file, remaining: maxScopeFileBytes})
	decoder.DisallowUnknownFields()
	var scope ScopeFile
	if err := decoder.Decode(&scope); err != nil {
		return ScopeFile{}, fmt.Errorf("decode Wi-Fi scope: %w", err)
	}
	return scope, scope.Validate()
}

type limitedReader struct {
	reader    interface{ Read([]byte) (int, error) }
	remaining int
}

func (l *limitedReader) Read(buffer []byte) (int, error) {
	if l.remaining <= 0 {
		return 0, errors.New("Wi-Fi scope file is too large")
	}
	if len(buffer) > l.remaining {
		buffer = buffer[:l.remaining]
	}
	count, err := l.reader.Read(buffer)
	l.remaining -= count
	return count, err
}

// Scope decides which frames may be recorded.
type Scope struct {
	bssids map[MAC]bool
	ssids  map[string]bool
	macs   map[MAC]bool
	nearby bool
}

// CompileScope indexes a validated scope file.
func CompileScope(file ScopeFile) *Scope {
	scope := &Scope{bssids: map[MAC]bool{}, ssids: map[string]bool{}, macs: map[MAC]bool{}, nearby: file.Nearby}
	for _, value := range file.LabBSSIDs {
		if mac, ok := ParseMAC(value); ok {
			scope.bssids[mac] = true
		}
	}
	for _, value := range file.LabMACs {
		if mac, ok := ParseMAC(value); ok {
			scope.macs[mac] = true
		}
	}
	for _, value := range file.LabSSIDs {
		scope.ssids[value] = true
	}
	return scope
}

// Nearby reports the tester's opt-in to record what is not part of the lab.
func (s *Scope) Nearby() bool { return s != nil && s.nearby }

// LabBSSID reports ShakerProxy's own access point.
func (s *Scope) LabBSSID(mac MAC) bool { return s != nil && s.bssids[mac] }

// LabSSID reports the lab network's name.
func (s *Scope) LabSSID(name string) bool { return s != nil && name != "" && s.ssids[name] }

// LabMAC reports a lab device address the scope lists.
func (s *Scope) LabMAC(mac MAC) bool { return s != nil && s.macs[mac] }
