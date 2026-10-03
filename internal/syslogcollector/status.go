package syslogcollector

import (
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// StatusSchema versions the status file the collector writes for control-api.
const StatusSchema = 1

// Status is what the Integrations page shows: whether the collector is on,
// where it listens, which sources it accepts, and the receiver's counts and
// per-source liveness. It never contains message content.
type Status struct {
	Schema         int       `json:"schema"`
	GeneratedAt    time.Time `json:"generated_at"`
	Enabled        bool      `json:"enabled"`
	BindAddress    string    `json:"bind_address"`
	TCP            bool      `json:"tcp"`
	UDP            bool      `json:"udp"`
	AllowedSources []string  `json:"allowed_sources"`
	Stats          Stats     `json:"stats"`
}

// ParseAllowedSources parses a comma or space separated list of source
// addresses into a deduplicated, ordered slice. An entry that is not a valid
// IP address is an error, so a typo never silently widens who is trusted.
func ParseAllowedSources(value string) ([]netip.Addr, error) {
	seen := map[netip.Addr]bool{}
	var addresses []netip.Addr
	for _, field := range strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		address, err := netip.ParseAddr(field)
		if err != nil {
			return nil, errors.New("allowed syslog source is not an IP address: " + field)
		}
		address = address.Unmap()
		if !seen[address] {
			seen[address] = true
			addresses = append(addresses, address)
		}
	}
	return addresses, nil
}

// WriteStatusFile writes the status atomically with mode 0640, like the other
// services' state files, so control-api (running as another user in the app
// group) can read it while nothing else can.
func WriteStatusFile(path string, status Status) error {
	status.Schema = StatusSchema
	if status.GeneratedAt.IsZero() {
		status.GeneratedAt = time.Now().UTC()
	}
	encoded, err := json.Marshal(status)
	if err != nil {
		return err
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".syslog-status-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o640); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
