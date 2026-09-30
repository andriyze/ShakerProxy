package detection

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"shakerproxy.dev/shakerproxy/internal/ingest"
	"shakerproxy.dev/shakerproxy/internal/resourcepressure"
)

type Type string
type Severity string
type State string
type ObservationKind string

const (
	RogueDHCP             Type = "ROGUE_DHCP"
	RogueRA               Type = "ROGUE_RA"
	GatewaySpoofSuspected Type = "GATEWAY_SPOOF_SUSPECTED"
	ClockDrift            Type = "CLOCK_DRIFT"
	CaptureDegraded       Type = "CAPTURE_DEGRADED"
	StoragePressure       Type = "STORAGE_PRESSURE"
	CPUPressure           Type = "CPU_PRESSURE"
	MemoryPressure        Type = "MEMORY_PRESSURE"

	SeverityWarning  Severity = "WARNING"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
	StateOpen        State    = "OPEN"
	StateResolved    State    = "RESOLVED"

	ObserveDHCP     ObservationKind = "DHCP_SERVER"
	ObserveRA       ObservationKind = "ROUTER_ADVERTISEMENT"
	ObserveGateway  ObservationKind = "GATEWAY_CLAIM"
	ObserveClock    ObservationKind = "CLOCK"
	ObserveCapture  ObservationKind = "CAPTURE"
	ObserveResource ObservationKind = "RESOURCE"
)

var safeScopePattern = regexp.MustCompile(`^[A-Za-z0-9_.:/=@-]{1,256}$`)

type Observation struct {
	Schema            int                      `json:"schema"`
	Kind              ObservationKind          `json:"kind"`
	OccurredAt        time.Time                `json:"occurred_at"`
	Interface         string                   `json:"interface,omitempty"`
	VLANID            int                      `json:"vlan_id,omitempty"`
	SourceIdentity    string                   `json:"source_identity,omitempty"`
	ClaimedAddress    string                   `json:"claimed_address,omitempty"`
	Authorized        bool                     `json:"authorized"`
	ClockSynchronized bool                     `json:"clock_synchronized"`
	ClockOffsetMillis int64                    `json:"clock_offset_millis,omitempty"`
	CaptureState      string                   `json:"capture_state,omitempty"`
	PacketDrops       uint64                   `json:"packet_drops,omitempty"`
	FeedEvictions     uint64                   `json:"feed_evictions,omitempty"`
	Pressure          *resourcepressure.Report `json:"resource_pressure,omitempty"`
}

type Candidate struct {
	Type     Type
	Severity Severity
	Scope    string
	Summary  string
	Active   bool
	At       time.Time
}

type Event struct {
	Schema      int       `json:"schema"`
	ID          string    `json:"id"`
	Type        Type      `json:"type"`
	Severity    Severity  `json:"severity"`
	State       State     `json:"state"`
	Summary     string    `json:"summary"`
	Scope       string    `json:"scope"`
	FirstSeenAt time.Time `json:"first_seen_at"`
	LastSeenAt  time.Time `json:"last_seen_at"`
	Revision    uint64    `json:"revision"`
}

type Config struct {
	AuthorizedDHCPServers map[string]bool
	AuthorizedRAs         map[string]bool
	GatewayBindings       map[string]string
}

type snapshot struct {
	Schema   int              `json:"schema"`
	Revision uint64           `json:"revision"`
	Open     map[string]Event `json:"open"`
}

type Manager struct {
	mu     sync.Mutex
	path   string
	config Config
}

func New(path string, config Config) (*Manager, error) {
	if !filepath.IsAbs(path) || filepath.Base(path) == "." || filepath.Base(path) == string(filepath.Separator) {
		return nil, errors.New("detection state path must be an absolute file")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	manager := &Manager{path: path, config: config}
	if _, err := manager.load(); err != nil {
		return nil, err
	}
	return manager, nil
}

func (m *Manager) Observe(observation Observation) ([]Event, error) {
	candidates, err := Evaluate(observation)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	state, err := m.load()
	if err != nil {
		return nil, err
	}
	events := []Event{}
	for _, candidate := range candidates {
		key := string(candidate.Type) + "|" + candidate.Scope
		current, open := state.Open[key]
		if candidate.Active {
			if open && current.Severity == candidate.Severity && current.Summary == candidate.Summary {
				continue
			}
			state.Revision++
			first := candidate.At
			if open {
				first = current.FirstSeenAt
			}
			event := newEvent(candidate, StateOpen, first, state.Revision)
			state.Open[key] = event
			events = append(events, event)
		} else if open {
			state.Revision++
			event := newEvent(candidate, StateResolved, current.FirstSeenAt, state.Revision)
			delete(state.Open, key)
			events = append(events, event)
		}
	}
	if len(events) > 0 {
		if err := m.save(state); err != nil {
			return nil, err
		}
	}
	return events, nil
}

func Evaluate(observation Observation) ([]Candidate, error) {
	if observation.Schema != 1 || observation.OccurredAt.IsZero() || observation.OccurredAt.After(time.Now().Add(5*time.Minute)) {
		return nil, errors.New("detection observation is invalid")
	}
	scope := strings.Trim(strings.Join([]string{observation.Interface, fmt.Sprintf("vlan=%d", observation.VLANID), observation.SourceIdentity, observation.ClaimedAddress}, "/"), "/")
	if !safeScopePattern.MatchString(scope) {
		return nil, errors.New("detection observation scope is invalid")
	}
	candidate := func(t Type, severity Severity, summary string, active bool) Candidate {
		return Candidate{Type: t, Severity: severity, Scope: scope, Summary: summary, Active: active, At: observation.OccurredAt.UTC()}
	}
	switch observation.Kind {
	case ObserveDHCP:
		return []Candidate{candidate(RogueDHCP, SeverityHigh, "Unapproved DHCP server response observed on the lab segment", !observation.Authorized)}, nil
	case ObserveRA:
		return []Candidate{candidate(RogueRA, SeverityHigh, "Unapproved IPv6 router advertisement observed on the lab segment", !observation.Authorized)}, nil
	case ObserveGateway:
		return []Candidate{candidate(GatewaySpoofSuspected, SeverityCritical, "Another link-layer identity claimed a configured gateway address", !observation.Authorized)}, nil
	case ObserveClock:
		active := !observation.ClockSynchronized || observation.ClockOffsetMillis > 5000 || observation.ClockOffsetMillis < -5000
		return []Candidate{candidate(ClockDrift, SeverityWarning, "Clock synchronization or offset threatens evidence timestamps", active)}, nil
	case ObserveCapture:
		active := observation.CaptureState == "FAILED" || observation.CaptureState == "STORAGE_PRESSURE" || observation.PacketDrops > 0 || observation.FeedEvictions > 0
		return []Candidate{candidate(CaptureDegraded, SeverityHigh, "Capture loss, failure, or analyzer-feed eviction was recorded", active)}, nil
	case ObserveResource:
		if observation.Pressure == nil {
			return nil, errors.New("resource observation requires a pressure report")
		}
		causes := map[string]bool{}
		for _, cause := range observation.Pressure.Causes {
			causes[cause] = true
		}
		severity := SeverityWarning
		if observation.Pressure.Level == resourcepressure.LevelCritical {
			severity = SeverityCritical
		}
		return []Candidate{
			candidate(CPUPressure, severity, "Sustained CPU pressure crossed the appliance degradation threshold", causes["CPU_PSI_DEGRADED"] || causes["CPU_PSI_CRITICAL"]),
			candidate(MemoryPressure, severity, "Available memory crossed the appliance degradation threshold", causes["MEMORY_AVAILABLE_DEGRADED"] || causes["MEMORY_AVAILABLE_CRITICAL"]),
			candidate(StoragePressure, severity, "Managed storage crossed the emergency reserve threshold", causes["DISK_RESERVE_DEGRADED"] || causes["DISK_RESERVE_CRITICAL"]),
		}, nil
	default:
		return nil, errors.New("unknown detection observation kind")
	}
}

func (m *Manager) ObservationsFromEnvelope(envelope ingest.Envelope) []Observation {
	if envelope.Source == ingest.SourceHost && envelope.Kind == "shakerproxy.observation" {
		var observation Observation
		decoder := json.NewDecoder(bytes.NewReader(envelope.Payload))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&observation) == nil && decoder.Decode(&struct{}{}) == io.EOF {
			observation.OccurredAt = envelope.OccurredAt
			return []Observation{observation}
		}
		return nil
	}
	var raw map[string]any
	decoder := json.NewDecoder(bytes.NewReader(envelope.Payload))
	decoder.UseNumber()
	if decoder.Decode(&raw) != nil {
		return nil
	}
	identity := firstString(raw, "src_mac", "server_id", "src_ip")
	iface := firstString(raw, "in_iface", "interface")
	if strings.Contains(envelope.Kind, "dhcp") && len(m.config.AuthorizedDHCPServers) > 0 {
		dhcp, _ := raw["dhcp"].(map[string]any)
		message := strings.ToUpper(firstString(dhcp, "type", "dhcp_type", "message_type"))
		if message == "OFFER" || message == "ACK" || message == "NAK" {
			if identity == "" {
				identity = firstString(dhcp, "server_id")
			}
			return []Observation{{Schema: 1, Kind: ObserveDHCP, OccurredAt: envelope.OccurredAt, Interface: iface, SourceIdentity: identity, Authorized: m.config.AuthorizedDHCPServers[strings.ToLower(identity)]}}
		}
	}
	if strings.Contains(envelope.Kind, "icmpv6") && len(m.config.AuthorizedRAs) > 0 {
		icmp, _ := raw["icmpv6"].(map[string]any)
		message := strings.ToUpper(firstString(icmp, "type", "message_type"))
		if message == "134" || message == "ROUTER_ADVERTISEMENT" || message == "RA" {
			return []Observation{{Schema: 1, Kind: ObserveRA, OccurredAt: envelope.OccurredAt, Interface: iface, SourceIdentity: identity, Authorized: m.config.AuthorizedRAs[strings.ToLower(identity)]}}
		}
	}
	if strings.Contains(envelope.Kind, "arp") && len(m.config.GatewayBindings) > 0 {
		arp, _ := raw["arp"].(map[string]any)
		claimed := firstString(arp, "src_ip", "sender_ip", "claimed_ip")
		mac := firstString(arp, "src_mac", "sender_mac")
		if expected, monitored := m.config.GatewayBindings[claimed]; monitored {
			return []Observation{{Schema: 1, Kind: ObserveGateway, OccurredAt: envelope.OccurredAt, Interface: iface, SourceIdentity: mac, ClaimedAddress: claimed, Authorized: strings.EqualFold(mac, expected)}}
		}
	}
	return nil
}

func newEvent(candidate Candidate, state State, first time.Time, revision uint64) Event {
	digest := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|%d", candidate.Type, candidate.Scope, state, revision)))
	return Event{Schema: 1, ID: "detection-" + hex.EncodeToString(digest[:16]), Type: candidate.Type, Severity: candidate.Severity, State: state, Summary: candidate.Summary, Scope: candidate.Scope, FirstSeenAt: first, LastSeenAt: candidate.At, Revision: revision}
}

func (m *Manager) load() (snapshot, error) {
	state := snapshot{Schema: 1, Open: map[string]Event{}}
	info, err := os.Lstat(m.path)
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 1<<20 {
		return snapshot{}, errors.New("detection state is unsafe")
	}
	contents, err := os.ReadFile(m.path)
	if err != nil {
		return snapshot{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&state) != nil || decoder.Decode(&struct{}{}) != io.EOF || state.Schema != 1 || state.Open == nil || len(state.Open) > 4096 {
		return snapshot{}, errors.New("detection state is corrupt")
	}
	return state, nil
}

func (m *Manager) save(state snapshot) error {
	encoded, err := json.Marshal(state)
	if err != nil || len(encoded) > 1<<20 {
		return errors.New("detection state exceeds its limit")
	}
	temporary, err := os.CreateTemp(filepath.Dir(m.path), ".detection-state-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
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
	return os.Rename(temporaryPath, m.path)
}

func firstString(values map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := values[key].(string); ok {
			value = strings.ToLower(strings.TrimSpace(value))
			if safeScopePattern.MatchString(value) {
				return value
			}
		}
	}
	return ""
}

func SortedSet(values string) map[string]bool {
	result := map[string]bool{}
	parts := strings.Split(values, ",")
	sort.Strings(parts)
	for _, value := range parts {
		value = strings.ToLower(strings.TrimSpace(value))
		if safeScopePattern.MatchString(value) {
			result[value] = true
		}
	}
	return result
}

func GatewayBindingSet(values string) map[string]string {
	result := map[string]string{}
	for _, value := range strings.Split(values, ",") {
		parts := strings.SplitN(strings.ToLower(strings.TrimSpace(value)), "=", 2)
		if len(parts) == 2 && safeScopePattern.MatchString(parts[0]) && safeScopePattern.MatchString(parts[1]) {
			result[parts[0]] = parts[1]
		}
	}
	return result
}
