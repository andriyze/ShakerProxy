package ingest

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// A device announces and looks for services over mDNS/Bonjour the moment it
// joins a network: AirPlay, Chromecast, printing, HomeKit. Those service
// types say what a device is and what it does even when the rest of its
// traffic never reaches ShakerProxy, because mDNS is multicast to the whole
// segment. This reads them from the recorded discovery traffic.

const (
	DeviceServiceHintsSchema = 1
	// DeviceServiceWindow is how far back the discovery traffic is read.
	DeviceServiceWindow = 7 * 24 * time.Hour
	// MaxDeviceServiceHints bounds the response, like the platform hints.
	MaxDeviceServiceHints        = 10000
	maxDeviceServiceObservations = 8 * MaxDeviceServiceHints
	// MaxServicesPerDevice bounds the services listed for one device.
	MaxServicesPerDevice = 12
)

// serviceInfo describes one mDNS service type. typeHint is the device type
// the service implies on its own, "" when it says nothing specific (SSH,
// file sharing). typeRank orders those hints: a more specific service (a
// Chromecast's _googlecast) outranks a generic Apple-continuity hint.
type serviceInfo struct {
	label    string
	category string
	typeHint string
	typeRank int
}

// serviceCatalog maps an mDNS service type (without the instance name or the
// .local suffix) to what it means. It is deliberately small and
// conservative; an unlisted service is still shown generically, without a
// type claim. The services here were seen on real networks or are the
// well-known Bonjour/DNS-SD types for common consumer devices.
var serviceCatalog = map[string]serviceInfo{
	"_rdlink._tcp":          {"Apple Continuity", "apple", "Apple device", 1},
	"_companion-link._tcp":  {"Apple Continuity", "apple", "Apple device", 1},
	"_apple-mobdev2._tcp":   {"Apple device sync", "apple", "Apple device", 1},
	"_atc._tcp":             {"Apple shared library", "apple", "Apple device", 1},
	"_sleep-proxy._udp":     {"Bonjour Sleep Proxy", "apple", "Apple device", 1},
	"_touch-able._tcp":      {"Apple TV remote", "apple", "Apple TV", 3},
	"_appletv-v2._tcp":      {"Apple TV", "media", "Apple TV", 3},
	"_airport._tcp":         {"AirPort base station", "apple", "Apple AirPort", 3},
	"_airplay._tcp":         {"AirPlay", "media", "AirPlay receiver", 2},
	"_raop._tcp":            {"AirPlay audio", "audio", "AirPlay speaker", 2},
	"_googlecast._tcp":      {"Google Cast", "cast", "Chromecast / Google Cast device", 3},
	"_googlezone._tcp":      {"Google Home", "speaker", "Google Home", 2},
	"_spotify-connect._tcp": {"Spotify Connect", "speaker", "Speaker (Spotify Connect)", 2},
	"_sonos._tcp":           {"Sonos", "speaker", "Sonos speaker", 3},
	"_amzn-wplay._tcp":      {"Amazon Fire TV", "media", "Amazon Fire TV", 3},
	"_amzn-alexa._tcp":      {"Amazon Alexa", "speaker", "Amazon Echo", 3},
	"_nvstream._tcp":        {"NVIDIA GameStream", "media", "NVIDIA Shield", 3},
	"_roku._tcp":            {"Roku", "media", "Roku", 3},
	"_viziocast._tcp":       {"Vizio Cast", "media", "Vizio TV", 3},
	"_ipp._tcp":             {"Printing (IPP)", "print", "Printer", 3},
	"_ipps._tcp":            {"Printing (IPP over TLS)", "print", "Printer", 3},
	"_printer._tcp":         {"Printing (LPR)", "print", "Printer", 3},
	"_pdl-datastream._tcp":  {"Printing (raw)", "print", "Printer", 3},
	"_scanner._tcp":         {"Scanning", "print", "Scanner", 2},
	"_uscan._tcp":           {"Scanning (eSCL)", "print", "Scanner", 2},
	"_hap._tcp":             {"HomeKit", "homekit", "HomeKit accessory", 2},
	"_homekit._tcp":         {"HomeKit", "homekit", "HomeKit accessory", 2},
	"_matter._tcp":          {"Matter", "iot", "Matter device", 2},
	"_matterc._udp":         {"Matter commissioning", "iot", "Matter device", 2},
	"_hue._tcp":             {"Philips Hue", "iot", "Philips Hue bridge", 3},
	"_dosvc._tcp":           {"Windows Delivery Optimization", "windows", "Windows PC", 2},
	"_smb._tcp":             {"File sharing (SMB)", "file", "", 0},
	"_afpovertcp._tcp":      {"File sharing (AFP)", "file", "Apple device", 1},
	"_adisk._tcp":           {"Time Machine", "file", "Apple device", 1},
	"_daap._tcp":            {"iTunes library", "media", "Apple device", 1},
	"_dacp._tcp":            {"iTunes remote", "media", "Apple device", 1},
	"_rfb._tcp":             {"Screen sharing (VNC)", "file", "", 0},
	"_ssh._tcp":             {"SSH", "file", "", 0},
	"_sftp-ssh._tcp":        {"SFTP", "file", "", 0},
	"_workstation._tcp":     {"Workstation", "file", "", 0},
	"_http._tcp":            {"Web interface", "web", "", 0},
}

// ServiceType normalizes an mDNS name into a catalog service type: the two
// labels before the trailing ".local" (e.g. "Den._airplay._tcp.local" and
// "_airplay._tcp.local" both become "_airplay._tcp"). It returns "" for a
// name that is not a DNS-SD service type, or the generic browse/meta names
// that say nothing about a device.
func ServiceType(name string) string {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSuffix(strings.TrimSpace(name), "."), ".local"))
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return ""
	}
	transport := labels[len(labels)-1]
	service := labels[len(labels)-2]
	if transport != "_tcp" && transport != "_udp" {
		return ""
	}
	if !strings.HasPrefix(service, "_") || len(service) < 2 {
		return ""
	}
	switch service {
	case "_services", "_dns-sd", "_device-info", "_sub":
		// Meta and generic browse names every device emits.
		return ""
	}
	return service + "." + transport
}

// DeviceService is one service type a device is associated with.
type DeviceService struct {
	Service  string    `json:"service"`
	Label    string    `json:"label,omitempty"`
	Category string    `json:"category,omitempty"`
	LastSeen time.Time `json:"last_seen"`
}

// DeviceServiceHint is a device's discovery identity: the services it uses
// and the device type they imply.
type DeviceServiceHint struct {
	DeviceID string          `json:"device_id"`
	Type     string          `json:"type,omitempty"`
	Services []DeviceService `json:"services"`
	LastSeen time.Time       `json:"last_seen"`
}

type DeviceServiceHints struct {
	Schema      int                 `json:"schema"`
	GeneratedAt time.Time           `json:"generated_at"`
	Hints       []DeviceServiceHint `json:"hints"`
}

type DeviceServiceHintReader interface {
	QueryDeviceServices(context.Context) (DeviceServiceHints, error)
}

type deviceServiceObservation struct {
	deviceID string
	name     string
	lastSeen time.Time
}

// resolveDeviceServiceHints keeps, per device, the known services it was
// seen using and the most specific device type they imply.
func resolveDeviceServiceHints(observations []deviceServiceObservation) []DeviceServiceHint {
	type collected struct {
		services map[string]DeviceService
		typeHint string
		typeRank int
		lastSeen time.Time
	}
	devices := map[string]*collected{}
	for _, observation := range observations {
		if !deviceIDPattern.MatchString(observation.deviceID) {
			continue
		}
		service := ServiceType(observation.name)
		if service == "" {
			continue
		}
		info, known := serviceCatalog[service]
		got := devices[observation.deviceID]
		if got == nil {
			got = &collected{services: map[string]DeviceService{}}
			devices[observation.deviceID] = got
		}
		last := observation.lastSeen.UTC()
		if existing, seen := got.services[service]; !seen || last.After(existing.LastSeen) {
			got.services[service] = DeviceService{Service: service, Label: info.label, Category: info.category, LastSeen: last}
		}
		if last.After(got.lastSeen) {
			got.lastSeen = last
		}
		if known && info.typeHint != "" && info.typeRank > got.typeRank {
			got.typeHint, got.typeRank = info.typeHint, info.typeRank
		}
	}
	hints := make([]DeviceServiceHint, 0, len(devices))
	for id, got := range devices {
		services := make([]DeviceService, 0, len(got.services))
		for _, service := range got.services {
			services = append(services, service)
		}
		// Newest first, then by name, so the list is stable and the most
		// recently used services lead.
		sort.Slice(services, func(i, j int) bool {
			if !services[i].LastSeen.Equal(services[j].LastSeen) {
				return services[i].LastSeen.After(services[j].LastSeen)
			}
			return services[i].Service < services[j].Service
		})
		if len(services) > MaxServicesPerDevice {
			services = services[:MaxServicesPerDevice]
		}
		hints = append(hints, DeviceServiceHint{DeviceID: id, Type: got.typeHint, Services: services, LastSeen: got.lastSeen})
	}
	sort.Slice(hints, func(i, j int) bool { return hints[i].DeviceID < hints[j].DeviceID })
	if len(hints) > MaxDeviceServiceHints {
		hints = hints[:MaxDeviceServiceHints]
	}
	return hints
}

func (h DeviceServiceHints) Validate() error {
	if h.Schema != DeviceServiceHintsSchema || h.GeneratedAt.IsZero() || len(h.Hints) > MaxDeviceServiceHints {
		return errors.New("device service hints are invalid")
	}
	seen := map[string]bool{}
	for _, hint := range h.Hints {
		if !deviceIDPattern.MatchString(hint.DeviceID) || seen[hint.DeviceID] || hint.LastSeen.IsZero() || len(hint.Services) == 0 || len(hint.Services) > MaxServicesPerDevice {
			return errors.New("device service hint is invalid")
		}
		seen[hint.DeviceID] = true
		for _, service := range hint.Services {
			if service.Service == "" || service.LastSeen.IsZero() {
				return errors.New("device service is invalid")
			}
		}
	}
	return nil
}

// The dns_query index serves this: mDNS events carry the service type there.
const deviceServiceStatement = `SELECT device_id, dns_query, max(occurred_at) FROM normalized_events
WHERE device_id IS NOT NULL AND occurred_at >= $1 AND app_protocol = 'mdns'
  AND dns_query IS NOT NULL
  AND (dns_query LIKE '%._tcp.local' OR dns_query LIKE '%._udp.local')
GROUP BY device_id, dns_query
LIMIT $2`

// QueryDeviceServices reads the mDNS service types each device used in the
// last week and keeps the services and the device type they imply.
func (s PostgresSink) QueryDeviceServices(ctx context.Context) (DeviceServiceHints, error) {
	if s.DB == nil {
		return DeviceServiceHints{}, errors.New("PostgreSQL connection is required")
	}
	var generatedAt time.Time
	if err := s.DB.QueryRowContext(ctx, "SELECT clock_timestamp()").Scan(&generatedAt); err != nil {
		return DeviceServiceHints{}, fmt.Errorf("read device service boundary: %w", err)
	}
	generatedAt = generatedAt.UTC()
	rows, err := s.DB.QueryContext(ctx, deviceServiceStatement, generatedAt.Add(-DeviceServiceWindow), maxDeviceServiceObservations)
	if err != nil {
		return DeviceServiceHints{}, fmt.Errorf("query device services: %w", err)
	}
	defer rows.Close()
	var observations []deviceServiceObservation
	for rows.Next() {
		var observation deviceServiceObservation
		var name sql.NullString
		var lastSeen sql.NullTime
		if err := rows.Scan(&observation.deviceID, &name, &lastSeen); err != nil {
			return DeviceServiceHints{}, fmt.Errorf("decode device service: %w", err)
		}
		observation.name = name.String
		observation.lastSeen = lastSeen.Time
		observations = append(observations, observation)
	}
	if err := rows.Err(); err != nil {
		return DeviceServiceHints{}, fmt.Errorf("read device services: %w", err)
	}
	hints := DeviceServiceHints{Schema: DeviceServiceHintsSchema, GeneratedAt: generatedAt, Hints: resolveDeviceServiceHints(observations)}
	if err := hints.Validate(); err != nil {
		return DeviceServiceHints{}, err
	}
	return hints, nil
}
