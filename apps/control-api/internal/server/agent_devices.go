package server

import (
	"errors"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"shakerproxy.dev/shakerproxy/internal/apitoken"
	"shakerproxy.dev/shakerproxy/internal/ingest"
	deviceinventory "shakerproxy.dev/shakerproxy/internal/inventory"
)

const (
	defaultAgentDeviceLimit    = 50
	maxAgentDeviceLimit        = 100
	maxAgentDeviceAddresses    = 16
	maxAgentDeviceHostnames    = 8
	maxAgentDeviceTags         = 16
	maxAgentDeviceWarnings     = 8
	maxAgentTruncatedFieldList = 4
)

type agentDeviceAddress struct {
	Address    string    `json:"address"`
	Family     string    `json:"family"`
	Confidence int       `json:"confidence"`
	ValidFrom  time.Time `json:"valid_from"`
	ValidUntil time.Time `json:"valid_until"`
	Active     bool      `json:"active"`
	Interface  string    `json:"interface,omitempty"`
	VLANID     *int      `json:"vlan_id,omitempty"`
}

type agentDeviceHostname struct {
	Hostname   string    `json:"hostname"`
	Confidence int       `json:"confidence"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
}

// agentDeviceDHCP is the DHCP identity a device showed on the lab, without
// its MAC address.
type agentDeviceDHCP struct {
	HostName      string    `json:"host_name,omitempty"`
	ClientFQDN    string    `json:"client_fqdn,omitempty"`
	VendorClass   string    `json:"vendor_class,omitempty"`
	ParameterList string    `json:"parameter_list,omitempty"`
	Platform      string    `json:"platform,omitempty"`
	Server        string    `json:"server,omitempty"`
	Router        string    `json:"router,omitempty"`
	LastSeen      time.Time `json:"last_seen"`
}

type agentDevice struct {
	Schema                int                   `json:"schema"`
	ID                    string                `json:"id"`
	DisplayName           string                `json:"display_name"`
	FriendlyName          string                `json:"friendly_name,omitempty"`
	Location              string                `json:"location,omitempty"`
	Category              string                `json:"category,omitempty"`
	Icon                  string                `json:"icon,omitempty"`
	Tags                  []string              `json:"tags,omitempty"`
	Vendor                string                `json:"vendor,omitempty"`
	Addresses             []agentDeviceAddress  `json:"addresses"`
	Hostnames             []agentDeviceHostname `json:"hostnames"`
	DHCP                  *agentDeviceDHCP      `json:"dhcp,omitempty"`
	FirstSeen             time.Time             `json:"first_seen"`
	LastSeen              time.Time             `json:"last_seen"`
	Online                bool                  `json:"online"`
	AttributionConfidence int                   `json:"attribution_confidence"`
	AttributionWarnings   []string              `json:"attribution_warnings,omitempty"`
	TruncatedFields       []string              `json:"truncated_fields,omitempty"`
}

type agentDevicePage struct {
	Schema      int           `json:"schema"`
	GeneratedAt time.Time     `json:"generated_at"`
	Query       string        `json:"query,omitempty"`
	Matched     int           `json:"matched"`
	Returned    int           `json:"returned"`
	Truncated   bool          `json:"truncated"`
	Devices     []agentDevice `json:"devices"`
}

// AgentDeviceHandler is a read-only, metadata-only inventory projection. It
// deliberately omits MAC/client-ID identities, owner and free-form notes while
// retaining stable IDs, friendly names, bounded address/hostname evidence and
// attribution needed to scope traffic investigations.
func (s *Server) AgentDeviceHandler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /api/v1/agent/devices", s.requireAuthOrScope(apitoken.ScopeDevicesRead, http.HandlerFunc(s.listAgentDevices)))
	mux.Handle("GET /api/v1/agent/devices/{deviceID}", s.requireAuthOrScope(apitoken.ScopeDevicesRead, http.HandlerFunc(s.getAgentDevice)))
	return s.wrapMux(mux)
}

func (s *Server) listAgentDevices(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	query, limit, onlineOnly, err := parseAgentDeviceQuery(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_query", err.Error())
		return
	}
	if s.inventory == nil {
		writeError(w, http.StatusServiceUnavailable, "inventory_unavailable", "device inventory is not configured")
		return
	}
	snapshot, err := s.inventory.Snapshot()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "inventory_unavailable", "device inventory is unavailable")
		return
	}
	matches := make([]deviceinventory.Device, 0, min(len(snapshot.Devices), maxAgentDeviceLimit))
	for _, device := range snapshot.Devices {
		if onlineOnly && !device.Online || query != "" && !deviceMatchesSearch(device, query) {
			continue
		}
		matches = append(matches, device)
	}
	sort.Slice(matches, func(left, right int) bool {
		if comparison := matches[right].LastSeen.Compare(matches[left].LastSeen); comparison != 0 {
			return comparison < 0
		}
		return matches[left].ID < matches[right].ID
	})
	matched := len(matches)
	if len(matches) > limit {
		matches = matches[:limit]
	}
	devices := make([]agentDevice, 0, len(matches))
	for _, device := range matches {
		devices = append(devices, projectAgentDevice(device))
	}
	writeJSON(w, http.StatusOK, agentDevicePage{
		Schema:      1,
		GeneratedAt: snapshot.GeneratedAt,
		Query:       query,
		Matched:     matched,
		Returned:    len(devices),
		Truncated:   matched > len(devices),
		Devices:     devices,
	})
}

func (s *Server) getAgentDevice(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" {
		writeError(w, http.StatusBadRequest, "invalid_query", "agent device detail does not accept query parameters")
		return
	}
	deviceID := r.PathValue("deviceID")
	if !deviceinventory.ValidDeviceID(deviceID) {
		writeError(w, http.StatusBadRequest, "invalid_device_id", "device ID is invalid")
		return
	}
	if s.inventory == nil {
		writeError(w, http.StatusServiceUnavailable, "inventory_unavailable", "device inventory is not configured")
		return
	}
	device, err := s.inventory.Get(deviceID)
	if errors.Is(err, os.ErrNotExist) {
		writeError(w, http.StatusNotFound, "device_not_found", "device was not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "inventory_unavailable", "device inventory is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, projectAgentDevice(device))
}

func parseAgentDeviceQuery(r *http.Request) (string, int, bool, error) {
	values := r.URL.Query()
	for key, entries := range values {
		if key != "q" && key != "limit" && key != "online" || len(entries) != 1 {
			return "", 0, false, errors.New("agent device query contains an unsupported or repeated parameter")
		}
	}
	query := strings.TrimSpace(values.Get("q"))
	if len(query) > 128 || !utf8.ValidString(query) {
		return "", 0, false, errors.New("agent device search exceeds 128 UTF-8 bytes")
	}
	for _, character := range query {
		if character < 0x20 || character == 0x7f {
			return "", 0, false, errors.New("agent device search contains a control character")
		}
	}
	limit := defaultAgentDeviceLimit
	if raw := values.Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > maxAgentDeviceLimit {
			return "", 0, false, errors.New("agent device limit must be between 1 and 100")
		}
		limit = parsed
	}
	onlineOnly := false
	if raw := values.Get("online"); raw != "" {
		parsed, err := strconv.ParseBool(raw)
		if err != nil {
			return "", 0, false, errors.New("agent device online filter must be true or false")
		}
		onlineOnly = parsed
	}
	return query, limit, onlineOnly, nil
}

func projectAgentDevice(device deviceinventory.Device) agentDevice {
	addressEvidence := append([]deviceinventory.AddressObservation(nil), device.Addresses...)
	sort.Slice(addressEvidence, func(left, right int) bool {
		if addressEvidence[left].Active != addressEvidence[right].Active {
			return addressEvidence[left].Active
		}
		if comparison := addressEvidence[right].ValidUntil.Compare(addressEvidence[left].ValidUntil); comparison != 0 {
			return comparison < 0
		}
		if addressEvidence[left].Confidence != addressEvidence[right].Confidence {
			return addressEvidence[left].Confidence > addressEvidence[right].Confidence
		}
		return addressEvidence[left].Address < addressEvidence[right].Address
	})
	hostnameEvidence := append([]deviceinventory.HostnameObservation(nil), device.Hostnames...)
	sort.Slice(hostnameEvidence, func(left, right int) bool {
		if comparison := hostnameEvidence[right].LastSeen.Compare(hostnameEvidence[left].LastSeen); comparison != 0 {
			return comparison < 0
		}
		if hostnameEvidence[left].Confidence != hostnameEvidence[right].Confidence {
			return hostnameEvidence[left].Confidence > hostnameEvidence[right].Confidence
		}
		return hostnameEvidence[left].Hostname < hostnameEvidence[right].Hostname
	})

	truncatedFields := make([]string, 0, maxAgentTruncatedFieldList)
	if len(addressEvidence) > maxAgentDeviceAddresses {
		addressEvidence = addressEvidence[:maxAgentDeviceAddresses]
		truncatedFields = append(truncatedFields, "addresses")
	}
	if len(hostnameEvidence) > maxAgentDeviceHostnames {
		hostnameEvidence = hostnameEvidence[:maxAgentDeviceHostnames]
		truncatedFields = append(truncatedFields, "hostnames")
	}
	tags := append([]string(nil), device.Tags...)
	if len(tags) > maxAgentDeviceTags {
		tags = tags[:maxAgentDeviceTags]
		truncatedFields = append(truncatedFields, "tags")
	}
	warnings := append([]string(nil), device.AttributionWarnings...)
	if len(warnings) > maxAgentDeviceWarnings {
		warnings = warnings[:maxAgentDeviceWarnings]
		truncatedFields = append(truncatedFields, "attribution_warnings")
	}

	addresses := make([]agentDeviceAddress, 0, len(addressEvidence))
	for _, address := range addressEvidence {
		addresses = append(addresses, agentDeviceAddress{
			Address:    address.Address,
			Family:     address.Family,
			Confidence: address.Confidence,
			ValidFrom:  address.ValidFrom,
			ValidUntil: address.ValidUntil,
			Active:     address.Active,
			Interface:  address.Interface,
			VLANID:     address.VLANID,
		})
	}
	hostnames := make([]agentDeviceHostname, 0, len(hostnameEvidence))
	for _, hostname := range hostnameEvidence {
		hostnames = append(hostnames, agentDeviceHostname{
			Hostname:   hostname.Hostname,
			Confidence: hostname.Confidence,
			FirstSeen:  hostname.FirstSeen,
			LastSeen:   hostname.LastSeen,
		})
	}
	vendor := ""
	if device.Vendor != nil {
		vendor = device.Vendor.Name
	}
	var dhcp *agentDeviceDHCP
	if observed := device.ObservedDHCP; observed != nil {
		dhcp = &agentDeviceDHCP{
			HostName: observed.HostName, ClientFQDN: observed.ClientFQDN, VendorClass: observed.VendorClass, ParameterList: observed.ParameterList,
			Server: observed.Server, Router: observed.Router, LastSeen: observed.LastSeen,
		}
		if platform, _, _, ok := ingest.DHCPPlatform(observed.VendorClass, observed.ParameterList); ok {
			dhcp.Platform = platform
		}
	}
	return agentDevice{
		Schema:                1,
		ID:                    device.ID,
		DisplayName:           deviceDisplayName(device),
		FriendlyName:          device.FriendlyName,
		Location:              device.Location,
		Category:              device.Category,
		Icon:                  device.Icon,
		Tags:                  tags,
		Vendor:                vendor,
		Addresses:             addresses,
		Hostnames:             hostnames,
		DHCP:                  dhcp,
		FirstSeen:             device.FirstSeen,
		LastSeen:              device.LastSeen,
		Online:                device.Online,
		AttributionConfidence: device.AttributionConfidence,
		AttributionWarnings:   warnings,
		TruncatedFields:       truncatedFields,
	}
}
