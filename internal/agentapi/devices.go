package agentapi

import (
	"context"
	"errors"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	maxAgentDeviceResponseBytes = 512 << 10
	maxAgentDeviceLimit         = 100
	maxAgentDeviceAddresses     = 16
	maxAgentDeviceHostnames     = 8
	maxAgentDeviceTags          = 16
	maxAgentDeviceWarnings      = 8
	maxAgentTruncatedFields     = 4
)

var agentDeviceIDPattern = regexp.MustCompile(`^device-[a-f0-9]{32}$`)

type DeviceAddress struct {
	Address    string    `json:"address"`
	Family     string    `json:"family"`
	Confidence int       `json:"confidence"`
	ValidFrom  time.Time `json:"valid_from"`
	ValidUntil time.Time `json:"valid_until"`
	Active     bool      `json:"active"`
	Interface  string    `json:"interface,omitempty"`
	VLANID     *int      `json:"vlan_id,omitempty"`
}

type DeviceHostname struct {
	Hostname   string    `json:"hostname"`
	Confidence int       `json:"confidence"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
}

// DeviceDHCP is the DHCP identity a device showed on the lab when another
// server (the network's router) answered it.
type DeviceDHCP struct {
	HostName      string    `json:"host_name,omitempty"`
	ClientFQDN    string    `json:"client_fqdn,omitempty"`
	VendorClass   string    `json:"vendor_class,omitempty"`
	ParameterList string    `json:"parameter_list,omitempty"`
	Platform      string    `json:"platform,omitempty"`
	Server        string    `json:"server,omitempty"`
	Router        string    `json:"router,omitempty"`
	LastSeen      time.Time `json:"last_seen"`
}

type Device struct {
	Schema                int              `json:"schema"`
	ID                    string           `json:"id"`
	DisplayName           string           `json:"display_name"`
	FriendlyName          string           `json:"friendly_name,omitempty"`
	Location              string           `json:"location,omitempty"`
	Category              string           `json:"category,omitempty"`
	Icon                  string           `json:"icon,omitempty"`
	Tags                  []string         `json:"tags,omitempty"`
	Vendor                string           `json:"vendor,omitempty"`
	Addresses             []DeviceAddress  `json:"addresses"`
	Hostnames             []DeviceHostname `json:"hostnames"`
	DHCP                  *DeviceDHCP      `json:"dhcp,omitempty"`
	FirstSeen             time.Time        `json:"first_seen"`
	LastSeen              time.Time        `json:"last_seen"`
	Online                bool             `json:"online"`
	AttributionConfidence int              `json:"attribution_confidence"`
	AttributionWarnings   []string         `json:"attribution_warnings,omitempty"`
	TruncatedFields       []string         `json:"truncated_fields,omitempty"`
}

type DevicePage struct {
	Schema      int       `json:"schema"`
	GeneratedAt time.Time `json:"generated_at"`
	Query       string    `json:"query,omitempty"`
	Matched     int       `json:"matched"`
	Returned    int       `json:"returned"`
	Truncated   bool      `json:"truncated"`
	Devices     []Device  `json:"devices"`
}

type DeviceListRequest struct {
	Query      string
	Limit      int
	OnlineOnly bool
}

func (c *Client) DevicesList(ctx context.Context, request DeviceListRequest) (DevicePage, error) {
	if c == nil || c.base == nil || c.client == nil {
		return DevicePage{}, errors.New("agent API client is unavailable")
	}
	request.Query = strings.TrimSpace(request.Query)
	if request.Limit == 0 {
		request.Limit = 50
	}
	if len(request.Query) > 128 || !utf8.ValidString(request.Query) || containsControl(request.Query) || request.Limit < 1 || request.Limit > maxAgentDeviceLimit {
		return DevicePage{}, errors.New("agent device query or limit is invalid")
	}
	values := url.Values{}
	values.Set("limit", strconv.Itoa(request.Limit))
	if request.Query != "" {
		values.Set("q", request.Query)
	}
	if request.OnlineOnly {
		values.Set("online", "true")
	}
	var page DevicePage
	if _, err := c.getJSON(ctx, "/api/v1/agent/devices", values, maxAgentDeviceResponseBytes, &page); err != nil {
		return DevicePage{}, err
	}
	if page.Schema != 1 || page.GeneratedAt.IsZero() || page.Matched < 0 || page.Returned != len(page.Devices) || page.Returned > request.Limit || page.Matched < page.Returned || page.Truncated != (page.Matched > page.Returned) {
		return DevicePage{}, errors.New("agent device API returned an invalid bounded page")
	}
	for _, device := range page.Devices {
		if err := validateAgentDevice(device); err != nil {
			return DevicePage{}, err
		}
	}
	return page, nil
}

func (c *Client) DeviceGet(ctx context.Context, deviceID string) (Device, error) {
	if c == nil || c.base == nil || c.client == nil {
		return Device{}, errors.New("agent API client is unavailable")
	}
	deviceID = strings.TrimSpace(deviceID)
	if !agentDeviceIDPattern.MatchString(deviceID) {
		return Device{}, errors.New("agent device ID is invalid")
	}
	var device Device
	if _, err := c.getJSON(ctx, "/api/v1/agent/devices/"+deviceID, nil, maxAgentDeviceResponseBytes, &device); err != nil {
		return Device{}, err
	}
	if device.ID != deviceID {
		return Device{}, errors.New("agent device API returned the wrong identity")
	}
	if err := validateAgentDevice(device); err != nil {
		return Device{}, err
	}
	return device, nil
}

func validateAgentDevice(device Device) error {
	if device.Schema != 1 || !agentDeviceIDPattern.MatchString(device.ID) || !boundedAgentText(device.DisplayName, 1, 256) || !boundedAgentText(device.FriendlyName, 0, 128) || !boundedAgentText(device.Location, 0, 128) || !boundedAgentText(device.Category, 0, 64) || !boundedAgentText(device.Icon, 0, 64) || !boundedAgentText(device.Vendor, 0, 128) || device.FirstSeen.IsZero() || device.LastSeen.IsZero() || device.LastSeen.Before(device.FirstSeen) || device.AttributionConfidence < 0 || device.AttributionConfidence > 100 || len(device.Tags) > maxAgentDeviceTags || len(device.Addresses) > maxAgentDeviceAddresses || len(device.Hostnames) > maxAgentDeviceHostnames || len(device.AttributionWarnings) > maxAgentDeviceWarnings || len(device.TruncatedFields) > maxAgentTruncatedFields {
		return errors.New("agent device API returned an invalid device projection")
	}
	for _, tag := range device.Tags {
		if !boundedAgentText(tag, 1, 64) {
			return errors.New("agent device API returned an invalid tag")
		}
	}
	for _, warning := range device.AttributionWarnings {
		if !boundedAgentText(warning, 1, 256) {
			return errors.New("agent device API returned an invalid attribution warning")
		}
	}
	seenTruncation := make(map[string]bool, len(device.TruncatedFields))
	for _, field := range device.TruncatedFields {
		if seenTruncation[field] {
			return errors.New("agent device API returned duplicate truncation markers")
		}
		seenTruncation[field] = true
		switch field {
		case "addresses", "hostnames", "tags", "attribution_warnings":
		default:
			return errors.New("agent device API returned an invalid truncation marker")
		}
	}
	for _, address := range device.Addresses {
		parsed, err := netip.ParseAddr(address.Address)
		if err != nil || parsed.String() != address.Address || address.Family == "IPv4" && !parsed.Is4() || address.Family == "IPv6" && !parsed.Is6() || address.Family != "IPv4" && address.Family != "IPv6" || address.Confidence < 0 || address.Confidence > 100 || address.ValidFrom.IsZero() || address.ValidUntil.Before(address.ValidFrom) || len(address.Interface) > 15 || address.VLANID != nil && (*address.VLANID < 1 || *address.VLANID > 4094) {
			return errors.New("agent device API returned invalid address evidence")
		}
	}
	for _, hostname := range device.Hostnames {
		if !boundedAgentText(hostname.Hostname, 1, 253) || hostname.Confidence < 0 || hostname.Confidence > 100 || hostname.FirstSeen.IsZero() || hostname.LastSeen.Before(hostname.FirstSeen) {
			return errors.New("agent device API returned invalid hostname evidence")
		}
	}
	if dhcp := device.DHCP; dhcp != nil {
		if !boundedAgentText(dhcp.HostName, 0, 253) || !boundedAgentText(dhcp.ClientFQDN, 0, 253) || !boundedAgentText(dhcp.VendorClass, 0, 255) || !boundedAgentText(dhcp.ParameterList, 0, 255) || !boundedAgentText(dhcp.Platform, 0, 64) || dhcp.LastSeen.IsZero() {
			return errors.New("agent device API returned an invalid DHCP identity")
		}
		for _, value := range []string{dhcp.Server, dhcp.Router} {
			if parsed, err := netip.ParseAddr(value); value != "" && (err != nil || !parsed.Is4() || parsed.String() != value) {
				return errors.New("agent device API returned an invalid DHCP server")
			}
		}
	}
	return nil
}

func boundedAgentText(value string, minimum, maximum int) bool {
	return len(value) >= minimum && len(value) <= maximum && utf8.ValidString(value) && !containsControl(value)
}

func containsControl(value string) bool {
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return true
		}
	}
	return false
}
