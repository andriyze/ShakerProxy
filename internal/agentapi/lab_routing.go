package agentapi

import (
	"context"
	"errors"
	"net/netip"
	"time"
)

const maxAgentLabRoutingBytes = 1 << 20

// LabRoutingDevice is one device seen on the lab network recently, and
// whether its traffic goes through ShakerProxy.
type LabRoutingDevice struct {
	Address       string    `json:"address"`
	HardwareAddrs []string  `json:"hardware_addrs,omitempty"`
	HostName      string    `json:"host_name,omitempty"`
	Routing       string    `json:"routing"`
	Since         time.Time `json:"since"`
	LastSeen      time.Time `json:"last_seen"`
	Evidence      []string  `json:"evidence"`
	Reason        string    `json:"reason,omitempty"`
	DeviceID      string    `json:"device_id,omitempty"`
	DisplayName   string    `json:"display_name,omitempty"`
}

// LabRouting is GET /api/v1/lab-routing.
type LabRouting struct {
	Schema             int       `json:"schema"`
	GeneratedAt        time.Time `json:"generated_at"`
	Available          bool      `json:"available"`
	Unavailable        string    `json:"unavailable,omitempty"`
	Topology           string    `json:"topology,omitempty"`
	Prefix             string    `json:"prefix,omitempty"`
	SubnetMask         string    `json:"subnet_mask,omitempty"`
	ShakerProxyAddress string    `json:"shakerproxy_address,omitempty"`
	RouterAddress      string    `json:"router_address,omitempty"`
	ThresholdSeconds   int       `json:"threshold_seconds"`
	Counts             struct {
		Through   int `json:"through_shakerproxy"`
		Bypassing int `json:"bypassing"`
		Unknown   int `json:"unknown"`
	} `json:"counts"`
	Devices []LabRoutingDevice `json:"devices"`
}

// LabRouting reads which lab devices send their traffic through ShakerProxy.
func (c *Client) LabRouting(ctx context.Context) (LabRouting, error) {
	if c == nil || c.base == nil || c.client == nil {
		return LabRouting{}, errors.New("agent API client is unavailable")
	}
	var report LabRouting
	if _, err := c.getJSONWith(ctx, "/api/v1/lab-routing", nil, maxAgentLabRoutingBytes, &report, false); err != nil {
		return LabRouting{}, err
	}
	if err := report.validate(); err != nil {
		return LabRouting{}, err
	}
	return report, nil
}

func (r LabRouting) validate() error {
	if r.Schema != 1 || r.GeneratedAt.IsZero() || len(r.Devices) > 512 || r.Counts.Through < 0 || r.Counts.Bypassing < 0 || r.Counts.Unknown < 0 || !boundedAgentText(r.Unavailable, 0, 200) {
		return errors.New("agent lab routing API returned an invalid bounded report")
	}
	for _, value := range []string{r.ShakerProxyAddress, r.RouterAddress, r.SubnetMask} {
		if address, err := netip.ParseAddr(value); value != "" && (err != nil || !address.Is4()) {
			return errors.New("agent lab routing API returned an invalid address")
		}
	}
	for _, device := range r.Devices {
		address, err := netip.ParseAddr(device.Address)
		if err != nil || !address.Is4() || len(device.HardwareAddrs) > 8 || len(device.Evidence) > 8 || device.LastSeen.IsZero() ||
			!boundedAgentText(device.HostName, 0, 253) || !boundedAgentText(device.Reason, 0, 300) || !boundedAgentText(device.DisplayName, 0, 253) ||
			device.DeviceID != "" && !agentDeviceIDPattern.MatchString(device.DeviceID) {
			return errors.New("agent lab routing API returned an invalid device")
		}
		switch device.Routing {
		case "THROUGH_SHAKERPROXY", "BYPASSING", "UNKNOWN":
		default:
			return errors.New("agent lab routing API returned an unknown routing state")
		}
		for _, item := range device.Evidence {
			if !boundedAgentText(item, 1, 200) {
				return errors.New("agent lab routing API returned invalid evidence")
			}
		}
	}
	return nil
}
