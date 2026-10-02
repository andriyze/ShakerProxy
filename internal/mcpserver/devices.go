package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"shakerproxy.dev/shakerproxy/internal/agentapi"
)

type ListDevicesArgs struct {
	Query      string `json:"query,omitempty" jsonschema:"optional search over names, addresses, hostnames, vendor, location, category, and tags, e.g. camera"`
	OnlineOnly bool   `json:"online_only,omitempty" jsonschema:"only devices that are online now"`
	Limit      int    `json:"limit,omitempty" jsonschema:"maximum devices to return, 1-100, default 50"`
}

type FindDeviceArgs struct {
	Device string `json:"device" jsonschema:"friendly name, IP address, MAC address, or device ID, e.g. living room tv or 10.77.0.23"`
}

type deviceLine struct {
	DeviceID  string    `json:"device_id"`
	Name      string    `json:"name"`
	Vendor    string    `json:"vendor,omitempty"`
	Category  string    `json:"category,omitempty"`
	Location  string    `json:"location,omitempty"`
	Addresses []string  `json:"addresses"`
	Online    bool      `json:"online"`
	LastSeen  time.Time `json:"last_seen"`
	DHCP      *dhcpLine `json:"dhcp,omitempty"`
	Summary   string    `json:"summary"`
}

// dhcpLine is what a device's DHCP request on the lab said about it when
// another server (the network's router) answered it.
type dhcpLine struct {
	HostName      string `json:"host_name,omitempty"`
	VendorClass   string `json:"vendor_class,omitempty"`
	ParameterList string `json:"parameter_list,omitempty"`
	Platform      string `json:"platform,omitempty"`
	Server        string `json:"server,omitempty"`
}

type deviceList struct {
	Summary   string       `json:"summary"`
	Devices   []deviceLine `json:"devices"`
	Matched   int          `json:"matched"`
	Truncated bool         `json:"truncated"`
}

type deviceMatchLine struct {
	DeviceID  string    `json:"device_id"`
	Name      string    `json:"name"`
	Vendor    string    `json:"vendor,omitempty"`
	Addresses []string  `json:"addresses"`
	Online    bool      `json:"online"`
	Match     string    `json:"match"`
	DHCP      *dhcpLine `json:"dhcp,omitempty"`
	Summary   string    `json:"summary"`
}

type findDeviceResult struct {
	Summary string            `json:"summary"`
	Unique  bool              `json:"unique"`
	Matches []deviceMatchLine `json:"matches"`
}

func (s *Service) listDevices(ctx context.Context, _ *mcp.CallToolRequest, args ListDevicesArgs) (*mcp.CallToolResult, any, error) {
	limit, err := normalizeLimit(args.Limit)
	if err != nil {
		return nil, nil, err
	}
	args.Query = strings.TrimSpace(args.Query)
	if len(args.Query) > 128 {
		return nil, nil, errors.New("query is limited to 128 characters")
	}
	page, err := s.backend.DevicesList(ctx, agentapi.DeviceListRequest{Query: args.Query, Limit: limit, OnlineOnly: args.OnlineOnly})
	if err != nil {
		return nil, nil, fmt.Errorf("list devices: %w", err)
	}
	result := deviceList{Devices: make([]deviceLine, 0, len(page.Devices)), Matched: page.Matched, Truncated: page.Truncated}
	online := 0
	for _, device := range page.Devices {
		addresses := []string{}
		for _, address := range device.Addresses {
			if address.Active {
				addresses = append(addresses, address.Address)
			}
		}
		if device.Online {
			online++
		}
		line := deviceLine{
			DeviceID: device.ID, Name: device.DisplayName, Vendor: device.Vendor, Category: device.Category, Location: device.Location,
			Addresses: addresses, Online: device.Online, LastSeen: device.LastSeen,
		}
		identity := device.Vendor
		if dhcp := device.DHCP; dhcp != nil {
			line.DHCP = &dhcpLine{HostName: dhcp.HostName, VendorClass: dhcp.VendorClass, ParameterList: dhcp.ParameterList, Platform: dhcp.Platform, Server: dhcp.Server}
			if identity == "" {
				identity = dhcp.Platform
			}
		}
		line.Summary = deviceSummary(device.DisplayName, identity, addresses, device.Online)
		result.Devices = append(result.Devices, line)
	}
	result.Summary = fmt.Sprintf("%s (%d online).", countNoun(len(result.Devices), "device", "devices"), online)
	if page.Truncated {
		result.Summary = fmt.Sprintf("Showing %d of %d devices (%d online); narrow with query or raise limit.", len(result.Devices), page.Matched, online)
	}
	if len(result.Devices) == 0 {
		result.Summary = "No devices found. Connect a device to the lab network, or try a different query."
	}
	return textResult(result)
}

func (s *Service) findDevice(ctx context.Context, _ *mcp.CallToolRequest, args FindDeviceArgs) (*mcp.CallToolResult, any, error) {
	reference := strings.TrimSpace(args.Device)
	if reference == "" {
		return nil, nil, errors.New("device is required: give a friendly name, IP address, MAC address, or device ID")
	}
	resolution, err := s.backend.ResolveDevice(ctx, reference)
	if err != nil {
		return nil, nil, fmt.Errorf("find device %q: %w", reference, err)
	}
	result := findDeviceResult{Unique: resolution.Unique, Matches: make([]deviceMatchLine, 0, len(resolution.Matches))}
	for _, match := range resolution.Matches {
		// Hardware addresses are omitted from agent output; a MAC can still be
		// used as a reference.
		line := deviceMatchLine{
			DeviceID: match.DeviceID, Name: match.FriendlyName, Vendor: match.Vendor, Addresses: match.Addresses,
			Online: match.Online, Match: match.Match,
		}
		identity := match.Vendor
		if match.DHCPHostName != "" || match.DHCPVendorClass != "" || match.DHCPPlatform != "" {
			line.DHCP = &dhcpLine{HostName: match.DHCPHostName, VendorClass: match.DHCPVendorClass, Platform: match.DHCPPlatform}
			if identity == "" {
				identity = match.DHCPPlatform
			}
		}
		line.Summary = deviceSummary(match.FriendlyName, identity, match.Addresses, match.Online)
		result.Matches = append(result.Matches, line)
	}
	switch len(result.Matches) {
	case 0:
		result.Summary = fmt.Sprintf("No device matches %q. Call list_devices to see names, addresses, and IDs.", reference)
	case 1:
		result.Summary = fmt.Sprintf("%q is %s (matched by %s).", reference, result.Matches[0].Summary, matchLabel(result.Matches[0].Match))
	default:
		result.Summary = fmt.Sprintf("%q matches %d devices; ask the user which one or use a device_id.", reference, len(result.Matches))
	}
	return textResult(result)
}

func deviceSummary(name, vendor string, addresses []string, online bool) string {
	parts := []string{}
	if vendor != "" {
		parts = append(parts, vendor)
	}
	if len(addresses) > 0 {
		parts = append(parts, strings.Join(addresses, ", "))
	}
	if online {
		parts = append(parts, "online")
	} else {
		parts = append(parts, "offline")
	}
	return fmt.Sprintf("%s (%s)", name, strings.Join(parts, ", "))
}

func matchLabel(kind string) string {
	switch kind {
	case "id":
		return "device ID"
	case "mac":
		return "MAC address"
	case "ip":
		return "IP address"
	case "name":
		return "name"
	case "name_prefix":
		return "start of name"
	default:
		return "part of name"
	}
}

func countNoun(count int, singular, plural string) string {
	if count == 1 {
		return "1 " + singular
	}
	return fmt.Sprintf("%d %s", count, plural)
}
