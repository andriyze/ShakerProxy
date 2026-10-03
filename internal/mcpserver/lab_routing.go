package mcpserver

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type LabRoutingArgs struct{}

type labRoutingLine struct {
	Title    string    `json:"title"`
	Address  string    `json:"address"`
	DeviceID string    `json:"device_id,omitempty"`
	Routing  string    `json:"routing"`
	Since    time.Time `json:"since"`
	LastSeen time.Time `json:"last_seen"`
	Reason   string    `json:"reason,omitempty"`
	Evidence []string  `json:"evidence"`
}

type labRoutingResult struct {
	Summary            string           `json:"summary"`
	Available          bool             `json:"available"`
	ShakerProxyAddress string           `json:"shakerproxy_address,omitempty"`
	RouterAddress      string           `json:"router_address,omitempty"`
	SubnetMask         string           `json:"subnet_mask,omitempty"`
	Devices            []labRoutingLine `json:"devices"`
}

func (s *Service) labRouting(ctx context.Context, _ *mcp.CallToolRequest, _ LabRoutingArgs) (*mcp.CallToolResult, any, error) {
	report, err := s.backend.LabRouting(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("read lab routing: %w", err)
	}
	result := labRoutingResult{Available: report.Available, ShakerProxyAddress: report.ShakerProxyAddress, RouterAddress: report.RouterAddress, SubnetMask: report.SubnetMask, Devices: []labRoutingLine{}}
	if !report.Available {
		result.Summary = boundText("Lab routing cannot be judged: "+report.Unavailable, 900)
		return textResult(result)
	}
	var bypassing, through, unknown []string
	// Bypassing devices first: they are why traffic is missing.
	for _, want := range []string{"BYPASSING", "UNKNOWN", "THROUGH_SHAKERPROXY"} {
		for _, device := range report.Devices {
			if device.Routing != want {
				continue
			}
			title := device.Address
			if device.DisplayName != "" {
				title = device.DisplayName + " · " + device.Address
			}
			result.Devices = append(result.Devices, labRoutingLine{Title: title, Address: device.Address, DeviceID: device.DeviceID, Routing: device.Routing, Since: device.Since, LastSeen: device.LastSeen, Reason: device.Reason, Evidence: device.Evidence})
			switch want {
			case "BYPASSING":
				bypassing = append(bypassing, title+" ("+strings.TrimSuffix(device.Reason, ".")+")")
			case "UNKNOWN":
				unknown = append(unknown, title)
			default:
				through = append(through, title)
			}
		}
	}
	parts := []string{}
	if len(bypassing) > 0 {
		verb := "devices bypass"
		if len(bypassing) == 1 {
			verb = "device bypasses"
		}
		gateway := "ShakerProxy's address"
		if report.ShakerProxyAddress != "" {
			gateway = report.ShakerProxyAddress
		}
		parts = append(parts, fmt.Sprintf("%d %s ShakerProxy: %s. ShakerProxy sees only their broadcasts. To fix: set the device's gateway and DNS to %s in its network settings, use VPN mode, or have the router's DHCP hand out %s as gateway and DNS.",
			len(bypassing), verb, strings.Join(bypassing, "; "), gateway, gateway))
	} else {
		parts = append(parts, "No device on the lab bypasses ShakerProxy.")
	}
	if len(through) > 0 {
		verb := "go"
		if len(through) == 1 {
			verb = "goes"
		}
		parts = append(parts, fmt.Sprintf("%d %s through ShakerProxy: %s.", len(through), verb, strings.Join(through, ", ")))
	}
	if len(unknown) > 0 {
		parts = append(parts, fmt.Sprintf("Just appeared, not judged yet: %s.", strings.Join(unknown, ", ")))
	}
	result.Summary = boundText(strings.Join(parts, " "), 1500)
	return textResult(result)
}
