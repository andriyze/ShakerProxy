package mcpserver

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"shakerproxy.dev/shakerproxy/internal/agentapi"
)

type VPNDevicesArgs struct{}

type vpnDevice struct {
	Name          string     `json:"name"`
	DeviceID      string     `json:"device_id,omitempty"`
	IPv4          string     `json:"ipv4"`
	IPv6          string     `json:"ipv6"`
	Connected     bool       `json:"connected"`
	LastHandshake *time.Time `json:"last_handshake,omitempty"`
	RemoteAddress string     `json:"remote_address,omitempty"`
	ReceivedBytes uint64     `json:"received_bytes"`
	SentBytes     uint64     `json:"sent_bytes"`
}

type vpnDevicesResult struct {
	Summary  string      `json:"summary"`
	Enabled  bool        `json:"enabled"`
	Up       bool        `json:"up"`
	Endpoint string      `json:"endpoint,omitempty"`
	Network  string      `json:"network"`
	Devices  []vpnDevice `json:"devices"`
	Problem  string      `json:"problem,omitempty"`
	Notes    []string    `json:"notes"`
}

func (s *Service) vpnDevices(ctx context.Context, _ *mcp.CallToolRequest, _ VPNDevicesArgs) (*mcp.CallToolResult, any, error) {
	view, err := s.backend.VPN(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("read ShakerProxy VPN mode: %w", err)
	}
	result := vpnDevicesResult{Summary: vpnSummary(view), Enabled: view.Enabled, Up: view.Up, Endpoint: view.Endpoint, Network: view.IPv4CIDR, Devices: []vpnDevice{}, Problem: view.Problem, Notes: view.Notes}
	for _, peer := range view.Peers {
		result.Devices = append(result.Devices, vpnDevice{
			Name: peer.Name, DeviceID: peer.DeviceID, IPv4: peer.IPv4, IPv6: peer.IPv6, Connected: peer.Connected,
			LastHandshake: peer.LastHandshake, RemoteAddress: peer.RemoteAddress, ReceivedBytes: peer.ReceivedBytes, SentBytes: peer.SentBytes,
		})
	}
	return textResult(result)
}

func vpnSummary(view agentapi.VPN) string {
	if !view.Enabled {
		return "VPN mode is off; no device is connected over the VPN."
	}
	if !view.Up {
		return boundText("VPN mode is on but not running: "+view.Problem, 600)
	}
	connected := []string{}
	for _, peer := range view.Peers {
		if peer.Connected {
			connected = append(connected, fmt.Sprintf("%s (%s)", peer.Name, peer.IPv4))
		}
	}
	summary := fmt.Sprintf("VPN mode is on at %s with %d device(s); %d connected", view.Endpoint, len(view.Peers), len(connected))
	if len(connected) > 0 {
		summary += ": " + strings.Join(connected, ", ")
	}
	return boundText(summary+". VPN devices send all their traffic through ShakerProxy; find it with device names ending in (VPN).", 600)
}
