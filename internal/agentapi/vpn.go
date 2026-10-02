package agentapi

import (
	"context"
	"errors"

	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
)

const maxAgentVPNBytes = 256 << 10

// VPN is GET /api/v1/vpn: VPN mode and its devices. It holds no private key.
type VPN = gatewayprotocol.VPNStatus

// VPNPeer is one VPN device.
type VPNPeer = gatewayprotocol.VPNPeerStatus

func (c *Client) VPN(ctx context.Context) (VPN, error) {
	if c == nil || c.base == nil || c.client == nil {
		return VPN{}, errors.New("agent API client is unavailable")
	}
	var view VPN
	if _, err := c.getJSON(ctx, "/api/v1/vpn", nil, maxAgentVPNBytes, &view); err != nil {
		return VPN{}, err
	}
	if view.Schema != 1 || len(view.Peers) > 256 || len(view.Notes) > 16 {
		return VPN{}, errors.New("agent VPN API returned an invalid bounded response")
	}
	return view, nil
}
