package agentapi

import (
	"context"
	"errors"

	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
)

const maxAgentWiFiVisibilityBytes = 64 << 10

// WiFiVisibility is GET /api/v1/wifi-visibility: whether ShakerProxy listens
// on the radio, with which adapter and channel, and why not.
type WiFiVisibility struct {
	gatewayprotocol.WiFiMonitorStatus
	Notes []string `json:"notes"`
}

func (c *Client) WiFiVisibility(ctx context.Context) (WiFiVisibility, error) {
	if c == nil || c.base == nil || c.client == nil {
		return WiFiVisibility{}, errors.New("agent API client is unavailable")
	}
	var view WiFiVisibility
	if _, err := c.getJSON(ctx, "/api/v1/wifi-visibility", nil, maxAgentWiFiVisibilityBytes, &view); err != nil {
		return WiFiVisibility{}, err
	}
	if view.Schema != gatewayprotocol.WiFiMonitorSchema || len(view.Adapters) > 16 || len(view.Notes) > 16 || len(view.HopChannels) > 24 || len(view.Reason) > 512 || len(view.LastError) > 512 {
		return WiFiVisibility{}, errors.New("agent Wi-Fi visibility API returned an invalid bounded response")
	}
	return view, nil
}
