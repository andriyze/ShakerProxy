package agentapi

import (
	"context"
	"errors"

	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
)

const maxSystemStatusResponseBytes = 128 << 10

// SystemStatus returns the same read-only appliance projection exposed by the
// local UI. It never reads host files or invokes the privileged gateway
// directly; the existing scoped control API remains the authorization and
// audit boundary.
func (c *Client) SystemStatus(ctx context.Context) (gatewayprotocol.Status, error) {
	if c == nil || c.base == nil || c.client == nil {
		return gatewayprotocol.Status{}, errors.New("agent API client is unavailable")
	}
	var status gatewayprotocol.Status
	if _, err := c.getJSON(ctx, "/api/v1/system/status", nil, maxSystemStatusResponseBytes, &status); err != nil {
		return gatewayprotocol.Status{}, err
	}
	if status.APIVersion == "" || status.DaemonVersion == "" || status.OperatingMode == "" || status.StartedAt == "" {
		return gatewayprotocol.Status{}, errors.New("agent system-status response is invalid")
	}
	return status, nil
}
