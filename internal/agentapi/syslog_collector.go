package agentapi

import (
	"context"
	"errors"
)

const maxAgentSyslogCollectorBytes = 256 << 10

// SyslogCollectorStatus is the read-only view of the network-gear log
// collector: whether it is on, where it listens, which sources it accepts, and
// its receiver counts. It never contains log content.
type SyslogCollectorStatus struct {
	Available      bool                     `json:"available"`
	Enabled        bool                     `json:"enabled"`
	BindAddress    string                   `json:"bind_address"`
	TCP            bool                     `json:"tcp"`
	UDP            bool                     `json:"udp"`
	AllowedSources []string                 `json:"allowed_sources"`
	Revision       int                      `json:"revision"`
	Status         *SyslogCollectorReceiver `json:"status,omitempty"`
}

// SyslogCollectorReceiver is the running receiver's counts, whether it is
// listening, and why not.
type SyslogCollectorReceiver struct {
	Received   uint64 `json:"received"`
	Parsed     uint64 `json:"parsed"`
	Unparsed   uint64 `json:"unparsed"`
	Delivered  uint64 `json:"delivered"`
	DeliverErr uint64 `json:"deliver_errors"`
	Dropped    uint64 `json:"dropped_rate_limited"`
	Rejected   uint64 `json:"rejected_not_allowed"`
	Listening  bool   `json:"listening"`
	Error      string `json:"error,omitempty"`
}

// SyslogCollector reads the network-gear log collector's status.
func (c *Client) SyslogCollector(ctx context.Context) (SyslogCollectorStatus, error) {
	if c == nil || c.base == nil || c.client == nil {
		return SyslogCollectorStatus{}, errors.New("agent API client is unavailable")
	}
	var status SyslogCollectorStatus
	if _, err := c.getJSONWith(ctx, "/api/v1/integrations/syslog-collector", nil, maxAgentSyslogCollectorBytes, &status, false); err != nil {
		return SyslogCollectorStatus{}, err
	}
	if len(status.AllowedSources) > 64 || len(status.BindAddress) > 64 {
		return SyslogCollectorStatus{}, errors.New("agent syslog collector API returned an invalid bounded status")
	}
	return status, nil
}
