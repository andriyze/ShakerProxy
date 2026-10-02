package agentapi

import (
	"context"
	"errors"
)

const maxAgentDNSVisibilityBytes = 256 << 10

// DNSVisibilityResolver is one encrypted-DNS resolver blocked by address.
type DNSVisibilityResolver struct {
	ID        string   `json:"id"`
	Provider  string   `json:"provider"`
	Hostnames []string `json:"hostnames"`
	IPv4      []string `json:"ipv4"`
	IPv6      []string `json:"ipv6"`
}

// DNSVisibility is GET /api/v1/dns-visibility: whether every lab lookup is
// visible (plain DNS forced through ShakerProxy, encrypted DNS blocked).
type DNSVisibility struct {
	Schema            int                     `json:"schema"`
	PolicyRevision    uint64                  `json:"policy_revision"`
	ForcePlainDNS     bool                    `json:"force_plain_dns"`
	BlockEncryptedDNS bool                    `json:"block_encrypted_dns"`
	Mode              string                  `json:"mode"`
	UpstreamServers   []string                `json:"upstream_servers"`
	BlockedResolvers  []DNSVisibilityResolver `json:"blocked_resolvers"`
	BlockedAddresses  int                     `json:"blocked_addresses"`
	BlockedNames      []string                `json:"blocked_names"`
	Canaries          []string                `json:"canaries"`
	Notes             []string                `json:"notes"`
}

func (c *Client) DNSVisibility(ctx context.Context) (DNSVisibility, error) {
	if c == nil || c.base == nil || c.client == nil {
		return DNSVisibility{}, errors.New("agent API client is unavailable")
	}
	var view DNSVisibility
	if _, err := c.getJSON(ctx, "/api/v1/dns-visibility", nil, maxAgentDNSVisibilityBytes, &view); err != nil {
		return DNSVisibility{}, err
	}
	if view.Schema != 1 || len(view.BlockedResolvers) > 512 || len(view.BlockedNames) > 512 || len(view.Notes) > 16 {
		return DNSVisibility{}, errors.New("agent DNS visibility API returned an invalid bounded response")
	}
	switch view.Mode {
	case "OBSERVE", "BLOCK_KNOWN", "ENFORCE_LOCAL":
	default:
		return DNSVisibility{}, errors.New("agent DNS visibility API returned an invalid mode")
	}
	return view, nil
}
