package server

import (
	"net/http"

	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/trafficpolicy"
)

// The DNS visibility switches are the two settings a tester needs to see every
// lookup: force plain DNS through ShakerProxy, and block encrypted DNS so
// devices fall back to plain DNS. They map onto the traffic policy; this API
// keeps the CLI, MCP and UI to two booleans.

type dnsVisibilityResolver struct {
	ID        string   `json:"id"`
	Provider  string   `json:"provider"`
	Hostnames []string `json:"hostnames"`
	IPv4      []string `json:"ipv4"`
	IPv6      []string `json:"ipv6"`
}

type dnsVisibilityView struct {
	Schema         int    `json:"schema"`
	PolicyRevision uint64 `json:"policy_revision"`
	// ForcePlainDNS: every lab client's plain DNS (port 53, to any
	// resolver) is answered by ShakerProxy.
	ForcePlainDNS bool `json:"force_plain_dns"`
	// BlockEncryptedDNS: DNS over TLS/QUIC (port 853) and the listed DNS-
	// over-HTTPS resolvers are refused, and their names answered with
	// NXDOMAIN, so devices fall back to plain DNS.
	BlockEncryptedDNS bool `json:"block_encrypted_dns"`
	// Mode is the effective traffic-policy mode the switches produce.
	Mode            string   `json:"mode"`
	UpstreamServers []string `json:"upstream_servers"`
	// BlockedResolvers are blocked by address while BlockEncryptedDNS is on.
	BlockedResolvers []dnsVisibilityResolver `json:"blocked_resolvers"`
	BlockedAddresses int                     `json:"blocked_addresses"`
	// BlockedNames are answered with NXDOMAIN while BlockEncryptedDNS is on
	// (each also covers its subdomains), including the canaries.
	BlockedNames []string `json:"blocked_names"`
	Canaries     []string `json:"canaries"`
	Notes        []string `json:"notes"`
}

func dnsVisibility(document trafficpolicy.Document) dnsVisibilityView {
	policy := document.Policy
	dns := policy.EncryptedDNS
	excluded := map[string]bool{}
	for _, id := range dns.ResolverExclusions {
		excluded[id] = true
	}
	resolvers := []dnsVisibilityResolver{}
	addresses := 0
	for _, resolver := range trafficpolicy.BuiltinCatalog().Resolvers {
		if excluded[resolver.ID] || !resolver.SafeForIPBlock || !resolver.DedicatedIPs {
			continue
		}
		resolvers = append(resolvers, dnsVisibilityResolver{
			ID: resolver.ID, Provider: resolver.Provider,
			Hostnames: append([]string{}, resolver.Hostnames...),
			IPv4:      append([]string{}, resolver.IPv4...),
			IPv6:      append([]string{}, resolver.IPv6...),
		})
		addresses += len(resolver.IPv4) + len(resolver.IPv6)
	}
	upstreams := append([]string{}, dns.UpstreamServers...)
	view := dnsVisibilityView{
		Schema: 1, PolicyRevision: policy.Revision,
		ForcePlainDNS: dns.ForcePlainDNS(), BlockEncryptedDNS: dns.BlockEncryptedDNS(),
		Mode: string(dns.EffectiveMode()), UpstreamServers: upstreams,
		BlockedResolvers: resolvers, BlockedAddresses: addresses,
		BlockedNames: trafficpolicy.BlockedResolverNames(policy),
		Canaries:     append([]string{}, trafficpolicy.EncryptedDNSCanaries...),
		Notes: []string{
			"Both switches apply to every device on the lab network once a lab is confirmed.",
		},
	}
	if view.BlockEncryptedDNS {
		view.Notes = append(view.Notes,
			"Android Private DNS set to a specific provider (strict) will lose internet while this is on: set Private DNS to Automatic or Off.",
			"DNS over HTTPS to resolvers not on this list, shared CDNs, VPNs and relays can still hide lookups.")
	}
	if len(upstreams) == 0 {
		view.Notes = append(view.Notes, "Lookups are forwarded to this host's own DNS servers.")
	}
	return view
}

func (s *Server) getDNSVisibility(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		writeError(w, http.StatusBadRequest, "invalid_query", "DNS visibility does not accept query parameters")
		return
	}
	var document trafficpolicy.Document
	if err := s.gateway.Call(r.Context(), "GetTrafficPolicy", gatewayprotocol.EmptyParams{}, &document); err != nil {
		writeError(w, http.StatusServiceUnavailable, "traffic_policy_unavailable", "traffic policy is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, dnsVisibility(document))
}

type dnsVisibilityRequest struct {
	ForcePlainDNS     *bool `json:"force_plain_dns"`
	BlockEncryptedDNS *bool `json:"block_encrypted_dns"`
}

// putDNSVisibility changes lab behaviour, like device controls: an
// administrator session or an API token with lab:write, no password prompt.
func (s *Server) putDNSVisibility(w http.ResponseWriter, r *http.Request) {
	var request dnsVisibilityRequest
	if err := decodeJSON(r, &request); err != nil || request.ForcePlainDNS == nil && request.BlockEncryptedDNS == nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "send force_plain_dns, block_encrypted_dns or both")
		return
	}
	var current trafficpolicy.Document
	if err := s.gateway.Call(r.Context(), "GetTrafficPolicy", gatewayprotocol.EmptyParams{}, &current); err != nil {
		writeError(w, http.StatusServiceUnavailable, "traffic_policy_unavailable", "traffic policy is unavailable")
		return
	}
	force, block := current.Policy.EncryptedDNS.ForcePlainDNS(), current.Policy.EncryptedDNS.BlockEncryptedDNS()
	if request.ForcePlainDNS != nil {
		force = *request.ForcePlainDNS
	}
	if request.BlockEncryptedDNS != nil {
		block = *request.BlockEncryptedDNS
	}
	if force == current.Policy.EncryptedDNS.ForcePlainDNS() && block == current.Policy.EncryptedDNS.BlockEncryptedDNS() {
		writeJSON(w, http.StatusOK, dnsVisibility(current))
		return
	}
	policy := current.Policy
	policy.Revision = current.Policy.Revision + 1
	policy.EncryptedDNS = policy.EncryptedDNS.WithSwitches(force, block)
	params := gatewayprotocol.ApplyTrafficPolicyParams{ExpectedRevision: current.Policy.Revision, Policy: policy}
	var document trafficpolicy.Document
	if err := s.gateway.Call(r.Context(), "ApplyTrafficPolicy", params, &document); err != nil {
		writeError(w, http.StatusConflict, "traffic_policy_apply_failed", err.Error())
		return
	}
	s.logger.Info("DNS visibility changed", "username", sessionUsername(r.Context()), "force_plain_dns", force, "block_encrypted_dns", block, "revision", document.Policy.Revision)
	writeJSON(w, http.StatusOK, dnsVisibility(document))
}
