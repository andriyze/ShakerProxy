package server

import (
	"context"
	"net/http"
	"sync"
	"time"

	"shakerproxy.dev/shakerproxy/internal/apitoken"
	"shakerproxy.dev/shakerproxy/internal/ingest"
	deviceinventory "shakerproxy.dev/shakerproxy/internal/inventory"
)

// The Devices page names a device by what it is ("GrapheneOS phone"), which
// ingestd works out from the connectivity checks the device made. The lookup
// is best effort: Devices must load even when ingestd is slow or down.
const (
	devicePlatformLookupTimeout = 1500 * time.Millisecond
	devicePlatformCacheTTL      = 30 * time.Second
)

type devicePlatformCache struct {
	mu        sync.Mutex
	fetchedAt time.Time
	hints     []ingest.DevicePlatformHint
	problem   string
}

type devicePlatformHint struct {
	Platform string    `json:"platform"`
	Domain   string    `json:"domain,omitempty"`
	LastSeen time.Time `json:"last_seen"`
	// Source is "dhcp" when the device's DHCP request identified it; Detail
	// is then the vendor class or option order that matched. Hints from a
	// connectivity check name their Domain instead.
	Source string `json:"source,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// deviceListResponse is the inventory snapshot plus platform hints keyed by
// device ID. The hints are derived on each request and never stored.
type deviceListResponse struct {
	deviceinventory.Snapshot
	PlatformHints map[string]devicePlatformHint `json:"platform_hints,omitempty"`
	// ServiceHints says what each device offers and looks for on the
	// network (mDNS/Bonjour), and the device type that implies.
	ServiceHints map[string]deviceServiceHint `json:"service_hints,omitempty"`
	// LabRouting says, per device seen on the lab recently, whether its
	// traffic goes through ShakerProxy (GET /api/v1/lab-routing).
	LabRouting map[string]labRoutingDevice `json:"lab_routing,omitempty"`
}

func (s *Server) devicePlatformHints(ctx context.Context) []ingest.DevicePlatformHint {
	reader, ok := s.eventReader.(ingest.DevicePlatformHintReader)
	if !ok || reader == nil {
		return nil
	}
	cache := &s.devicePlatforms
	cache.mu.Lock()
	defer cache.mu.Unlock()
	now := time.Now()
	if !cache.fetchedAt.IsZero() && now.Sub(cache.fetchedAt) < devicePlatformCacheTTL {
		return cache.hints
	}
	lookup, cancel := context.WithTimeout(ctx, devicePlatformLookupTimeout)
	defer cancel()
	hints, err := reader.QueryDevicePlatformHints(lookup)
	// A failed lookup keeps the previous hints and waits a full interval
	// before trying again, so a slow ingestd does not slow every page load.
	cache.fetchedAt = now
	if err != nil {
		if problem := err.Error(); problem != cache.problem && s.logger != nil {
			s.logger.Warn("device platform hints are unavailable; devices are shown without them", "error", err)
			cache.problem = problem
		}
		return cache.hints
	}
	cache.problem = ""
	cache.hints = hints.Hints
	return cache.hints
}

// platformHintsFor picks each listed device's best hint, including hints
// recorded under device records merged into it. A DHCP fingerprint names a
// device the connectivity checks do not, or name less specifically; a check
// wins a tie.
func platformHintsFor(devices []deviceinventory.Device, hints []ingest.DevicePlatformHint) map[string]devicePlatformHint {
	if len(devices) == 0 {
		return nil
	}
	byID := make(map[string]ingest.DevicePlatformHint, len(hints))
	for _, hint := range hints {
		byID[hint.DeviceID] = hint
	}
	result := map[string]devicePlatformHint{}
	for _, device := range devices {
		var best ingest.DevicePlatformHint
		found := false
		for _, id := range append([]string{device.ID}, device.FormerIDs...) {
			if hint, ok := byID[id]; ok && (!found || ingest.PreferDevicePlatformHint(hint, best)) {
				best, found = hint, true
			}
		}
		if observed := device.ObservedDHCP; observed != nil {
			if platform, evidence, rank, ok := ingest.DHCPPlatform(observed.VendorClass, observed.ParameterList); ok && (!found || rank > ingest.DevicePlatformRank(best)) {
				result[device.ID] = devicePlatformHint{Platform: platform, LastSeen: observed.LastSeen, Source: "dhcp", Detail: evidence}
				continue
			}
		}
		if found {
			result[device.ID] = devicePlatformHint{Platform: best.Platform, Domain: best.Domain, LastSeen: best.LastSeen}
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

// mayReadTraffic reports whether the caller may see facts derived from
// traffic: a signed-in administrator, or an API token with traffic:read.
func mayReadTraffic(r *http.Request) bool {
	principal, ok := r.Context().Value(apiPrincipalContextKey{}).(apitoken.Principal)
	if !ok {
		return true
	}
	for _, scope := range principal.Scopes {
		if scope == apitoken.ScopeTrafficRead {
			return true
		}
	}
	return false
}
