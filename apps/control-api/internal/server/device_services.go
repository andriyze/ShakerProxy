package server

import (
	"context"
	"sync"
	"time"

	"shakerproxy.dev/shakerproxy/internal/ingest"
	deviceinventory "shakerproxy.dev/shakerproxy/internal/inventory"
)

// The Devices page also shows what a device offers and looks for on the
// network — AirPlay, Chromecast, printing — which ingestd reads from the
// mDNS the device broadcasts. Like the platform hints, this is best effort:
// Devices must load even when ingestd is slow or down.
const (
	deviceServiceLookupTimeout = 1500 * time.Millisecond
	deviceServiceCacheTTL      = 30 * time.Second
)

type deviceServiceCache struct {
	mu        sync.Mutex
	fetchedAt time.Time
	hints     []ingest.DeviceServiceHint
	problem   string
}

// deviceServiceHint is a device's discovery identity for the API: the type
// its services imply and the services themselves. It is derived on each
// request and never stored.
type deviceServiceHint struct {
	Type     string                 `json:"type,omitempty"`
	Services []ingest.DeviceService `json:"services"`
	LastSeen time.Time              `json:"last_seen"`
}

func (s *Server) deviceServiceHints(ctx context.Context) []ingest.DeviceServiceHint {
	reader, ok := s.eventReader.(ingest.DeviceServiceHintReader)
	if !ok || reader == nil {
		return nil
	}
	cache := &s.deviceServices
	cache.mu.Lock()
	defer cache.mu.Unlock()
	now := time.Now()
	if !cache.fetchedAt.IsZero() && now.Sub(cache.fetchedAt) < deviceServiceCacheTTL {
		return cache.hints
	}
	lookup, cancel := context.WithTimeout(ctx, deviceServiceLookupTimeout)
	defer cancel()
	hints, err := reader.QueryDeviceServices(lookup)
	cache.fetchedAt = now
	if err != nil {
		if problem := err.Error(); problem != cache.problem && s.logger != nil {
			s.logger.Warn("device service hints are unavailable; devices are shown without them", "error", err)
			cache.problem = problem
		}
		return cache.hints
	}
	cache.problem = ""
	cache.hints = hints.Hints
	return cache.hints
}

// serviceHintsFor picks each listed device's services, including those
// recorded under device records merged into it. A device with no discovery
// services is left out.
func serviceHintsFor(devices []deviceinventory.Device, hints []ingest.DeviceServiceHint) map[string]deviceServiceHint {
	if len(devices) == 0 {
		return nil
	}
	byID := make(map[string]ingest.DeviceServiceHint, len(hints))
	for _, hint := range hints {
		byID[hint.DeviceID] = hint
	}
	result := map[string]deviceServiceHint{}
	for _, device := range devices {
		for _, id := range append([]string{device.ID}, device.FormerIDs...) {
			hint, ok := byID[id]
			if !ok || len(hint.Services) == 0 {
				continue
			}
			result[device.ID] = deviceServiceHint{Type: hint.Type, Services: hint.Services, LastSeen: hint.LastSeen}
			break
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}
