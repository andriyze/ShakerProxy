package server

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"shakerproxy.dev/shakerproxy/internal/ingest"
	deviceinventory "shakerproxy.dev/shakerproxy/internal/inventory"
)

// When the network's router serves the lab's DHCP, ingestd reads the
// exchanges the lab recording saw. The inventory takes them as evidence on
// each refresh that brings new ones; like the platform hints the lookup is
// best effort, so Devices loads even when ingestd is slow or down.
const (
	observedDHCPLookupTimeout = 1500 * time.Millisecond
	observedDHCPCacheTTL      = 30 * time.Second
)

type observedDHCPState struct {
	mu        sync.Mutex
	fetchedAt time.Time
	problem   string
	// scope and labPrefix come from the gateway's IPv4 neighbor table, the
	// lab the recording covers.
	scope     deviceinventory.ObservedDHCPScope
	labPrefix netip.Prefix
}

// noteIPv4Scope remembers the lab interface, plan and prefix the gateway's
// IPv4 neighbor table reported.
func (s *Server) noteIPv4Scope(scope deviceinventory.ObservedDHCPScope, labPrefix string) {
	state := &s.observedDHCP
	state.mu.Lock()
	defer state.mu.Unlock()
	state.scope = scope
	state.labPrefix = netip.Prefix{}
	if prefix, err := netip.ParsePrefix(labPrefix); err == nil && prefix.Addr().Is4() {
		state.labPrefix = prefix.Masked()
	}
}

// withObservedDHCP adds new observed DHCP exchanges to the inventory. A
// lookup or reconciliation problem is logged once and leaves the snapshot
// as it was.
func (s *Server) withObservedDHCP(snapshot deviceinventory.Snapshot, err error) (deviceinventory.Snapshot, error) {
	if err != nil || s.inventory == nil {
		return snapshot, err
	}
	reader, ok := s.eventReader.(ingest.ObservedDHCPReader)
	if !ok || reader == nil {
		return snapshot, nil
	}
	state := &s.observedDHCP
	state.mu.Lock()
	defer state.mu.Unlock()
	now := time.Now()
	if !state.fetchedAt.IsZero() && now.Sub(state.fetchedAt) < observedDHCPCacheTTL {
		return snapshot, nil
	}
	state.fetchedAt = now
	lookup, cancel := context.WithTimeout(context.Background(), observedDHCPLookupTimeout)
	defer cancel()
	observed, lookupErr := reader.QueryObservedDHCP(lookup)
	if lookupErr == nil && len(observed.Clients) > 0 {
		updated, reconcileErr := s.inventory.ReconcileObservedDHCP(observedDHCPClients(observed.Clients, state.labPrefix), state.scope)
		if reconcileErr == nil {
			s.noteObservedDHCPProblem(state, nil)
			return updated, nil
		}
		lookupErr = reconcileErr
	}
	s.noteObservedDHCPProblem(state, lookupErr)
	return snapshot, nil
}

// noteObservedDHCPProblem logs a problem once, and its recovery; the caller
// holds state.mu.
func (s *Server) noteObservedDHCPProblem(state *observedDHCPState, err error) {
	switch {
	case err == nil && state.problem != "":
		if s.logger != nil {
			s.logger.Info("observed DHCP evidence is available again")
		}
		state.problem = ""
	case err != nil && err.Error() != state.problem:
		if s.logger != nil {
			s.logger.Warn("observed DHCP evidence is unavailable; devices are named without it", "error", err)
		}
		state.problem = err.Error()
	}
}

// observedDHCPClients converts ingestd's clients for the inventory. A lease
// outside the lab's prefix (a neighbouring network sharing the segment)
// still names a MAC the lab knows, but binds no address and creates no
// device.
func observedDHCPClients(clients []ingest.ObservedDHCPClient, labPrefix netip.Prefix) []deviceinventory.ObservedDHCPClient {
	converted := make([]deviceinventory.ObservedDHCPClient, 0, len(clients))
	for _, client := range clients {
		item := deviceinventory.ObservedDHCPClient{
			HardwareAddr: client.HardwareAddr, HostName: client.HostName, ClientFQDN: client.ClientFQDN,
			VendorClass: client.VendorClass, ParameterList: client.ParameterList, FirstSeen: client.FirstSeen, LastSeen: client.LastSeen,
		}
		if assigned, err := netip.ParseAddr(client.AssignedAddr); err == nil && (!labPrefix.IsValid() || labPrefix.Contains(assigned)) {
			item.AssignedAddr, item.AssignedAt, item.LeaseTime = assigned, client.AssignedAt, time.Duration(client.LeaseSeconds)*time.Second
			if server, err := netip.ParseAddr(client.Server); err == nil {
				item.Server = server
			}
			if router, err := netip.ParseAddr(client.Router); err == nil {
				item.Router = router
			}
		}
		converted = append(converted, item)
	}
	return converted
}
