package server

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	deviceinventory "shakerproxy.dev/shakerproxy/internal/inventory"
)

// withNeighborEvidence adds the gateway's neighbor tables to the inventory
// after the DHCPv4 lease reconciliation: IPv6 NDP (SLAAC addresses) and IPv4
// ARP (single-arm clients and static-IP devices, which never lease from
// ShakerProxy). The tables are optional evidence: an unreachable or older
// gateway, or a plan without a routed lab, leaves the DHCP snapshot
// unchanged. Evidence that fails validation is an error.
func (s *Server) withNeighborEvidence(snapshot deviceinventory.Snapshot, err error) (deviceinventory.Snapshot, error) {
	if err != nil || s.inventory == nil || s.gateway.SocketPath == "" {
		return snapshot, err
	}
	var observations []deviceinventory.NeighborObservation
	for _, source := range []struct{ method, family string }{{"GetNeighbors", ""}, {"GetIPv4Neighbors", gatewayprotocol.NeighborFamilyIPv4}} {
		table, ok, tableErr := s.neighborTable(source.method)
		if tableErr != nil {
			return deviceinventory.Snapshot{}, tableErr
		}
		if !ok || !table.Active {
			continue
		}
		if table.Family != source.family {
			return deviceinventory.Snapshot{}, fmt.Errorf("gateway %s returned the wrong address family", source.method)
		}
		if table.Family == gatewayprotocol.NeighborFamilyIPv4 {
			s.noteIPv4Scope(deviceinventory.ObservedDHCPScope{Interface: table.Interface, VLANID: table.VLANID, ScopePlanSHA256: table.ScopePlanHash}, table.LabPrefix)
		}
		for _, neighbor := range table.Neighbors {
			observations = append(observations, deviceinventory.NeighborObservation{
				Address:         netip.MustParseAddr(neighbor.Address),
				HardwareAddr:    neighbor.HardwareAddress,
				SeenAt:          neighbor.LastConfirmedAt,
				Interface:       table.Interface,
				VLANID:          table.VLANID,
				ScopePlanSHA256: table.ScopePlanHash,
			})
		}
	}
	if len(observations) == 0 {
		return snapshot, nil
	}
	return s.inventory.ReconcileNeighbors(observations)
}

// neighborTable fetches and validates one gateway neighbor table. ok is false
// when the gateway cannot answer (unreachable, or an older gateway without
// the method).
func (s *Server) neighborTable(method string) (gatewayprotocol.NeighborTable, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var table gatewayprotocol.NeighborTable
	if callErr := s.gateway.CallWithTimeout(ctx, method, gatewayprotocol.EmptyParams{}, &table, 2*time.Second); callErr != nil {
		if s.logger != nil {
			s.logger.Debug("neighbor evidence unavailable", "method", method, "error", callErr)
		}
		return table, false, nil
	}
	if validateErr := table.Validate(); validateErr != nil {
		return table, false, fmt.Errorf("gateway neighbor table: %w", validateErr)
	}
	return table, true, nil
}
