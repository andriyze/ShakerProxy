package server

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/ingest"
	deviceinventory "shakerproxy.dev/shakerproxy/internal/inventory"
	"shakerproxy.dev/shakerproxy/internal/labrouting"
	"shakerproxy.dev/shakerproxy/internal/networkplan"
)

// Devices on the lab network whose traffic never reaches ShakerProxy are the
// first thing a tester must know about: they browse, and ShakerProxy shows
// nothing. The lab routing report says which devices those are, why, and
// what ShakerProxy's and the router's addresses are, so the fix can be
// given in concrete terms. It also adds those devices to the inventory: a
// device that bypasses ShakerProxy leaves no ARP or DHCP lease to find it
// by, only its broadcasts.

const (
	LabRoutingSchema        = 1
	labRoutingLookupTimeout = 3 * time.Second
	labRoutingCacheTTL      = 15 * time.Second
)

type labRoutingDevice struct {
	labrouting.Result
	DeviceID    string `json:"device_id,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
}

type labRoutingCounts struct {
	Through   int `json:"through_shakerproxy"`
	Bypassing int `json:"bypassing"`
	Unknown   int `json:"unknown"`
}

type labRoutingReport struct {
	Schema      int       `json:"schema"`
	GeneratedAt time.Time `json:"generated_at"`
	// Available is false when there is no routed lab to judge, or the
	// recorded traffic could not be read; Unavailable then says why.
	Available          bool               `json:"available"`
	Unavailable        string             `json:"unavailable,omitempty"`
	Topology           string             `json:"topology,omitempty"`
	Prefix             string             `json:"prefix,omitempty"`
	SubnetMask         string             `json:"subnet_mask,omitempty"`
	ShakerProxyAddress string             `json:"shakerproxy_address,omitempty"`
	RouterAddress      string             `json:"router_address,omitempty"`
	ThresholdSeconds   int                `json:"threshold_seconds"`
	Counts             labRoutingCounts   `json:"counts"`
	Devices            []labRoutingDevice `json:"devices"`
}

type labRoutingState struct {
	mu        sync.Mutex
	fetchedAt time.Time
	report    labRoutingReport
	problem   string
}

func (s *Server) getLabRouting(w http.ResponseWriter, r *http.Request) {
	if len(r.URL.Query()) != 0 {
		writeError(w, http.StatusBadRequest, "invalid_query", "lab routing takes no parameters")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, s.currentLabRouting(r.Context()))
}

// currentLabRouting returns the report, at most labRoutingCacheTTL old.
func (s *Server) currentLabRouting(ctx context.Context) labRoutingReport {
	state := &s.labRouting
	state.mu.Lock()
	defer state.mu.Unlock()
	now := time.Now().UTC()
	if !state.fetchedAt.IsZero() && now.Sub(state.fetchedAt) < labRoutingCacheTTL {
		return state.report
	}
	report, problem := s.buildLabRouting(ctx, now)
	s.noteLabRoutingProblem(state, problem)
	state.fetchedAt, state.report = now, report
	return report
}

func unavailableLabRouting(now time.Time, reason string) labRoutingReport {
	return labRoutingReport{Schema: LabRoutingSchema, GeneratedAt: now, Unavailable: reason, ThresholdSeconds: int(labrouting.DefaultThreshold / time.Second), Devices: []labRoutingDevice{}}
}

// buildLabRouting judges the lab; the second result is an operational
// problem worth logging (not an absent lab).
func (s *Server) buildLabRouting(ctx context.Context, now time.Time) (labRoutingReport, string) {
	lookup, cancel := context.WithTimeout(ctx, labRoutingLookupTimeout)
	defer cancel()
	var status gatewayprotocol.Status
	if err := s.gateway.Call(lookup, "GetManagedState", gatewayprotocol.EmptyParams{}, &status); err != nil {
		return unavailableLabRouting(now, "ShakerProxy's gateway service did not answer."), ""
	}
	prefix, prefixErr := netip.ParsePrefix(status.LabIPv4Prefix)
	if status.OperatingMode != gatewayprotocol.ModeRouted || status.EmergencyBypass || prefixErr != nil || !ingest.ValidLabPresencePrefix(prefix) {
		return unavailableLabRouting(now, "No lab network routes through ShakerProxy right now."), ""
	}
	reader, ok := s.eventReader.(ingest.LabPresenceReader)
	if !ok || reader == nil {
		return unavailableLabRouting(now, "Recorded traffic cannot be read."), ""
	}
	presence, err := reader.QueryLabPresence(lookup, prefix)
	if err != nil {
		return unavailableLabRouting(now, "Recorded traffic cannot be read right now."), err.Error()
	}
	shakerProxy, _ := netip.ParseAddr(status.LabIPv4Gateway)
	router, _ := netip.ParseAddr(status.LabIPv4Router)
	judge := labrouting.Context{
		Now: now, ShakerProxy: shakerProxy, Router: router, Threshold: labrouting.DefaultThreshold,
		ShakerProxyServesDHCP: networkplan.UsesManagedDHCP4(networkplan.Plan{Topology: networkplan.Topology(status.LabTopology)}),
	}
	results := labrouting.Classify(presence.Hosts, judge)
	report := labRoutingReport{
		Schema: LabRoutingSchema, GeneratedAt: now, Available: true, Topology: status.LabTopology, Prefix: prefix.String(),
		SubnetMask: net.IP(net.CIDRMask(prefix.Bits(), 32)).String(), ShakerProxyAddress: status.LabIPv4Gateway, RouterAddress: status.LabIPv4Router,
		ThresholdSeconds: int(labrouting.DefaultThreshold / time.Second), Devices: make([]labRoutingDevice, 0, len(results)),
	}
	problem := ""
	snapshot, inventoryOK := s.addLabPresenceDevices(presence.Hosts, results, status)
	if !inventoryOK {
		problem = "lab devices could not be added to the inventory"
	}
	for _, result := range results {
		device := labRoutingDevice{Result: result}
		if inventoryOK {
			device.DeviceID, device.DisplayName = labDeviceFor(snapshot, result)
		}
		if device.DisplayName == "" {
			device.DisplayName = result.HostName
		}
		report.Devices = append(report.Devices, device)
		switch result.Routing {
		case labrouting.Through:
			report.Counts.Through++
		case labrouting.Bypassing:
			report.Counts.Bypassing++
		default:
			report.Counts.Unknown++
		}
	}
	return report, problem
}

// addLabPresenceDevices adds the devices that have no other evidence (those
// whose traffic does not go through ShakerProxy) to the inventory, and
// returns the inventory.
func (s *Server) addLabPresenceDevices(hosts []ingest.LabPresenceHost, results []labrouting.Result, status gatewayprotocol.Status) (deviceinventory.Snapshot, bool) {
	if s.inventory == nil {
		return deviceinventory.Snapshot{}, false
	}
	judged := map[string]labrouting.Routing{}
	for _, result := range results {
		judged[result.Address] = result.Routing
	}
	var observations []deviceinventory.LANPresence
	for _, host := range hosts {
		routing, ok := judged[host.Address]
		address, err := netip.ParseAddr(host.Address)
		if !ok || routing == labrouting.Through || err != nil {
			continue
		}
		for _, mac := range host.HardwareAddrs {
			observations = append(observations, deviceinventory.LANPresence{HardwareAddr: mac, Address: address, HostName: host.HostName, FirstSeen: host.FirstSeen, LastSeen: host.LastSeen})
		}
	}
	if len(observations) > 0 && status.LabInterface != "" {
		scope := deviceinventory.ObservedDHCPScope{Interface: status.LabInterface, VLANID: status.LabVLANID, ScopePlanSHA256: status.LabScopePlanHash}
		snapshot, err := s.inventory.ReconcileLANPresence(observations, scope)
		if err == nil {
			return snapshot, true
		}
		if s.logger != nil {
			s.logger.Warn("lab devices seen only on the network could not be added", "error", err)
		}
	}
	snapshot, err := s.inventory.Snapshot()
	return snapshot, err == nil
}

// labDeviceFor finds the inventory device behind a result: by MAC, else by
// an active address.
func labDeviceFor(snapshot deviceinventory.Snapshot, result labrouting.Result) (string, string) {
	macs := map[string]bool{}
	for _, mac := range result.HardwareAddrs {
		macs[mac] = true
	}
	for _, device := range snapshot.Devices {
		for _, identity := range device.Identities {
			if identity.Kind == deviceinventory.IdentityMAC && macs[identity.Value] {
				return device.ID, device.FriendlyName
			}
		}
	}
	for _, device := range snapshot.Devices {
		for _, address := range device.Addresses {
			if address.Active && address.Address == result.Address {
				return device.ID, device.FriendlyName
			}
		}
	}
	return "", ""
}

// noteLabRoutingProblem logs a problem once, and its recovery; the caller
// holds state.mu.
func (s *Server) noteLabRoutingProblem(state *labRoutingState, problem string) {
	switch {
	case problem == "" && state.problem != "":
		if s.logger != nil {
			s.logger.Info("lab routing evidence is available again")
		}
	case problem != "" && problem != state.problem && s.logger != nil:
		s.logger.Warn("lab routing evidence is unavailable", "error", problem)
	}
	state.problem = problem
}

// labRoutingByDevice keys the report by inventory device for the device
// list.
func labRoutingByDevice(report labRoutingReport) map[string]labRoutingDevice {
	if !report.Available {
		return nil
	}
	byDevice := map[string]labRoutingDevice{}
	for _, device := range report.Devices {
		if device.DeviceID != "" {
			if _, seen := byDevice[device.DeviceID]; !seen {
				byDevice[device.DeviceID] = device
			}
		}
	}
	return byDevice
}

// withLabPresence refreshes the lab routing report (and with it the
// inventory's lab-only devices) on each inventory refresh; it never fails
// the refresh.
func (s *Server) withLabPresence(snapshot deviceinventory.Snapshot, err error) (deviceinventory.Snapshot, error) {
	if err != nil || s.inventory == nil || s.gateway.SocketPath == "" {
		return snapshot, err
	}
	if _, ok := s.eventReader.(ingest.LabPresenceReader); !ok {
		return snapshot, nil
	}
	s.currentLabRouting(context.Background())
	return snapshot, nil
}

// labDeviceTitle is the device as the UI titles it: "iPhone · 192.168.10.130".
func labDeviceTitle(device labRoutingDevice) string {
	if device.DisplayName == "" {
		return device.Address
	}
	return device.DisplayName + " · " + device.Address
}
