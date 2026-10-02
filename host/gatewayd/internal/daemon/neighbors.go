package daemon

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/networkplan"
)

// IPv6 neighbor discovery evidence for device attribution. SLAAC addresses
// never appear in DHCP leases, so the kernel's neighbor table on the lab
// interface is the authoritative MAC-to-IPv6 mapping ShakerProxy can observe.

// Linux netlink constants (stable kernel ABI), kept here so parsing is
// testable on every platform.
const (
	netlinkHeaderLength = 16
	ndMessageLength     = 12
	nlmsgError          = 2
	nlmsgDone           = 3
	rtmNewNeighbor      = 28
	rtmGetNeighbor      = 30
	nlmFlagRequest      = 0x1
	nlmFlagDump         = 0x300
	addressFamilyIPv4   = 2
	addressFamilyIPv6   = 10
	ndaDestination      = 1
	ndaLinkLayerAddress = 2
	ndaCacheInfo        = 3
	nudReachable        = 0x02
	nudStale            = 0x04
	nudDelay            = 0x08
	nudProbe            = 0x10
	ntfRouter           = 0x80
	// Neighbor cache ages are reported in USER_HZ clock ticks.
	userHZ = 100

	maxNeighborDumpBytes = 8 << 20
	maxNeighborAge       = 30 * 24 * time.Hour
)

type rawNeighbor struct {
	interfaceIndex int32
	state          uint16
	flags          uint8
	address        netip.Addr
	hardware       net.HardwareAddr
	confirmedTicks uint32
	hasCacheInfo   bool
}

// neighborDumpRequest builds an RTM_GETNEIGH dump request for one address
// family (addressFamilyIPv4 or addressFamilyIPv6).
func neighborDumpRequest(sequence uint32, family uint8) []byte {
	request := make([]byte, netlinkHeaderLength+ndMessageLength)
	binary.NativeEndian.PutUint32(request[0:4], uint32(len(request)))
	binary.NativeEndian.PutUint16(request[4:6], rtmGetNeighbor)
	binary.NativeEndian.PutUint16(request[6:8], nlmFlagRequest|nlmFlagDump)
	binary.NativeEndian.PutUint32(request[8:12], sequence)
	request[netlinkHeaderLength] = family
	return request
}

// parseNeighborMessages parses one netlink receive buffer. It returns done
// once the dump's NLMSG_DONE arrives. Malformed input is an error rather than
// silently truncated evidence.
func parseNeighborMessages(buffer []byte, sequence uint32) ([]rawNeighbor, bool, error) {
	var neighbors []rawNeighbor
	for len(buffer) > 0 {
		if len(buffer) < netlinkHeaderLength {
			return nil, false, errors.New("netlink message header is truncated")
		}
		length := int(binary.NativeEndian.Uint32(buffer[0:4]))
		kind := binary.NativeEndian.Uint16(buffer[4:6])
		messageSequence := binary.NativeEndian.Uint32(buffer[8:12])
		if length < netlinkHeaderLength || length > len(buffer) {
			return nil, false, errors.New("netlink message length is invalid")
		}
		payload := buffer[netlinkHeaderLength:length]
		if messageSequence != sequence {
			return nil, false, errors.New("netlink message belongs to another request")
		}
		switch kind {
		case nlmsgDone:
			return neighbors, true, nil
		case nlmsgError:
			if len(payload) < 4 {
				return nil, false, errors.New("netlink error message is truncated")
			}
			if code := int32(binary.NativeEndian.Uint32(payload[0:4])); code != 0 {
				return nil, false, fmt.Errorf("kernel rejected the neighbor dump (errno %d)", -code)
			}
		case rtmNewNeighbor:
			neighbor, ok, err := parseNeighbor(payload)
			if err != nil {
				return nil, false, err
			}
			if ok {
				neighbors = append(neighbors, neighbor)
			}
		}
		aligned := (length + 3) &^ 3
		if aligned > len(buffer) {
			aligned = len(buffer)
		}
		buffer = buffer[aligned:]
	}
	return neighbors, false, nil
}

func parseNeighbor(payload []byte) (rawNeighbor, bool, error) {
	if len(payload) < ndMessageLength {
		return rawNeighbor{}, false, errors.New("neighbor message is truncated")
	}
	if payload[0] != addressFamilyIPv6 && payload[0] != addressFamilyIPv4 {
		return rawNeighbor{}, false, nil
	}
	addressLength := 16
	if payload[0] == addressFamilyIPv4 {
		addressLength = 4
	}
	neighbor := rawNeighbor{
		interfaceIndex: int32(binary.NativeEndian.Uint32(payload[4:8])),
		state:          binary.NativeEndian.Uint16(payload[8:10]),
		flags:          payload[10],
	}
	attributes := payload[ndMessageLength:]
	for len(attributes) >= 4 {
		length := int(binary.NativeEndian.Uint16(attributes[0:2]))
		kind := binary.NativeEndian.Uint16(attributes[2:4]) & 0x3fff
		if length < 4 || length > len(attributes) {
			return rawNeighbor{}, false, errors.New("neighbor attribute length is invalid")
		}
		value := attributes[4:length]
		switch kind {
		case ndaDestination:
			switch {
			case len(value) != addressLength:
			case addressLength == 4:
				neighbor.address = netip.AddrFrom4([4]byte(value))
			default:
				neighbor.address = netip.AddrFrom16([16]byte(value))
			}
		case ndaLinkLayerAddress:
			neighbor.hardware = append(net.HardwareAddr(nil), value...)
		case ndaCacheInfo:
			if len(value) >= 4 {
				neighbor.confirmedTicks = binary.NativeEndian.Uint32(value[0:4])
				neighbor.hasCacheInfo = true
			}
		}
		aligned := (length + 3) &^ 3
		if aligned > len(attributes) {
			aligned = len(attributes)
		}
		attributes = attributes[aligned:]
	}
	return neighbor, neighbor.address.IsValid(), nil
}

// selectLabNeighbors keeps only usable lab evidence: live NDP states on the
// lab interface, unicast MACs, and addresses that are link-local or inside
// the lab prefix. Addresses from any other prefix are spoofed or stale and
// are never attributed.
func selectLabNeighbors(entries []rawNeighbor, interfaceIndex int, prefix netip.Prefix, now time.Time) ([]gatewayprotocol.Neighbor, bool) {
	return selectNeighbors(entries, interfaceIndex, now, func(address netip.Addr) bool {
		return address.Is6() && !address.Is4In6() && !address.IsMulticast() && !address.IsUnspecified() && !address.IsLoopback() && (address.IsLinkLocalUnicast() || prefix.Contains(address))
	})
}

// selectLabIPv4Neighbors keeps ARP evidence for lab clients: live entries on
// the lab interface inside the lab CIDR, never ShakerProxy itself, the
// network or broadcast address, or an excluded router.
func selectLabIPv4Neighbors(entries []rawNeighbor, interfaceIndex int, prefix netip.Prefix, excluded map[netip.Addr]bool, now time.Time) ([]gatewayprotocol.Neighbor, bool) {
	network := prefix.Masked().Addr()
	broadcast := lastIPv4(prefix)
	return selectNeighbors(entries, interfaceIndex, now, func(address netip.Addr) bool {
		return address.Is4() && prefix.Contains(address) && address != network && address != broadcast && !excluded[address]
	})
}

func lastIPv4(prefix netip.Prefix) netip.Addr {
	bytes := prefix.Masked().Addr().As4()
	value := binary.BigEndian.Uint32(bytes[:]) | (uint32(1)<<(32-prefix.Bits()) - 1)
	binary.BigEndian.PutUint32(bytes[:], value)
	return netip.AddrFrom4(bytes)
}

func selectNeighbors(entries []rawNeighbor, interfaceIndex int, now time.Time, accept func(netip.Addr) bool) ([]gatewayprotocol.Neighbor, bool) {
	byAddress := map[netip.Addr]gatewayprotocol.Neighbor{}
	for _, entry := range entries {
		if int(entry.interfaceIndex) != interfaceIndex {
			continue
		}
		state := neighborStateName(entry.state)
		if state == "" {
			continue
		}
		address := entry.address
		if !accept(address) {
			continue
		}
		if len(entry.hardware) != 6 || entry.hardware[0]&1 != 0 || isZeroHardware(entry.hardware) {
			continue
		}
		confirmed := now
		if entry.hasCacheInfo {
			age := time.Duration(entry.confirmedTicks) * (time.Second / userHZ)
			if age > maxNeighborAge {
				age = maxNeighborAge
			}
			confirmed = now.Add(-age)
		} else if state == "STALE" {
			continue
		}
		if _, duplicate := byAddress[address]; duplicate {
			continue
		}
		byAddress[address] = gatewayprotocol.Neighbor{Address: address.String(), HardwareAddress: entry.hardware.String(), State: state, Router: address.Is6() && entry.flags&ntfRouter != 0, LastConfirmedAt: confirmed.UTC()}
	}
	neighbors := make([]gatewayprotocol.Neighbor, 0, len(byAddress))
	for _, neighbor := range byAddress {
		neighbors = append(neighbors, neighbor)
	}
	sort.Slice(neighbors, func(i, j int) bool { return neighbors[i].Address < neighbors[j].Address })
	if len(neighbors) > gatewayprotocol.MaxNeighbors {
		return neighbors[:gatewayprotocol.MaxNeighbors], true
	}
	return neighbors, false
}

func neighborStateName(state uint16) string {
	switch {
	case state&nudReachable != 0:
		return "REACHABLE"
	case state&nudDelay != 0:
		return "DELAY"
	case state&nudProbe != 0:
		return "PROBE"
	case state&nudStale != 0:
		return "STALE"
	}
	return ""
}

func isZeroHardware(address net.HardwareAddr) bool {
	for _, octet := range address {
		if octet != 0 {
			return false
		}
	}
	return true
}

// neighborTable answers GetNeighbors. It is read-only and returns an inactive
// table unless a confirmed plan routes lab IPv6.
func (s *Server) neighborTable(ctx context.Context) (gatewayprotocol.NeighborTable, error) {
	now := time.Now().UTC()
	table := gatewayprotocol.NeighborTable{Schema: gatewayprotocol.NeighborTableSchema, ObservedAt: now, Neighbors: []gatewayprotocol.Neighbor{}}
	staged := s.store.Get().activeNetworkPlan()
	if staged == nil {
		return table, nil
	}
	labIPv6, ok := networkplan.LabIPv6Routing(staged.Plan)
	if !ok {
		return table, nil
	}
	iface, err := net.InterfaceByName(labIPv6.Interface)
	if err != nil {
		return table, errors.New("lab interface is unavailable")
	}
	entries, err := dumpNeighbors(ctx, addressFamilyIPv6)
	if err != nil {
		return table, err
	}
	table.Active = true
	table.Interface = labIPv6.Interface
	table.VLANID = cloneVLANID(labIPv6.VLANID)
	table.ScopePlanHash = staged.PlanHash
	table.LabPrefix = labIPv6.Prefix.String()
	table.Neighbors, table.Truncated = selectLabNeighbors(entries, iface.Index, labIPv6.Prefix, now)
	return table, table.Validate()
}

// ipv4NeighborTable answers GetIPv4Neighbors: the lab interface's ARP table.
// Clients of a single-arm lab and static-IP devices never lease an address
// from ShakerProxy, so this is the only IPv4 evidence for them. It is
// read-only and returns an inactive table unless an IPv4 lab is confirmed.
func (s *Server) ipv4NeighborTable(ctx context.Context) (gatewayprotocol.NeighborTable, error) {
	now := time.Now().UTC()
	table := gatewayprotocol.NeighborTable{Schema: gatewayprotocol.NeighborTableSchema, Family: gatewayprotocol.NeighborFamilyIPv4, ObservedAt: now, Neighbors: []gatewayprotocol.Neighbor{}}
	lab, plan, ok := confirmedLabPlan(s.store)
	if !ok {
		return table, nil
	}
	prefix, err := netip.ParsePrefix(plan.IPv4.LabCIDR)
	if err != nil || !prefix.Addr().Is4() || prefix.Bits() > 30 {
		return table, nil
	}
	prefix = prefix.Masked()
	iface, err := net.InterfaceByName(lab.CurrentName)
	if err != nil {
		return table, errors.New("lab interface is unavailable")
	}
	excluded := defaultIPv4Gateways(lab.CurrentName)
	if gateway, err := netip.ParseAddr(plan.IPv4.GatewayAddress); err == nil {
		excluded[gateway] = true
	}
	entries, err := dumpNeighbors(ctx, addressFamilyIPv4)
	if err != nil {
		return table, err
	}
	staged := s.store.Get().activeNetworkPlan()
	if staged == nil {
		return table, nil
	}
	table.Active = true
	table.Interface = lab.CurrentName
	table.VLANID = cloneVLANID(lab.VLANID)
	table.ScopePlanHash = staged.PlanHash
	table.LabPrefix = prefix.String()
	table.Neighbors, table.Truncated = selectLabIPv4Neighbors(entries, iface.Index, prefix, excluded, now)
	return table, table.Validate()
}

// defaultIPv4Gateways returns the next hops of IPv4 default routes on iface.
// In a single-arm lab the upstream router shares the lab subnet; it is not a
// device under test.
func defaultIPv4Gateways(iface string) map[netip.Addr]bool {
	gateways := map[netip.Addr]bool{}
	data, err := readBoundedDiagnosticFile("/proc/net/route", 1<<20)
	if err != nil {
		return gateways
	}
	for index, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if index == 0 || len(fields) < 3 || fields[0] != iface || fields[1] != "00000000" {
			continue
		}
		value, err := strconv.ParseUint(fields[2], 16, 32)
		if err != nil || value == 0 {
			continue
		}
		var address [4]byte
		binary.LittleEndian.PutUint32(address[:], uint32(value))
		gateways[netip.AddrFrom4(address)] = true
	}
	return gateways
}

// setLabIPv6Status publishes the confirmed plan's IPv6 lab scope in
// GetManagedState so other components can discover it.
func setLabIPv6Status(status *gatewayprotocol.Status, plan networkplan.Plan) {
	// The topology and Wi-Fi tell the visibility coverage check which ways
	// around ShakerProxy a lab leaves open.
	status.LabTopology = string(plan.Topology)
	status.LabWiFi = networkplan.WiFiEnabled(plan)
	status.LabIPv6Strategy = string(plan.IPv6.Strategy)
	if labIPv6, ok := networkplan.LabIPv6Routing(plan); ok {
		status.LabIPv6Prefix = labIPv6.Prefix.String()
		status.LabIPv6Gateway = labIPv6.Gateway.String()
	}
}
