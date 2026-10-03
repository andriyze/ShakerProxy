package daemon

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/networkplan"
	"shakerproxy.dev/shakerproxy/internal/networktransaction"
)

func netlinkAttribute(kind uint16, value []byte) []byte {
	length := 4 + len(value)
	attribute := make([]byte, (length+3)&^3)
	binary.NativeEndian.PutUint16(attribute[0:2], uint16(length))
	binary.NativeEndian.PutUint16(attribute[2:4], kind)
	copy(attribute[4:], value)
	return attribute
}

func netlinkMessage(kind uint16, sequence uint32, payload []byte) []byte {
	length := netlinkHeaderLength + len(payload)
	message := make([]byte, (length+3)&^3)
	binary.NativeEndian.PutUint32(message[0:4], uint32(length))
	binary.NativeEndian.PutUint16(message[4:6], kind)
	binary.NativeEndian.PutUint16(message[6:8], 2) // NLM_F_MULTI
	binary.NativeEndian.PutUint32(message[8:12], sequence)
	copy(message[netlinkHeaderLength:], payload)
	return message
}

type neighborFixture struct {
	family   byte
	index    int32
	state    uint16
	flags    uint8
	address  string
	mac      string
	ticks    uint32
	noCache  bool
	noLLAddr bool
}

func neighborPayload(fixture neighborFixture) []byte {
	payload := make([]byte, ndMessageLength)
	payload[0] = fixture.family
	if payload[0] == 0 {
		payload[0] = addressFamilyIPv6
	}
	binary.NativeEndian.PutUint32(payload[4:8], uint32(fixture.index))
	binary.NativeEndian.PutUint16(payload[8:10], fixture.state)
	payload[10] = fixture.flags
	parsed := netip.MustParseAddr(fixture.address)
	if payload[0] == addressFamilyIPv4 {
		address := parsed.As4()
		payload = append(payload, netlinkAttribute(ndaDestination, address[:])...)
	} else {
		address := parsed.As16()
		payload = append(payload, netlinkAttribute(ndaDestination, address[:])...)
	}
	if !fixture.noLLAddr {
		mac, _ := net.ParseMAC(fixture.mac)
		payload = append(payload, netlinkAttribute(ndaLinkLayerAddress, mac)...)
	}
	if !fixture.noCache {
		cache := make([]byte, 16)
		binary.NativeEndian.PutUint32(cache[0:4], fixture.ticks)
		payload = append(payload, netlinkAttribute(ndaCacheInfo, cache)...)
	}
	return payload
}

func TestNeighborDumpRequestIsAnIPv6Dump(t *testing.T) {
	request := neighborDumpRequest(7, addressFamilyIPv6)
	if len(request) != 28 || binary.NativeEndian.Uint32(request[0:4]) != 28 || binary.NativeEndian.Uint16(request[4:6]) != rtmGetNeighbor || binary.NativeEndian.Uint16(request[6:8]) != nlmFlagRequest|nlmFlagDump || binary.NativeEndian.Uint32(request[8:12]) != 7 || request[16] != addressFamilyIPv6 {
		t.Fatalf("unexpected neighbor dump request: %x", request)
	}
}

func TestParseNeighborMessagesReadsNDPEntries(t *testing.T) {
	buffer := append(netlinkMessage(rtmNewNeighbor, 9, neighborPayload(neighborFixture{index: 3, state: nudReachable, address: "fd12:3456:789a:1:5054:ff:fe12:3456", mac: "52:54:00:12:34:56", ticks: 250})),
		netlinkMessage(rtmNewNeighbor, 9, neighborPayload(neighborFixture{index: 3, state: nudStale, flags: ntfRouter, address: "fe80::5054:ff:fe12:3456", mac: "52:54:00:12:34:56", ticks: 6000}))...)
	buffer = append(buffer, netlinkMessage(rtmNewNeighbor, 9, neighborPayload(neighborFixture{family: 2, index: 3, state: nudReachable, address: "10.77.0.5", mac: "52:54:00:12:34:57"}))...)
	neighbors, done, err := parseNeighborMessages(buffer, 9)
	if err != nil || done || len(neighbors) != 3 {
		t.Fatalf("unexpected parse: %+v done=%v err=%v", neighbors, done, err)
	}
	if arp := neighbors[2]; arp.address.String() != "10.77.0.5" || arp.hardware.String() != "52:54:00:12:34:57" {
		t.Fatalf("ARP entry was not parsed: %+v", arp)
	}
	first := neighbors[0]
	if first.interfaceIndex != 3 || first.state != nudReachable || first.address.String() != "fd12:3456:789a:1:5054:ff:fe12:3456" || first.hardware.String() != "52:54:00:12:34:56" || !first.hasCacheInfo || first.confirmedTicks != 250 {
		t.Fatalf("unexpected neighbor: %+v", first)
	}
	if neighbors[1].flags&ntfRouter == 0 {
		t.Fatal("router flag was lost")
	}
	_, done, err = parseNeighborMessages(netlinkMessage(nlmsgDone, 9, make([]byte, 4)), 9)
	if err != nil || !done {
		t.Fatalf("NLMSG_DONE was not recognised: done=%v err=%v", done, err)
	}
	errorPayload := make([]byte, 20)
	binary.NativeEndian.PutUint32(errorPayload[0:4], uint32(0xffffffff)) // -EPERM
	if _, _, err := parseNeighborMessages(netlinkMessage(nlmsgError, 9, errorPayload), 9); err == nil || !strings.Contains(err.Error(), "errno 1") {
		t.Fatalf("kernel error was not surfaced: %v", err)
	}
}

func TestParseNeighborMessagesRejectsMalformedInput(t *testing.T) {
	valid := netlinkMessage(rtmNewNeighbor, 4, neighborPayload(neighborFixture{index: 1, state: nudReachable, address: "fe80::1", mac: "52:54:00:00:00:01"}))
	cases := map[string][]byte{
		"truncated header": valid[:10],
		"length too long": func() []byte {
			copy := append([]byte(nil), valid...)
			binary.NativeEndian.PutUint32(copy[0:4], uint32(len(copy)+8))
			return copy
		}(),
		"attribute overrun": func() []byte {
			copy := append([]byte(nil), valid...)
			binary.NativeEndian.PutUint16(copy[netlinkHeaderLength+ndMessageLength:], 200)
			return copy
		}(),
		"truncated neighbor": netlinkMessage(rtmNewNeighbor, 4, []byte{addressFamilyIPv6, 0, 0}),
	}
	for name, buffer := range cases {
		if _, _, err := parseNeighborMessages(buffer, 4); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
	if _, _, err := parseNeighborMessages(valid, 5); err == nil {
		t.Fatal("a message for another request was accepted")
	}
}

func TestSelectLabNeighborsKeepsOnlyUsableLabEvidence(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	prefix := netip.MustParsePrefix("fd12:3456:789a:1::/64")
	raw := func(index int32, state uint16, address, mac string, ticks uint32, cache bool) rawNeighbor {
		hardware, _ := net.ParseMAC(mac)
		return rawNeighbor{interfaceIndex: index, state: state, address: netip.MustParseAddr(address), hardware: hardware, confirmedTicks: ticks, hasCacheInfo: cache}
	}
	entries := []rawNeighbor{
		raw(3, nudReachable, "fd12:3456:789a:1::50", "52:54:00:00:00:50", 150, true),
		raw(3, nudStale, "fe80::50", "52:54:00:00:00:50", 100*3600, true),
		raw(3, nudDelay, "fd12:3456:789a:1::51", "52:54:00:00:00:51", 0, false),
		raw(4, nudReachable, "fd12:3456:789a:1::52", "52:54:00:00:00:52", 0, true),      // another interface
		raw(3, 0x20, "fd12:3456:789a:1::53", "52:54:00:00:00:53", 0, true),              // FAILED
		raw(3, 0x80, "fd12:3456:789a:1::54", "52:54:00:00:00:54", 0, true),              // PERMANENT (administrator entry)
		raw(3, nudReachable, "2a01:4f8::55", "52:54:00:00:00:55", 0, true),              // outside the lab prefix
		raw(3, nudReachable, "fd12:3456:789a:1::56", "01:00:5e:00:00:56", 0, true),      // multicast MAC
		raw(3, nudReachable, "fd12:3456:789a:1::57", "00:00:00:00:00:00", 0, true),      // zero MAC
		raw(3, nudStale, "fd12:3456:789a:1::58", "52:54:00:00:00:58", 0, false),         // stale without age
		raw(3, nudReachable, "fd12:3456:789a:1::50", "52:54:00:00:00:99", 0, true),      // duplicate address
		raw(3, nudStale, "fd12:3456:789a:1::59", "52:54:00:00:00:59", 4294967295, true), // clamp the age
	}
	neighbors, truncated := selectLabNeighbors(entries, 3, prefix, now)
	if truncated {
		t.Fatal("small table was reported truncated")
	}
	got := map[string]gatewayprotocol.Neighbor{}
	for _, neighbor := range neighbors {
		got[neighbor.Address] = neighbor
	}
	if len(got) != 4 || got["fd12:3456:789a:1::50"].HardwareAddress != "52:54:00:00:00:50" || got["fd12:3456:789a:1::50"].State != "REACHABLE" {
		t.Fatalf("unexpected selected neighbors: %+v", neighbors)
	}
	if !got["fd12:3456:789a:1::50"].LastConfirmedAt.Equal(now.Add(-1500*time.Millisecond)) || !got["fe80::50"].LastConfirmedAt.Equal(now.Add(-time.Hour)) || !got["fd12:3456:789a:1::51"].LastConfirmedAt.Equal(now) {
		t.Fatalf("confirmation ages were not converted from USER_HZ ticks: %+v", got)
	}
	if !got["fd12:3456:789a:1::59"].LastConfirmedAt.Equal(now.Add(-maxNeighborAge)) {
		t.Fatalf("neighbor age was not clamped: %+v", got["fd12:3456:789a:1::59"])
	}
	table := gatewayprotocol.NeighborTable{Schema: 1, Active: true, Interface: "enp2s0", ScopePlanHash: stateTestPlanHash, LabPrefix: prefix.String(), ObservedAt: now, Neighbors: neighbors}
	if err := table.Validate(); err != nil {
		t.Fatalf("selected neighbors do not form a valid table: %v", err)
	}
}

func confirmedIPv6Server(t *testing.T, ipv6 networkplan.IPv6Configuration) *Server {
	t.Helper()
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	staged := &networkplan.StagedPlan{
		PlanHash: stateTestPlanHash,
		Plan: networkplan.Plan{
			Topology:   networkplan.TopologyTwoNIC,
			Interfaces: []networkplan.Interface{{StableID: "wan", CurrentName: "lgtest-wan0", Role: networkplan.RoleWAN}, {StableID: "lab", CurrentName: "lgtest-lab0", Role: networkplan.RoleLab}},
			IPv6:       ipv6,
		},
		Status:      string(networktransaction.PhaseConfirmed),
		Transaction: &networktransaction.Record{Phase: networktransaction.PhaseConfirmed},
	}
	store.mu.Lock()
	store.state.StagedNetworkPlan = staged
	store.mu.Unlock()
	return NewServer(store, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestManagedStatePublishesConfirmedLabIPv6Scope(t *testing.T) {
	server := confirmedIPv6Server(t, networkplan.IPv6Configuration{Strategy: networkplan.IPv6ULANAT66Lab, LabPrefix: "fd12:3456:789a:1::/64"})
	result, rpcErr := server.dispatch(t.Context(), gatewayprotocol.Request{JSONRPC: gatewayprotocol.JSONRPCVersion, ID: "ipv6-scope", Method: "GetManagedState", Params: json.RawMessage(`{}`)})
	status, ok := result.(gatewayprotocol.Status)
	if rpcErr != nil || !ok || status.LabInterface != "lgtest-lab0" || status.LabIPv6Strategy != "ULA_NAT66_LAB" || status.LabIPv6Prefix != "fd12:3456:789a:1::/64" || status.LabIPv6Gateway != "fd12:3456:789a:1::1" {
		t.Fatalf("confirmed IPv6 scope was not published: %#v rpc=%#v", result, rpcErr)
	}
	disabled := confirmedIPv6Server(t, networkplan.IPv6Configuration{Strategy: networkplan.IPv6Disabled})
	result, _ = disabled.dispatch(t.Context(), gatewayprotocol.Request{JSONRPC: gatewayprotocol.JSONRPCVersion, ID: "ipv6-scope", Method: "GetManagedState", Params: json.RawMessage(`{}`)})
	if status := result.(gatewayprotocol.Status); status.LabIPv6Strategy != "DISABLED" || status.LabIPv6Prefix != "" {
		t.Fatalf("disabled IPv6 published a prefix: %#v", status)
	}
}

func TestGetNeighborsIsInactiveWithoutRoutedIPv6(t *testing.T) {
	server := confirmedIPv6Server(t, networkplan.IPv6Configuration{Strategy: networkplan.IPv6Disabled})
	result, rpcErr := server.dispatch(t.Context(), gatewayprotocol.Request{JSONRPC: gatewayprotocol.JSONRPCVersion, ID: "neighbors", Method: "GetNeighbors", Params: json.RawMessage(`{}`)})
	table, ok := result.(gatewayprotocol.NeighborTable)
	if rpcErr != nil || !ok || table.Active || len(table.Neighbors) != 0 || table.Validate() != nil {
		t.Fatalf("inactive neighbor table is wrong: %#v rpc=%#v", result, rpcErr)
	}
	if _, rpcErr := server.dispatch(t.Context(), gatewayprotocol.Request{JSONRPC: gatewayprotocol.JSONRPCVersion, ID: "neighbors-params", Method: "GetNeighbors", Params: json.RawMessage(`{"interface":"eth0"}`)}); rpcErr == nil || rpcErr.Code != -32602 {
		t.Fatalf("caller-selected neighbor interface was accepted: %#v", rpcErr)
	}
	routed := confirmedIPv6Server(t, networkplan.IPv6Configuration{Strategy: networkplan.IPv6ULANAT66Lab, LabPrefix: "fd12:3456:789a:1::/64"})
	if _, rpcErr := routed.dispatch(t.Context(), gatewayprotocol.Request{JSONRPC: gatewayprotocol.JSONRPCVersion, ID: "neighbors-missing", Method: "GetNeighbors", Params: json.RawMessage(`{}`)}); rpcErr == nil || rpcErr.Code != -32080 {
		t.Fatalf("missing lab interface was not reported: %#v", rpcErr)
	}
}

type fakeRadvdFinalizer struct {
	fakeConfirmationFinalizer
	radvdCalls []string
	err        error
}

func (f *fakeRadvdFinalizer) EnableRadvd(context.Context) error {
	f.radvdCalls = append(f.radvdCalls, "enable")
	return f.err
}

func (f *fakeRadvdFinalizer) DisableRadvd(context.Context) error {
	f.radvdCalls = append(f.radvdCalls, "disable")
	return f.err
}

func TestFinalizeRadvdFollowsTheConfirmedStrategy(t *testing.T) {
	routed := networkplan.Plan{Topology: networkplan.TopologyTwoNIC, IPv6: networkplan.IPv6Configuration{Strategy: networkplan.IPv6NativeRouted, LabPrefix: "2a01:4f8:1c1c:a001::/64"}}
	disabled := networkplan.Plan{Topology: networkplan.TopologyTwoNIC, IPv6: networkplan.IPv6Configuration{Strategy: networkplan.IPv6Disabled}}
	finalizer := &fakeRadvdFinalizer{}
	if err := finalizeRadvd(context.Background(), finalizer, routed); err != nil {
		t.Fatal(err)
	}
	if err := finalizeRadvd(context.Background(), finalizer, disabled); err != nil {
		t.Fatal(err)
	}
	if strings.Join(finalizer.radvdCalls, ",") != "enable,disable" {
		t.Fatalf("unexpected radvd finalization: %v", finalizer.radvdCalls)
	}
	finalizer.err = errors.New("unit missing")
	if err := finalizeRadvd(context.Background(), finalizer, routed); err == nil {
		t.Fatal("radvd enablement failure was ignored")
	}
	plain := &fakeConfirmationFinalizer{}
	if err := finalizeRadvd(context.Background(), plain, disabled); err != nil {
		t.Fatalf("IPv4-only finalizer must not fail a non-routing plan: %v", err)
	}
	if err := finalizeRadvd(context.Background(), plain, routed); err == nil {
		t.Fatal("routed IPv6 confirmed without radvd boot enablement")
	}
}

func TestNeighborDumpRequestCarriesTheFamily(t *testing.T) {
	if request := neighborDumpRequest(8, addressFamilyIPv4); request[16] != addressFamilyIPv4 {
		t.Fatalf("IPv4 dump request has family %d", request[16])
	}
}

func TestSelectLabIPv4NeighborsKeepsOnlyLabClients(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	entry := func(address, mac string, state uint16) rawNeighbor {
		hardware, _ := net.ParseMAC(mac)
		return rawNeighbor{interfaceIndex: 3, state: state, address: netip.MustParseAddr(address), hardware: hardware, hasCacheInfo: true, confirmedTicks: 100}
	}
	prefix := netip.MustParsePrefix("172.31.32.0/20")
	entries := []rawNeighbor{
		entry("172.31.47.197", "0e:00:00:00:00:01", nudReachable), // lab client
		entry("172.31.32.1", "0e:00:00:00:00:02", nudReachable),   // upstream router
		entry("172.31.47.80", "0e:00:00:00:00:03", nudReachable),  // ShakerProxy
		entry("172.31.32.0", "0e:00:00:00:00:04", nudReachable),   // network
		entry("172.31.47.255", "0e:00:00:00:00:05", nudReachable), // broadcast
		entry("10.0.0.9", "0e:00:00:00:00:06", nudReachable),      // outside the lab
		entry("172.31.40.7", "0e:00:00:00:00:07", 0),              // failed/incomplete
		{interfaceIndex: 4, state: nudReachable, address: netip.MustParseAddr("172.31.40.8"), hardware: net.HardwareAddr{0x0e, 0, 0, 0, 0, 8}},
	}
	excluded := map[netip.Addr]bool{netip.MustParseAddr("172.31.32.1"): true, netip.MustParseAddr("172.31.47.80"): true}
	neighbors, truncated := selectLabIPv4Neighbors(entries, 3, prefix, excluded, now)
	if truncated || len(neighbors) != 1 || neighbors[0].Address != "172.31.47.197" || neighbors[0].Router {
		t.Fatalf("unexpected IPv4 lab neighbors: %+v", neighbors)
	}
	if last := lastIPv4(netip.MustParsePrefix("10.77.0.0/24")); last.String() != "10.77.0.255" {
		t.Fatalf("broadcast = %s", last)
	}
}

// The test VM: ShakerProxy is 192.168.10.177 on the lab, and the lab
// interface's default route goes through the UniFi router 192.168.10.1.
func TestLabRouterIsTheLabsOwnDefaultGateway(t *testing.T) {
	prefix := netip.MustParsePrefix("192.168.10.0/24")
	gateways := map[netip.Addr]bool{netip.MustParseAddr("192.168.10.177"): true, netip.MustParseAddr("192.168.10.1"): true, netip.MustParseAddr("10.0.0.1"): true}
	router, ok := labRouter(gateways, prefix, "192.168.10.177")
	if !ok || router != netip.MustParseAddr("192.168.10.1") {
		t.Fatalf("router = %v ok=%v", router, ok)
	}
	if _, ok := labRouter(map[netip.Addr]bool{netip.MustParseAddr("10.0.0.1"): true}, prefix, "192.168.10.177"); ok {
		t.Fatal("a gateway outside the lab prefix was taken for the lab's router")
	}
	status := gatewayprotocol.Status{}
	setLabIPv4Status(&status, networkplan.Plan{IPv4: networkplan.IPv4Configuration{Enabled: true, LabCIDR: "192.168.10.0/24", GatewayAddress: "192.168.10.177"}})
	if status.LabIPv4Prefix != "192.168.10.0/24" || status.LabIPv4Gateway != "192.168.10.177" {
		t.Fatalf("status = %+v", status)
	}
}
