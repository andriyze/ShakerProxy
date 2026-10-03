package labrouting

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/ingest"
)

var singleArm = Context{
	Now:         time.Date(2026, 10, 2, 23, 52, 30, 0, time.UTC),
	ShakerProxy: netip.MustParseAddr("192.168.10.177"),
	Router:      netip.MustParseAddr("192.168.10.1"),
}

func at(clock string) time.Time {
	parsed, err := time.Parse("15:04:05", clock)
	if err != nil {
		panic(err)
	}
	return time.Date(2026, 10, 2, parsed.Hour(), parsed.Minute(), parsed.Second(), 0, time.UTC)
}

func only(t *testing.T, results []Result, address string) Result {
	t.Helper()
	for _, result := range results {
		if result.Address == address {
			return result
		}
	}
	t.Fatalf("%s not reported: %+v", address, results)
	return Result{}
}

// The test VM on 2026-10-02: the owner joined an iPhone to the lab Wi-Fi and
// browsed. The router's DHCP gave it 192.168.10.130; ShakerProxy saw its
// DHCP request and its mDNS, no connection, no DNS lookup, nothing sent to
// ShakerProxy.
func TestTheIPhoneOnTheRoutersDHCPBypassesShakerProxy(t *testing.T) {
	iphone := ingest.LabPresenceHost{
		Address: "192.168.10.130", HardwareAddrs: []string{"62:bc:f1:bc:1d:8d"}, HostName: "iPhone",
		FirstSeen: at("23:48:30"), LastSeen: at("23:52:06"), Events: 31, DiscoveryEvents: 30, DHCPLastSeen: at("23:48:30"),
	}
	result := only(t, Classify([]ingest.LabPresenceHost{iphone}, singleArm), "192.168.10.130")
	if result.Routing != Bypassing || !result.Since.Equal(at("23:48:30")) || result.HostName != "iPhone" {
		t.Fatalf("result = %+v", result)
	}
	if result.Reason != "It got its address from your router's DHCP, so it uses the router (192.168.10.1) as its gateway, not ShakerProxy." {
		t.Fatalf("reason = %q", result.Reason)
	}
	joined := strings.Join(result.Evidence, "; ")
	for _, want := range []string{"asked the network's DHCP server for 192.168.10.130", "30 local discovery messages", "no connections or DNS lookups through ShakerProxy"} {
		if !strings.Contains(joined, want) {
			t.Errorf("evidence %q lacks %q", joined, want)
		}
	}
}

// The Apple Watch that joined with it asked for an address twice within ten
// seconds and sent nothing else ShakerProxy could see: on the router's DHCP
// in a single-arm lab, that is enough once the threshold has passed.
func TestADeviceOnlySeenAskingTheRouterBypassesOnceTheThresholdPasses(t *testing.T) {
	watch := ingest.LabPresenceHost{Address: "192.168.10.64", HardwareAddrs: []string{"a6:e2:08:f3:d2:61"}, HostName: "Watch", FirstSeen: at("23:48:47"), LastSeen: at("23:48:56"), Events: 2, DHCPLastSeen: at("23:48:56")}
	if result := only(t, Classify([]ingest.LabPresenceHost{watch}, singleArm), "192.168.10.64"); result.Routing != Bypassing {
		t.Fatalf("result = %+v", result)
	}
	early := singleArm
	early.Now = at("23:49:30")
	if result := only(t, Classify([]ingest.LabPresenceHost{watch}, early), "192.168.10.64"); result.Routing != Unknown || result.Reason != "" {
		t.Fatalf("before the threshold: %+v", result)
	}
}

// A phone set to use ShakerProxy shows connections and lookups through it.
func TestARoutedPhoneGoesThroughShakerProxy(t *testing.T) {
	pixel := ingest.LabPresenceHost{
		Address: "192.168.10.201", HardwareAddrs: []string{"b6:53:83:65:54:a2"}, FirstSeen: at("23:30:00"), LastSeen: at("23:52:00"),
		Events: 400, DiscoveryEvents: 12, VisibleEvents: 380, VisibleFirstSeen: at("23:30:01"), VisibleLastSeen: at("23:51:58"),
	}
	result := only(t, Classify([]ingest.LabPresenceHost{pixel}, singleArm), "192.168.10.201")
	if result.Routing != Through || !result.Since.Equal(at("23:30:01")) || result.Reason != "" {
		t.Fatalf("result = %+v", result)
	}
	// Idle for a while, announcing itself only: still through ShakerProxy.
	idle := pixel
	idle.LastSeen = at("23:52:20")
	idle.VisibleLastSeen = at("23:40:00")
	if result := only(t, Classify([]ingest.LabPresenceHost{idle}, singleArm), "192.168.10.201"); result.Routing != Through {
		t.Fatalf("an idle routed phone: %+v", result)
	}
}

// A phone that went through ShakerProxy, then rejoined the Wi-Fi and took
// the router's DHCP, bypasses from that request on.
func TestAPhoneThatRejoinedThroughTheRoutersDHCPBypassesFromThen(t *testing.T) {
	phone := ingest.LabPresenceHost{
		Address: "192.168.10.201", FirstSeen: at("23:20:00"), LastSeen: at("23:52:10"), Events: 90, DiscoveryEvents: 20,
		VisibleEvents: 60, VisibleFirstSeen: at("23:20:00"), VisibleLastSeen: at("23:40:00"), DHCPLastSeen: at("23:45:00"),
	}
	result := only(t, Classify([]ingest.LabPresenceHost{phone}, singleArm), "192.168.10.201")
	if result.Routing != Bypassing || !result.Since.Equal(at("23:45:00")) {
		t.Fatalf("result = %+v", result)
	}
}

// Something that only just appeared, with no DHCP and a single announcement,
// is not judged yet; ShakerProxy, the router and devices gone for more than
// ten minutes are not reported.
func TestBriefMulticastIsUnknownAndInfrastructureIsSkipped(t *testing.T) {
	hosts := []ingest.LabPresenceHost{
		{Address: "192.168.10.50", FirstSeen: at("23:52:00"), LastSeen: at("23:52:00"), Events: 1, DiscoveryEvents: 1},
		{Address: "192.168.10.1", FirstSeen: at("23:00:00"), LastSeen: at("23:52:00"), Events: 900, DiscoveryEvents: 900},
		{Address: "192.168.10.177", FirstSeen: at("23:00:00"), LastSeen: at("23:52:00"), Events: 9, VisibleEvents: 9, VisibleFirstSeen: at("23:00:00"), VisibleLastSeen: at("23:52:00")},
		{Address: "192.168.10.99", FirstSeen: at("23:20:00"), LastSeen: at("23:30:00"), Events: 40, DiscoveryEvents: 40},
	}
	results := Classify(hosts, singleArm)
	if len(results) != 1 || results[0].Address != "192.168.10.50" || results[0].Routing != Unknown {
		t.Fatalf("results = %+v", results)
	}
}

// In a routed lab ShakerProxy serves DHCP; a device that never routes
// through it must have set its own address and gateway.
func TestRoutedLabReasonPointsAtAFixedAddress(t *testing.T) {
	routed := singleArm
	routed.ShakerProxyServesDHCP, routed.Router = true, netip.Addr{}
	host := ingest.LabPresenceHost{Address: "192.168.10.30", FirstSeen: at("23:40:00"), LastSeen: at("23:52:00"), Events: 12, DiscoveryEvents: 12}
	result := only(t, Classify([]ingest.LabPresenceHost{host}, routed), "192.168.10.30")
	if result.Routing != Bypassing || !strings.Contains(result.Reason, "fixed address") {
		t.Fatalf("result = %+v", result)
	}
	single := singleArm
	single.Router = netip.Addr{}
	if result := only(t, Classify([]ingest.LabPresenceHost{host}, single), "192.168.10.30"); result.Reason != "It uses the router as its gateway, not ShakerProxy." {
		t.Fatalf("reason without a known router = %q", result.Reason)
	}
}
