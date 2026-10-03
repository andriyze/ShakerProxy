package ingest

import (
	"net/netip"
	"testing"
	"time"
)

// The real records from the test VM: the iPhone's mDNS (with its MAC from
// Zeek's conn.log) and its DHCP request, the Watch's DHCP request only, and
// an iPad on a neighbouring network whose request must not count.
func TestMergeLabPresenceAddsMACsAndDHCPRequests(t *testing.T) {
	prefix := netip.MustParsePrefix("192.168.10.0/24")
	base := time.Date(2026, 10, 2, 23, 48, 30, 0, time.UTC)
	hosts := map[string]*LabPresenceHost{
		"192.168.10.130": {Address: "192.168.10.130", FirstSeen: base.Add(time.Minute), LastSeen: base.Add(3 * time.Minute), Events: 30, DiscoveryEvents: 30},
	}
	macs := []labPresenceMAC{
		{address: "192.168.10.130", mac: "62:bc:f1:bc:1d:8d", first: base.Add(time.Minute), last: base.Add(3 * time.Minute)},
		{address: "192.168.10.130", mac: "01:00:5e:00:00:fb"},
		{address: "192.168.10.250", mac: "aa:bb:cc:dd:ee:01"},
	}
	iphone, ok := parseZeekDHCP([]byte(`{"mac":"62:bc:f1:bc:1d:8d","host_name":"iPhone","msg_types":["DISCOVER","REQUEST"],"requested_addr":"192.168.10.130","client_param_list":[1,121,3,6,15,108,114,119,162,252]}`), base)
	watch, ok2 := parseZeekDHCP([]byte(`{"mac":"a6:e2:08:f3:d2:61","host_name":"Watch","msg_types":["DISCOVER","REQUEST"],"requested_addr":"192.168.10.64"}`), base.Add(17*time.Second))
	ipad, ok3 := parseZeekDHCP([]byte(`{"mac":"b4:17:a8:fb:a0:2e","msg_types":["DISCOVER","REQUEST"],"requested_addr":"192.168.100.34"}`), base)
	if !ok || !ok2 || !ok3 {
		t.Fatal("DHCP records did not parse")
	}
	merged := mergeLabPresence(hosts, macs, []dhcpExchange{iphone, watch, ipad}, prefix)
	if len(merged) != 2 {
		t.Fatalf("merged = %+v", merged)
	}
	byAddress := map[string]LabPresenceHost{}
	for _, host := range merged {
		byAddress[host.Address] = host
	}
	got := byAddress["192.168.10.130"]
	if got.HostName != "iPhone" || len(got.HardwareAddrs) != 1 || got.HardwareAddrs[0] != "62:bc:f1:bc:1d:8d" || !got.FirstSeen.Equal(base) || !got.DHCPLastSeen.Equal(base) || got.Events != 31 || got.VisibleEvents != 0 {
		t.Fatalf("iPhone = %+v", got)
	}
	got = byAddress["192.168.10.64"]
	if got.HostName != "Watch" || len(got.HardwareAddrs) != 1 || got.Events != 1 || !got.DHCPLastSeen.Equal(base.Add(17*time.Second)) {
		t.Fatalf("Watch = %+v", got)
	}
	presence := LabPresence{Schema: LabPresenceSchema, GeneratedAt: base.Add(4 * time.Minute), Prefix: prefix.String(), Since: base.Add(-26 * time.Minute), Hosts: merged}
	if err := presence.Validate(); err != nil {
		t.Fatal(err)
	}
	presence.Hosts[0].VisibleEvents = 1
	if presence.Validate() == nil {
		t.Fatal("visible events without a time were accepted")
	}
}

func TestLabPresencePrefixBounds(t *testing.T) {
	for _, value := range []string{"192.168.10.0/24", "10.0.0.0/8", "192.168.10.0/30"} {
		if _, err := ParseLabPresencePrefix(value); err != nil {
			t.Errorf("%s: %v", value, err)
		}
	}
	for _, value := range []string{"192.168.10.5/24", "0.0.0.0/0", "192.168.10.0/31", "fd00::/64", "x"} {
		if _, err := ParseLabPresencePrefix(value); err == nil {
			t.Errorf("%s was accepted", value)
		}
	}
}
