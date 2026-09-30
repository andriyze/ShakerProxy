package gatewayprotocol

import (
	"strings"
	"testing"
	"time"
)

func validNeighborTable() NeighborTable {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	return NeighborTable{
		Schema: NeighborTableSchema, Active: true, Interface: "enp2s0", ScopePlanHash: strings.Repeat("a", 64),
		LabPrefix: "fd12:3456:789a:1::/64", ObservedAt: now,
		Neighbors: []Neighbor{
			{Address: "fd12:3456:789a:1::50", HardwareAddress: "52:54:00:00:00:50", State: "REACHABLE", LastConfirmedAt: now},
			{Address: "fe80::50", HardwareAddress: "52:54:00:00:00:50", State: "STALE", LastConfirmedAt: now.Add(-time.Hour)},
		},
	}
}

func TestNeighborTableValidation(t *testing.T) {
	if err := validNeighborTable().Validate(); err != nil {
		t.Fatal(err)
	}
	inactive := NeighborTable{Schema: NeighborTableSchema, ObservedAt: time.Now(), Neighbors: []Neighbor{}}
	if err := inactive.Validate(); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*NeighborTable){
		"schema":            func(table *NeighborTable) { table.Schema = 2 },
		"inactive evidence": func(table *NeighborTable) { table.Active = false },
		"prefix size":       func(table *NeighborTable) { table.LabPrefix = "fd12:3456::/48" },
		"interface":         func(table *NeighborTable) { table.Interface = "eth0;reboot" },
		"plan hash":         func(table *NeighborTable) { table.ScopePlanHash = "short" },
		"outside prefix":    func(table *NeighborTable) { table.Neighbors[0].Address = "fd99::50" },
		"non-canonical":     func(table *NeighborTable) { table.Neighbors[0].Address = "FD12:3456:789A:1::50" },
		"IPv4":              func(table *NeighborTable) { table.Neighbors[0].Address = "10.77.0.5" },
		"multicast MAC":     func(table *NeighborTable) { table.Neighbors[0].HardwareAddress = "01:00:5e:00:00:01" },
		"state":             func(table *NeighborTable) { table.Neighbors[0].State = "FAILED" },
		"future":            func(table *NeighborTable) { table.Neighbors[0].LastConfirmedAt = table.ObservedAt.Add(time.Second) },
		"vlan":              func(table *NeighborTable) { vlan := 4095; table.VLANID = &vlan },
	}
	for name, edit := range cases {
		table := validNeighborTable()
		edit(&table)
		if err := table.Validate(); err == nil {
			t.Fatalf("%s: invalid neighbor table was accepted", name)
		}
	}
}

func TestIPv4NeighborTableValidation(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	table := NeighborTable{
		Schema: NeighborTableSchema, Family: NeighborFamilyIPv4, Active: true, Interface: "ens5",
		ScopePlanHash: "dca4fbd4930bf43d72b641a33622333c175dd51802db80d638d871ddd63902a6", LabPrefix: "172.31.32.0/20", ObservedAt: now,
		Neighbors: []Neighbor{{Address: "172.31.47.197", HardwareAddress: "0e:00:00:00:00:01", State: "REACHABLE", LastConfirmedAt: now}},
	}
	if err := table.Validate(); err != nil {
		t.Fatalf("valid IPv4 table was rejected: %v", err)
	}
	outside := table
	outside.Neighbors = []Neighbor{{Address: "10.0.0.9", HardwareAddress: "0e:00:00:00:00:01", State: "REACHABLE", LastConfirmedAt: now}}
	ipv6InIPv4 := table
	ipv6InIPv4.Neighbors = []Neighbor{{Address: "fe80::1", HardwareAddress: "0e:00:00:00:00:01", State: "REACHABLE", LastConfirmedAt: now}}
	unknownFamily := table
	unknownFamily.Family = "ipv5"
	wrongPrefix := table
	wrongPrefix.LabPrefix = "fd12:3456:789a:1::/64"
	for name, invalid := range map[string]NeighborTable{"outside": outside, "IPv6 address": ipv6InIPv4, "family": unknownFamily, "prefix": wrongPrefix} {
		if err := invalid.Validate(); err == nil {
			t.Fatalf("%s: invalid IPv4 table was accepted", name)
		}
	}
}
