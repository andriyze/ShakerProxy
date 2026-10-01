package server

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/inventory"
)

func TestInventorySyncAddsIPv6NeighborEvidence(t *testing.T) {
	directory := t.TempDir()
	socketPath := filepath.Join(directory, "gateway.sock")
	server, _ := configuredAPIServer(t, socketPath)
	server.inventory = &inventory.Store{Path: filepath.Join(directory, "inventory.json")}
	server.keaLeasePath = filepath.Join(directory, "kea-leases4.csv")
	expiry := time.Now().Add(10 * time.Minute).Unix()
	contents := fmt.Sprintf("address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id\n10.77.0.114,52:54:00:ab:cd:04,01:52:54:00:ab:cd:04,600,%d,1,0,0,phone.local,0,,0\n", expiry)
	if err := os.WriteFile(server.keaLeasePath, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	observedAt := time.Now().UTC().Truncate(time.Second)
	table := gatewayprotocol.NeighborTable{
		Schema: gatewayprotocol.NeighborTableSchema, Active: true, Interface: "enp2s0", ScopePlanHash: activationTestPlanHash,
		LabPrefix: "fd12:3456:789a:1::/64", ObservedAt: observedAt,
		Neighbors: []gatewayprotocol.Neighbor{{Address: "fd12:3456:789a:1:5054:ff:feab:cd04", HardwareAddress: "52:54:00:ab:cd:04", State: "REACHABLE", LastConfirmedAt: observedAt.Add(-2 * time.Second)}},
	}
	requests := startGatewaySequenceStub(t, socketPath, gatewayprotocol.Status{LabInterface: "enp2s0", LabScopePlanHash: activationTestPlanHash}, table)
	snapshot, err := server.refreshInventory()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Devices) != 1 {
		t.Fatalf("NDP evidence split the device: %#v", snapshot.Devices)
	}
	found := false
	for _, address := range snapshot.Devices[0].Addresses {
		if address.Family == "IPv6" {
			found = address.Address == "fd12:3456:789a:1:5054:ff:feab:cd04" && address.Source == inventory.SourceNDP && address.Interface == "enp2s0" && address.ScopePlanSHA256 == activationTestPlanHash && address.Active
		}
	}
	if !found {
		t.Fatalf("SLAAC address was not attributed to the device: %#v", snapshot.Devices[0].Addresses)
	}
	methods := []string{}
	for request := range requests {
		methods = append(methods, request.Method)
	}
	if len(methods) != 2 || methods[0] != "GetManagedState" || methods[1] != "GetNeighbors" {
		t.Fatalf("unexpected gateway calls: %v", methods)
	}
}

func TestInventorySyncRejectsInvalidNeighborEvidenceAndToleratesAnAbsentGateway(t *testing.T) {
	directory := t.TempDir()
	socketPath := filepath.Join(directory, "gateway.sock")
	server, _ := configuredAPIServer(t, socketPath)
	server.inventory = &inventory.Store{Path: filepath.Join(directory, "inventory.json")}
	bad := gatewayprotocol.NeighborTable{
		Schema: gatewayprotocol.NeighborTableSchema, Active: true, Interface: "enp2s0", ScopePlanHash: activationTestPlanHash,
		LabPrefix: "fd12:3456:789a:1::/64", ObservedAt: time.Now().UTC(),
		Neighbors: []gatewayprotocol.Neighbor{{Address: "2a01:4f8::1", HardwareAddress: "52:54:00:ab:cd:05", State: "REACHABLE", LastConfirmedAt: time.Now().UTC().Add(-time.Second)}},
	}
	startGatewaySequenceStub(t, socketPath, bad)
	if _, err := server.withNeighborEvidence(server.inventory.Snapshot()); err == nil {
		t.Fatal("neighbor evidence outside the lab prefix was accepted")
	}
	absent, _ := configuredAPIServer(t, filepath.Join(directory, "absent.sock"))
	absent.inventory = &inventory.Store{Path: filepath.Join(directory, "absent-inventory.json")}
	if _, err := absent.withNeighborEvidence(absent.inventory.Snapshot()); err != nil {
		t.Fatalf("an unreachable gateway must not fail inventory refresh: %v", err)
	}
}

// Regression from a routed single-arm EC2 lab: the client never leases from
// ShakerProxy, so without ARP evidence it never appeared as a device.
func TestInventorySyncAddsIPv4ARPEvidenceForClientsWithoutLeases(t *testing.T) {
	directory := t.TempDir()
	socketPath := filepath.Join(directory, "gateway.sock")
	server, _ := configuredAPIServer(t, socketPath)
	server.inventory = &inventory.Store{Path: filepath.Join(directory, "inventory.json")}
	// Single-arm: Kea runs no pool, so the lease file has no leases.
	server.keaLeasePath = filepath.Join(directory, "kea-leases4.csv")
	if err := os.WriteFile(server.keaLeasePath, []byte("address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	observedAt := time.Now().UTC().Truncate(time.Second)
	inactive := gatewayprotocol.NeighborTable{Schema: gatewayprotocol.NeighborTableSchema, ObservedAt: observedAt, Neighbors: []gatewayprotocol.Neighbor{}}
	arp := gatewayprotocol.NeighborTable{
		Schema: gatewayprotocol.NeighborTableSchema, Family: gatewayprotocol.NeighborFamilyIPv4, Active: true, Interface: "ens5", ScopePlanHash: activationTestPlanHash,
		LabPrefix: "172.31.32.0/20", ObservedAt: observedAt,
		Neighbors: []gatewayprotocol.Neighbor{{Address: "172.31.47.197", HardwareAddress: "0e:5e:2b:1c:44:01", State: "REACHABLE", LastConfirmedAt: observedAt.Add(-time.Second)}},
	}
	// Without leases the refresh asks only for the neighbor tables.
	requests := startGatewaySequenceStub(t, socketPath, inactive, arp)
	snapshot, err := server.refreshInventory()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Devices) != 1 || !snapshot.Devices[0].Online {
		t.Fatalf("the ARP-only client did not appear as an online device: %#v", snapshot.Devices)
	}
	address := snapshot.Devices[0].Addresses[0]
	if address.Address != "172.31.47.197" || address.Source != inventory.SourceARP || address.Family != "IPv4" || address.Interface != "ens5" {
		t.Fatalf("unexpected ARP evidence: %#v", address)
	}
	methods := []string{}
	for request := range requests {
		methods = append(methods, request.Method)
	}
	if len(methods) != 2 || methods[0] != "GetNeighbors" || methods[1] != "GetIPv4Neighbors" {
		t.Fatalf("unexpected gateway calls: %v", methods)
	}
}

func TestInventorySyncFindsDevicesWhenTheLeaseFileIsUnreadable(t *testing.T) {
	directory := t.TempDir()
	socketPath := filepath.Join(directory, "gateway.sock")
	server, _ := configuredAPIServer(t, socketPath)
	server.inventory = &inventory.Store{Path: filepath.Join(directory, "inventory.json")}
	server.keaLeasePath = filepath.Join(directory, "kea-leases4.csv")
	// Kea 3 on Ubuntu 26.04 owns /var/lib/kea as _kea 0750; without
	// ShakerProxy DHCP the control API cannot read the lease file.
	previous := readKeaDHCP4Leases
	readKeaDHCP4Leases = func(string) ([]inventory.DHCP4Lease, error) {
		return nil, &fs.PathError{Op: "lstat", Path: server.keaLeasePath, Err: fs.ErrPermission}
	}
	t.Cleanup(func() { readKeaDHCP4Leases = previous })
	observedAt := time.Now().UTC().Truncate(time.Second)
	inactive := gatewayprotocol.NeighborTable{Schema: gatewayprotocol.NeighborTableSchema, ObservedAt: observedAt, Neighbors: []gatewayprotocol.Neighbor{}}
	arp := gatewayprotocol.NeighborTable{
		Schema: gatewayprotocol.NeighborTableSchema, Family: gatewayprotocol.NeighborFamilyIPv4, Active: true, Interface: "ens18", ScopePlanHash: activationTestPlanHash,
		LabPrefix: "192.168.10.0/24", ObservedAt: observedAt,
		Neighbors: []gatewayprotocol.Neighbor{{Address: "192.168.10.201", HardwareAddress: "8a:23:46:10:cf:33", State: "REACHABLE", LastConfirmedAt: observedAt.Add(-time.Second)}},
	}
	startGatewaySequenceStub(t, socketPath, inactive, arp)
	snapshot, err := server.refreshInventory()
	if err != nil {
		t.Fatalf("an unreadable lease file must not stop device discovery: %v", err)
	}
	if len(snapshot.Devices) != 1 || snapshot.Devices[0].Addresses[0].Address != "192.168.10.201" {
		t.Fatalf("the phone seen in the ARP table did not appear: %#v", snapshot.Devices)
	}
}
