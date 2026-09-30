package main

import (
	"flag"
	"fmt"
	"net/netip"
	"os"
	"time"

	"shakerproxy.dev/shakerproxy/internal/inventory"
)

func main() {
	path := flag.String("path", "", "inventory document path")
	flag.Parse()
	if *path == "" {
		fmt.Fprintln(os.Stderr, "inventory path is required")
		os.Exit(2)
	}
	clock := time.Now().UTC()
	store := &inventory.Store{Path: *path, Now: func() time.Time { return clock }}
	snapshot, err := store.ReconcileDHCP4([]inventory.DHCP4Lease{{
		Address:       netip.MustParseAddr("10.77.0.210"),
		HardwareAddr:  "52:54:00:ab:cd:10",
		Hostname:      "bench-camera",
		ValidLifetime: 25 * time.Hour,
		ExpiresAt:     clock.Add(24 * time.Hour),
	}})
	if err != nil || len(snapshot.Devices) != 1 {
		fail("seed device inventory", err)
	}
	deviceID := snapshot.Devices[0].ID
	clock = clock.Add(time.Nanosecond)
	if _, err := store.UpdateAlias(deviceID, "smoke-admin", "alias-smoke-old-0001", inventory.AliasUpdate{FriendlyName: "Bench Camera", Reason: "Historical alias smoke fixture", ExpectedRevision: 0}); err != nil {
		fail("assign historical alias", err)
	}
	clock = clock.Add(time.Nanosecond)
	if _, err := store.UpdateAlias(deviceID, "smoke-admin", "alias-smoke-new-0002", inventory.AliasUpdate{FriendlyName: "North Camera", Reason: "Current alias smoke fixture", ExpectedRevision: 1}); err != nil {
		fail("assign current alias", err)
	}
	clock = clock.Add(time.Nanosecond)
	if _, err := store.UpdateMetadata(deviceID, "smoke-admin", "metadata-smoke-tags-0003", inventory.DeviceMetadata{FriendlyName: "North Camera", Tags: []string{"Camera", "Lab Gear"}}); err != nil {
		fail("assign current tags", err)
	}
	fmt.Println(deviceID)
}

func fail(action string, err error) {
	if err == nil {
		err = fmt.Errorf("unexpected fixture cardinality")
	}
	fmt.Fprintf(os.Stderr, "%s: %v\n", action, err)
	os.Exit(1)
}
