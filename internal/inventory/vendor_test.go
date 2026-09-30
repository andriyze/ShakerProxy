package inventory

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestVendorRegistryUsesLongestIEEEPrefixAndClassifiesLocalAddresses(t *testing.T) {
	directory := t.TempDir()
	writeVendorFixtures(t, directory,
		"MA-L,001122,Large Vendor,Address\n",
		"MA-M,0011223,Medium Vendor,Address\n",
		"MA-S,001122334,Small Vendor,Address\n",
	)
	registry := &VendorRegistry{Directory: directory}
	for _, test := range []struct {
		mac, state, name, assignment string
	}{
		{"00:11:22:33:44:55", string(VendorStateMatched), "Small Vendor", "001122334"},
		{"00:11:22:3f:44:55", string(VendorStateMatched), "Medium Vendor", "0011223"},
		{"00:11:22:af:44:55", string(VendorStateMatched), "Large Vendor", "001122"},
		{"00:aa:bb:cc:dd:ee", string(VendorStateNoMatch), "", ""},
		{"02:11:22:33:44:55", string(VendorStateLocallyAdministered), "", ""},
	} {
		lookup, err := registry.LookupMAC(test.mac)
		if err != nil || string(lookup.State) != test.state || lookup.Name != test.name || lookup.Assignment != test.assignment {
			t.Fatalf("lookup %s = %#v err=%v", test.mac, lookup, err)
		}
		if lookup.State == VendorStateMatched && len(lookup.DatabaseSHA256) != 64 {
			t.Fatalf("lookup %s did not retain registry provenance: %#v", test.mac, lookup)
		}
	}
	local, err := (&VendorRegistry{Directory: "/does/not/exist"}).LookupMAC("02:00:00:00:00:01")
	if err != nil || local.State != VendorStateLocallyAdministered {
		t.Fatalf("local address unnecessarily required a registry: %#v err=%v", local, err)
	}
}

func TestVendorRegistryMarksConflictingAssignmentsAmbiguous(t *testing.T) {
	directory := t.TempDir()
	writeVendorFixtures(t, directory,
		"MA-L,001122,Large Vendor,Address\n",
		"MA-M,0011223,Medium Vendor,Address\n",
		"MA-S,001122334,First Vendor,Address\nMA-S,001122334,Second Vendor,Address\n",
	)
	lookup, err := (&VendorRegistry{Directory: directory}).LookupMAC("00:11:22:33:44:55")
	if err != nil || lookup.State != VendorStateAmbiguous || lookup.Name != "" {
		t.Fatalf("conflicting assignment was guessed: %#v err=%v", lookup, err)
	}
}

func TestVendorRegistryRefreshRejectsCorruptOrSymlinkedCache(t *testing.T) {
	directory := t.TempDir()
	writeVendorFixtures(t, directory,
		"MA-L,001122,Large Vendor,Address\n",
		"MA-M,0011223,Medium Vendor,Address\n",
		"MA-S,001122334,Small Vendor,Address\n",
	)
	clock := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	registry := &VendorRegistry{Directory: directory, RefreshInterval: time.Minute, Now: func() time.Time { return clock }}
	if _, err := registry.LookupMAC("00:11:22:33:44:55"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "oui36.csv"), []byte("bad\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(2 * time.Minute)
	if _, err := registry.LookupMAC("00:11:22:33:44:55"); err == nil {
		t.Fatal("corrupt refreshed registry was accepted")
	}

	other := t.TempDir()
	writeVendorFixtures(t, other,
		"MA-L,001122,Large Vendor,Address\n",
		"MA-M,0011223,Medium Vendor,Address\n",
		"MA-S,001122334,Small Vendor,Address\n",
	)
	realPath := filepath.Join(other, "oui36.csv")
	if err := os.Remove(filepath.Join(other, "oui36.csv")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(directory, "oui36.csv"), realPath); err != nil {
		t.Fatal(err)
	}
	if _, err := (&VendorRegistry{Directory: other}).LookupMAC("00:11:22:33:44:55"); err == nil {
		t.Fatal("symlinked registry was accepted")
	}
}

func TestReconcilePersistsVendorProvenance(t *testing.T) {
	directory := t.TempDir()
	writeVendorFixtures(t, directory,
		"MA-L,001122,Large Vendor,Address\n",
		"MA-M,0011223,Medium Vendor,Address\n",
		"MA-S,001122334,Small Vendor,Address\n",
	)
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	store := deterministicMutationStore(t, now)
	store.Vendors = &VendorRegistry{Directory: directory, Now: func() time.Time { return now }}
	snapshot, err := store.ReconcileDHCP4([]DHCP4Lease{{Address: netip.MustParseAddr("10.77.0.111"), HardwareAddr: "00:11:22:33:44:55", ClientID: "01:01", ValidLifetime: time.Hour, ExpiresAt: now.Add(time.Hour)}})
	if err != nil || len(snapshot.Devices) != 1 || snapshot.Devices[0].VendorState != VendorStateMatched || snapshot.Devices[0].Vendor == nil || snapshot.Devices[0].Vendor.Name != "Small Vendor" || snapshot.Devices[0].Vendor.ObservedAt != now {
		t.Fatalf("vendor evidence was not reconciled: %#v err=%v", snapshot, err)
	}
	persisted, err := store.Snapshot()
	if err != nil || persisted.Devices[0].Vendor == nil || persisted.Devices[0].Vendor.DatabaseSHA256 == "" {
		t.Fatalf("vendor provenance was not persisted: %#v err=%v", persisted, err)
	}
}

func TestVendorRegistryUbuntuCacheIntegration(t *testing.T) {
	directory := os.Getenv("SHAKERPROXY_IEEE_TEST_DIR")
	if directory == "" {
		t.Skip("SHAKERPROXY_IEEE_TEST_DIR is not set")
	}
	entries, err := loadVendorRegistry(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 10000 {
		t.Fatalf("Ubuntu IEEE cache was unexpectedly small: %d assignments", len(entries))
	}
}

func writeVendorFixtures(t *testing.T, directory, large, medium, small string) {
	t.Helper()
	header := "Registry,Assignment,Organization Name,Organization Address\n"
	for name, rows := range map[string]string{"oui.csv": large, "mam.csv": medium, "oui36.csv": small} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(header+rows), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
