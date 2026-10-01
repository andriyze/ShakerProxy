package inventory

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDeviceJSONWritesEmptyListsNotNull(t *testing.T) {
	// A device seen only in the ARP table has no hostname; the web UI reads
	// device.hostnames as a list.
	encoded, err := json.Marshal(Device{ID: "dev_arp_only"})
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"identities":[]`, `"addresses":[]`, `"hostnames":[]`} {
		if !strings.Contains(string(encoded), field) {
			t.Fatalf("device JSON lacks %s: %s", field, encoded)
		}
	}
	var decoded Device
	if err := json.Unmarshal(encoded, &decoded); err != nil || decoded.ID != "dev_arp_only" {
		t.Fatalf("device JSON did not round-trip: %+v %v", decoded, err)
	}
}
