package inventory

import (
	"net/netip"
	"testing"
	"time"
)

// recordSeparately stores one device per MAC at the same static address, the
// way versions before MAC-rotation handling recorded a phone.
func recordSeparately(t *testing.T, store *Store, address string, macs []string, base time.Time) {
	t.Helper()
	for index, mac := range macs {
		// A distinct placeholder address keeps the records apart while they
		// are created; the stored address is then rewritten to the real one.
		placeholder := netip.AddrFrom4([4]byte{192, 0, 2, byte(10 + index)}).String()
		if _, err := store.ReconcileNeighbors([]NeighborObservation{neighborObservation(placeholder, mac, base.Add(time.Duration(index)*time.Minute))}); err != nil {
			t.Fatal(err)
		}
	}
	doc, err := store.load()
	if err != nil {
		t.Fatal(err)
	}
	for deviceIndex := range doc.Devices {
		for addressIndex := range doc.Devices[deviceIndex].Addresses {
			doc.Devices[deviceIndex].Addresses[addressIndex].Address = address
		}
	}
	if err := store.save(doc); err != nil {
		t.Fatal(err)
	}
}

func TestReconcileNeighborsFoldsEarlierRecordsOfARotatingPhone(t *testing.T) {
	now := time.Date(2026, 10, 1, 20, 0, 0, 0, time.UTC)
	store := deterministicMutationStore(t, now)
	recordSeparately(t, store, "192.168.10.201", []string{"8a:23:46:10:cf:33", "ae:f9:0a:ef:51:8c", "ee:a0:da:04:5c:eb", "e2:4f:7b:ef:5c:30"}, now.Add(-time.Hour))
	before, err := store.Snapshot()
	if err != nil || len(before.Devices) != 4 {
		t.Fatalf("fixture should hold four records: %d err=%v", len(before.Devices), err)
	}
	formerIDs := map[string]bool{}
	for _, device := range before.Devices {
		formerIDs[device.ID] = true
	}
	snapshot, err := store.ReconcileNeighbors([]NeighborObservation{neighborObservation("192.168.10.201", "72:58:49:e8:e4:00", now.Add(-time.Minute))})
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Devices) != 1 {
		t.Fatalf("the phone is still %d devices: %+v", len(snapshot.Devices), snapshot.Devices)
	}
	phone := snapshot.Devices[0]
	if macs := len(phone.Identities); macs != 5 {
		t.Fatalf("the phone should keep all five MACs, has %d", macs)
	}
	if !phone.Online {
		t.Fatal("the phone is not online after its current MAC was seen")
	}
	survivorIsFormer := formerIDs[phone.ID]
	delete(formerIDs, phone.ID)
	if len(phone.FormerIDs) != len(formerIDs) {
		t.Fatalf("former IDs = %v, want the %d absorbed records (survivor was a former record: %v)", phone.FormerIDs, len(formerIDs), survivorIsFormer)
	}
	for _, id := range phone.FormerIDs {
		if !formerIDs[id] {
			t.Fatalf("unexpected former ID %s", id)
		}
	}
	audit, err := store.AuditLog(50)
	if err != nil {
		t.Fatal(err)
	}
	merges := 0
	for _, event := range audit {
		if event.Action == AuditDevicesMerged && event.Actor == macRotationActor {
			merges++
		}
	}
	if merges != len(formerIDs) {
		t.Fatalf("audited %d automatic merges, want %d", merges, len(formerIDs))
	}
}

func TestReconcileNeighborsKeepsDHCPDevicesApartAtAReusedAddress(t *testing.T) {
	now := time.Date(2026, 10, 1, 20, 0, 0, 0, time.UTC)
	store := deterministicMutationStore(t, now)
	// A lab DHCP server handed 10.77.0.50 to one phone, then to another.
	for index, mac := range []string{"8a:23:46:10:cf:33", "ae:f9:0a:ef:51:8c"} {
		lease := DHCP4Lease{Address: netip.MustParseAddr("10.77.0.50"), HardwareAddr: mac, ValidLifetime: time.Hour, ExpiresAt: now.Add(time.Duration(index-2) * time.Hour)}
		if _, err := store.ReconcileDHCP4([]DHCP4Lease{lease}); err != nil {
			t.Fatal(err)
		}
	}
	snapshot, err := store.ReconcileNeighbors([]NeighborObservation{neighborObservation("10.77.0.50", "ae:f9:0a:ef:51:8c", now)})
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Devices) != 2 {
		t.Fatalf("two DHCP clients at a reused address were merged: %+v", snapshot.Devices)
	}
}

func TestAPhoneThatRotatesPastTheIdentityLimitKeepsItsNewestMACs(t *testing.T) {
	now := time.Date(2026, 10, 1, 20, 0, 0, 0, time.UTC)
	store := deterministicMutationStore(t, now)
	total := MaxIdentities + 5
	var newest string
	for index := 0; index < total; index++ {
		mac := "aa:00:00:00:00:" + hexByte(index)
		newest = mac
		if _, err := store.ReconcileNeighbors([]NeighborObservation{neighborObservation("192.168.10.201", mac, now.Add(time.Duration(index-total)*time.Minute))}); err != nil {
			t.Fatalf("rotation %d: %v", index, err)
		}
	}
	snapshot, err := store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Devices) != 1 {
		t.Fatalf("rotations created %d devices", len(snapshot.Devices))
	}
	identities := snapshot.Devices[0].Identities
	if len(identities) != MaxIdentities {
		t.Fatalf("identities = %d, want the limit %d", len(identities), MaxIdentities)
	}
	found := false
	for _, identity := range identities {
		if identity.Value == "aa:00:00:00:00:00" {
			t.Fatal("the oldest MAC was kept instead of a newer one")
		}
		found = found || identity.Value == newest
	}
	if !found {
		t.Fatalf("the newest MAC %s is missing", newest)
	}
}

func hexByte(value int) string {
	const digits = "0123456789abcdef"
	return string([]byte{digits[value>>4&0xf], digits[value&0xf]})
}
