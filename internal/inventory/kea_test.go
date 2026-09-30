package inventory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const keaHeader = "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id\n"

func TestParseKeaDHCP4LeasesNormalizesBoundedEvidence(t *testing.T) {
	leases, err := ParseKeaDHCP4Leases([]byte(keaHeader + "10.77.0.111,52:54:00:AB:CD:01,01:52:54:00:ab:cd:01,600,2000000000,1,0,0,Camera.Local.,0,,0\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 1 || leases[0].Address.String() != "10.77.0.111" || leases[0].HardwareAddr != "52:54:00:ab:cd:01" || leases[0].Hostname != "camera.local" {
		t.Fatalf("unexpected lease: %#v", leases)
	}
}

func TestParseKeaDHCP4LeasesRejectsMissingIdentityAndOversizedField(t *testing.T) {
	if _, err := ParseKeaDHCP4Leases([]byte(keaHeader + "10.77.0.111,,,600,2000000000,1,0,0,camera,0,,0\n")); err == nil {
		t.Fatal("identity-free lease was accepted")
	}
	line := "10.77.0.111,52:54:00:ab:cd:01,01,600,2000000000,1,0,0," + strings.Repeat("x", MaxLeaseField+1) + ",0,,0\n"
	if _, err := ParseKeaDHCP4Leases([]byte(keaHeader + line)); err == nil {
		t.Fatal("oversized lease field was accepted")
	}
	malformedClient := "10.77.0.111,,not-a-hex-client,600,2000000000,1,0,0,camera,0,,0\n"
	if _, err := ParseKeaDHCP4Leases([]byte(keaHeader + malformedClient)); err == nil {
		t.Fatal("malformed client identity was accepted")
	}
}

func TestReadKeaDHCP4LeasesRejectsSymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "leases.csv")
	if err := os.WriteFile(target, []byte(keaHeader), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link.csv")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadKeaDHCP4Leases(link); err == nil {
		t.Fatal("symlinked lease source was accepted")
	}
}

func TestParseKeaDHCP4LeasesToleratesDeclinedAndLongLeases(t *testing.T) {
	active := "10.77.0.23,02:00:00:00:00:02,01:02:00:00:00:00:02,4000,1790004000,1,0,0,cam,0,,0\n"
	declined := "10.77.0.24,,,86400,1790086400,1,0,0,,1,,0\n"
	monthLong := "10.77.0.25,02:00:00:00:00:03,,2592000,1792592000,1,0,0,tv,0,,0\n"
	infinite := "10.77.0.26,02:00:00:00:00:04,,4294967295,6084967295,1,0,0,printer,0,,0\n"
	leases, err := ParseKeaDHCP4Leases([]byte(keaHeader + active + declined + monthLong + infinite))
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 3 || leases[0].Address.String() != "10.77.0.23" || leases[1].Address.String() != "10.77.0.25" || leases[2].Address.String() != "10.77.0.26" {
		t.Fatalf("unexpected leases: %#v", leases)
	}
	if leases[1].ExpiresAt.Sub(leases[1].ExpiresAt.Add(-leases[1].ValidLifetime)).Hours() != 720 {
		t.Fatalf("long lease window was not preserved: %#v", leases[1])
	}
	store := &Store{Path: filepath.Join(t.TempDir(), "inventory.json"), Now: func() time.Time { return time.Unix(1790000500, 0).UTC() }}
	snapshot, err := store.ReconcileDHCP4(leases)
	if err != nil || len(snapshot.Devices) != 3 {
		t.Fatalf("long-lived leases were not reconciled: %#v err=%v", snapshot, err)
	}
}
