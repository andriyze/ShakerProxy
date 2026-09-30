package inventory

import (
	"errors"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAddressAliasMutationsAreScopedAuditedAndIdempotent(t *testing.T) {
	now := time.Date(2026, 9, 1, 14, 0, 0, 0, time.UTC)
	store := &Store{Path: filepath.Join(t.TempDir(), "inventory.json"), Now: func() time.Time { return now }}
	vlan := 20
	input := AddressAliasInput{Name: "  Bench subnet  ", Prefix: "2001:db8:20::1234/64", Interface: " enp2s0.20 ", VLANID: &vlan, ValidFrom: now.Add(-time.Hour), Priority: 50, Confidence: 70, Reason: "  No stable client identity  "}
	created, err := store.CreateAddressAlias("admin", "address-alias-op-0001", input)
	if err != nil || created.Replayed || created.Alias.Revision != 1 || created.Alias.Name != "Bench subnet" || created.Alias.Prefix != "2001:db8:20::/64" || created.Alias.Interface != "enp2s0.20" || created.Audit.Action != AuditAddressAliasCreated {
		t.Fatalf("unexpected address alias creation: %#v err=%v", created, err)
	}
	replay, err := store.CreateAddressAlias("admin", "address-alias-op-0001", input)
	if err != nil || !replay.Replayed || replay.Alias.ID != created.Alias.ID {
		t.Fatalf("address alias replay was not stable: %#v err=%v", replay, err)
	}
	conflicting := input
	conflicting.Name = "Different"
	if _, err := store.CreateAddressAlias("admin", "address-alias-op-0001", conflicting); !errors.Is(err, ErrOperationConflict) {
		t.Fatalf("conflicting address alias replay was accepted: %v", err)
	}
	validUntil := now.Add(2 * time.Hour)
	update := AddressAliasUpdate{AddressAliasInput: input, ExpectedRevision: 1}
	update.Name, update.Prefix, update.ValidUntil = "Bench console", "2001:db8:20::44", &validUntil
	updated, err := store.UpdateAddressAlias(created.Alias.ID, "admin", "address-alias-op-0002", update)
	if err != nil || updated.Alias.Revision != 2 || updated.Alias.Prefix != "2001:db8:20::44/128" || updated.Alias.ValidUntil == nil || updated.Audit.Action != AuditAddressAliasUpdated {
		t.Fatalf("unexpected address alias update: %#v err=%v", updated, err)
	}
	if _, err := store.UpdateAddressAlias(created.Alias.ID, "admin", "address-alias-op-0003", update); !errors.Is(err, ErrAddressAliasRevisionConflict) {
		t.Fatalf("stale address alias revision was accepted: %v", err)
	}
	snapshot, err := store.Snapshot()
	if err != nil || len(snapshot.AddressAliases) != 1 || snapshot.AddressAliases[0].ID != created.Alias.ID {
		t.Fatalf("address alias did not survive persistence: %#v err=%v", snapshot.AddressAliases, err)
	}
}

func TestAddressAliasResolutionPrefersExactVLANScopeAndFailsClosedOnTie(t *testing.T) {
	now := time.Date(2026, 9, 1, 15, 0, 0, 0, time.UTC)
	store := &Store{Path: filepath.Join(t.TempDir(), "inventory.json"), Now: func() time.Time { return now }}
	base := AddressAliasInput{Name: "Broad lab", Prefix: "10.77.0.0/24", Interface: "enp2s0", ValidFrom: now.Add(-time.Hour), Priority: 10, Confidence: 60, Reason: "Manual lab range"}
	if _, err := store.CreateAddressAlias("admin", "address-alias-resolve-01", base); err != nil {
		t.Fatal(err)
	}
	vlan := 20
	exact := base
	exact.Name, exact.Prefix, exact.VLANID, exact.Priority, exact.Confidence = "Bench camera", "10.77.0.44", &vlan, 20, 90
	if _, err := store.CreateAddressAlias("admin", "address-alias-resolve-02", exact); err != nil {
		t.Fatal(err)
	}
	resolved, err := store.ResolveAddressAlias(netip.MustParseAddr("10.77.0.44"), "enp2s0", &vlan, now)
	if err != nil || !resolved.Matched || resolved.Conflict || resolved.Alias == nil || resolved.Alias.Name != "Bench camera" || len(resolved.Candidates) != 2 {
		t.Fatalf("scoped address alias did not win: %#v err=%v", resolved, err)
	}
	tied := exact
	tied.Name = "Conflicting fixture"
	if _, err := store.CreateAddressAlias("admin", "address-alias-resolve-03", tied); err != nil {
		t.Fatal(err)
	}
	resolved, err = store.ResolveAddressAlias(netip.MustParseAddr("10.77.0.44"), "enp2s0", &vlan, now)
	if err != nil || !resolved.Matched || !resolved.Conflict || resolved.Alias != nil || len(resolved.Candidates) != 3 {
		t.Fatalf("equal-rank disagreement did not fail closed: %#v err=%v", resolved, err)
	}
	otherVLAN := 30
	resolved, err = store.ResolveAddressAlias(netip.MustParseAddr("10.77.0.44"), "enp2s0", &otherVLAN, now)
	if err != nil || resolved.Conflict || resolved.Alias == nil || resolved.Alias.Name != "Broad lab" {
		t.Fatalf("VLAN-scoped alias leaked to another VLAN: %#v err=%v", resolved, err)
	}
}

func TestAddressAliasValidationAndObservedAttributionConflict(t *testing.T) {
	now := time.Date(2026, 9, 1, 16, 0, 0, 0, time.UTC)
	store := &Store{Path: filepath.Join(t.TempDir(), "inventory.json"), Now: func() time.Time { return now }}
	if _, err := store.ReconcileDHCP4([]DHCP4Lease{{Address: netip.MustParseAddr("10.77.0.44"), HardwareAddr: "52:54:00:00:00:44", ValidLifetime: time.Hour, ExpiresAt: now.Add(time.Hour)}}); err != nil {
		t.Fatal(err)
	}
	input := AddressAliasInput{Name: "Manual camera", Prefix: "10.77.0.44", Interface: "enp2s0", ValidFrom: now.Add(-time.Hour), Priority: 10, Confidence: 50, Reason: "Temporary manual attribution"}
	created, err := store.CreateAddressAlias("admin", "address-alias-conflict-1", input)
	if err != nil || !created.Alias.Conflict || len(created.Alias.ConflictWarnings) != 1 {
		t.Fatalf("observed identity conflict was hidden: %#v err=%v", created, err)
	}
	invalid := input
	invalid.Prefix = "not-an-address"
	if _, err := store.CreateAddressAlias("admin", "address-alias-invalid-01", invalid); !errors.Is(err, ErrMutationRejected) {
		t.Fatalf("invalid address alias prefix was accepted: %v", err)
	}
	invalid = input
	invalid.Interface = "../../danger"
	if _, err := store.CreateAddressAlias("admin", "address-alias-invalid-02", invalid); !errors.Is(err, ErrMutationRejected) {
		t.Fatalf("invalid address alias interface was accepted: %v", err)
	}
}

func TestAddressAliasObservedConflictHonorsKnownNetworkScope(t *testing.T) {
	now := time.Date(2026, 9, 1, 16, 0, 0, 0, time.UTC)
	store := &Store{Path: filepath.Join(t.TempDir(), "inventory.json"), Now: func() time.Time { return now }}
	vlan := 20
	if _, err := store.ReconcileDHCP4([]DHCP4Lease{{Address: netip.MustParseAddr("10.77.0.44"), HardwareAddr: "52:54:00:00:00:44", ValidLifetime: time.Hour, ExpiresAt: now.Add(time.Hour), Interface: "enp2s0", VLANID: &vlan, ScopePlanSHA256: strings.Repeat("c", 64)}}); err != nil {
		t.Fatal(err)
	}
	differentInterface := AddressAliasInput{Name: "Other interface", Prefix: "10.77.0.44", Interface: "enp3s0", VLANID: &vlan, ValidFrom: now.Add(-time.Hour), Priority: 10, Confidence: 50, Reason: "Separate lab scope"}
	created, err := store.CreateAddressAlias("admin", "address-alias-scope-01", differentInterface)
	if err != nil || created.Alias.Conflict {
		t.Fatalf("known interface scope produced a false conflict: %#v err=%v", created, err)
	}
	matching := differentInterface
	matching.Name, matching.Interface = "Matching scope", "enp2s0"
	created, err = store.CreateAddressAlias("admin", "address-alias-scope-02", matching)
	if err != nil || !created.Alias.Conflict || len(created.Alias.ConflictWarnings) != 1 || !strings.Contains(created.Alias.ConflictWarnings[0], "same interface, VLAN, and time scope") {
		t.Fatalf("matching observed scope conflict was hidden: %#v err=%v", created, err)
	}
	otherVLAN := 30
	matching.Name, matching.VLANID = "Other VLAN", &otherVLAN
	created, err = store.CreateAddressAlias("admin", "address-alias-scope-03", matching)
	if err != nil || created.Alias.Conflict {
		t.Fatalf("known VLAN scope produced a false conflict: %#v err=%v", created, err)
	}
}
