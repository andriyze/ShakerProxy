package inventory

import (
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestNameResolverProjectsCurrentAndCaptureTimeNames(t *testing.T) {
	base := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	clock := base
	store := deterministicMutationStore(t, base)
	store.Now = func() time.Time { return clock }
	snapshot, err := store.ReconcileDHCP4([]DHCP4Lease{{Address: netip.MustParseAddr("10.77.0.110"), HardwareAddr: "52:54:00:00:00:01", ValidLifetime: time.Hour, ExpiresAt: base.Add(time.Hour)}})
	if err != nil {
		t.Fatal(err)
	}
	deviceID := snapshot.Devices[0].ID
	clock = base.Add(time.Minute)
	if _, err := store.UpdateAlias(deviceID, "admin", "device-alias-op-0001", AliasUpdate{FriendlyName: "Bench Camera", Reason: "Matched the chassis label", ExpectedRevision: 0}); err != nil {
		t.Fatal(err)
	}
	clock = base.Add(2 * time.Minute)
	if _, err := store.UpdateAlias(deviceID, "admin", "device-alias-op-0002", AliasUpdate{FriendlyName: "North Camera", Reason: "Moved to the north bench", ExpectedRevision: 1}); err != nil {
		t.Fatal(err)
	}

	resolverClock := base.Add(3 * time.Minute)
	resolver := &NameResolver{Store: store, Now: func() time.Time { return resolverClock }}
	before, found, err := resolver.Resolve(deviceID, base.Add(30*time.Second))
	if err != nil || !found || !before.FriendlyNameAtCaptureKnown || before.FriendlyNameAtCapture != "" || before.CurrentFriendlyName != "North Camera" || before.AliasRevision != 2 {
		t.Fatalf("unexpected pre-alias projection: %#v found=%v err=%v", before, found, err)
	}
	during, found, err := resolver.Resolve(deviceID, base.Add(90*time.Second))
	if err != nil || !found || !during.FriendlyNameAtCaptureKnown || during.FriendlyNameAtCapture != "Bench Camera" {
		t.Fatalf("unexpected historical projection: %#v found=%v err=%v", during, found, err)
	}

	clock = base.Add(4 * time.Minute)
	if _, err := store.UpdateAlias(deviceID, "admin", "device-alias-op-0003", AliasUpdate{FriendlyName: "Loading Dock Camera", Reason: "Installed at the loading dock", ExpectedRevision: 2}); err != nil {
		t.Fatal(err)
	}
	stale, _, err := resolver.Resolve(deviceID, clock)
	if err != nil || stale.CurrentFriendlyName != "North Camera" {
		t.Fatalf("resolver did not retain its bounded cache: %#v err=%v", stale, err)
	}
	resolver.Invalidate()
	current, _, err := resolver.Resolve(deviceID, clock)
	if err != nil || current.CurrentFriendlyName != "Loading Dock Camera" || current.AliasRevision != 3 {
		t.Fatalf("resolver invalidation did not reveal the new alias: %#v err=%v", current, err)
	}
	aliases, err := resolver.ResolveAliases([]string{"north camera", "Loading Dock Camera", "*", "Missing"})
	if err != nil || len(aliases["north camera"]) != 1 || aliases["north camera"][0] != deviceID || len(aliases["Loading Dock Camera"]) != 1 || aliases["Loading Dock Camera"][0] != deviceID || len(aliases["*"]) != 1 || len(aliases["Missing"]) != 0 {
		t.Fatalf("current and historical aliases were not resolved exactly: %#v err=%v", aliases, err)
	}
	clock = base.Add(5 * time.Minute)
	if _, err := store.UpdateMetadata(deviceID, "admin", "device-meta-op-0001", DeviceMetadata{FriendlyName: "Loading Dock Camera", Tags: []string{"Camera", "lab gear"}}); err != nil {
		t.Fatal(err)
	}
	resolver.Invalidate()
	aliases, tags, err := resolver.ResolveSelectors([]string{"North Camera"}, []string{"camera", "missing"})
	if err != nil || len(aliases["North Camera"]) != 1 || aliases["North Camera"][0] != deviceID || len(tags["camera"]) != 1 || tags["camera"][0] != deviceID || len(tags["missing"]) != 0 {
		t.Fatalf("alias and tag selectors did not share one bounded resolution: aliases=%#v tags=%#v err=%v", aliases, tags, err)
	}
	historical, truncated, err := resolver.CompleteQueryValues("device.name", "north", 10)
	if err != nil || truncated || len(historical) != 1 || historical[0].Value != "North Camera" || !historical[0].IncludesHistorical || historical[0].DeviceCount != 1 {
		t.Fatalf("historical alias completion is invalid: %#v truncated=%v err=%v", historical, truncated, err)
	}
	completedTags, truncated, err := resolver.CompleteQueryValues("device.tag", "cam", 10)
	if err != nil || truncated || len(completedTags) != 1 || completedTags[0].Value != "camera" || completedTags[0].IncludesHistorical || completedTags[0].DeviceCount != 1 {
		t.Fatalf("device-tag completion is invalid: %#v truncated=%v err=%v", completedTags, truncated, err)
	}
}

func TestNameResolverRejectsUnboundedAliasOperands(t *testing.T) {
	resolver := &NameResolver{}
	values := make([]string, MaxResolvedAliasValues+1)
	for index := range values {
		values[index] = "name"
	}
	if _, err := resolver.ResolveAliases(values); !errors.Is(err, ErrAliasResolutionLimit) {
		t.Fatalf("unbounded alias operands were accepted: %v", err)
	}
}

func TestNameResolverCompletionIsBoundedBeforeInventoryAccess(t *testing.T) {
	resolver := &NameResolver{}
	if _, _, err := resolver.CompleteQueryValues("policy", "", 10); err == nil {
		t.Fatal("unsupported completion field reached the inventory")
	}
	if _, _, err := resolver.CompleteQueryValues("device.name", "", MaxQueryValueCompletions+1); err == nil {
		t.Fatal("unbounded completion request reached the inventory")
	}
}

func TestNameProjectionMarksLegacyAndTruncatedHistoryUnknown(t *testing.T) {
	at := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	legacy := projectDeviceName(Device{FriendlyName: "Legacy Name"}, at)
	if legacy.FriendlyNameAtCaptureKnown || legacy.CurrentFriendlyName != "Legacy Name" {
		t.Fatalf("legacy projection overstated capture-time certainty: %#v", legacy)
	}
	legacyAfterFirstRevision := projectDeviceName(Device{
		FriendlyName:  "Current",
		AliasRevision: 1,
		AliasHistory:  []AliasChange{{Revision: 1, PreviousFriendlyName: "Legacy Name", FriendlyName: "Current", ChangedAt: at.Add(time.Minute)}},
	}, at)
	if legacyAfterFirstRevision.FriendlyNameAtCaptureKnown || legacyAfterFirstRevision.FriendlyNameAtCapture != "Legacy Name" {
		t.Fatalf("first revision made an undated legacy baseline look certain: %#v", legacyAfterFirstRevision)
	}
	truncated := projectDeviceName(Device{
		FriendlyName:          "Current",
		AliasRevision:         2,
		AliasHistoryTruncated: true,
		AliasHistory:          []AliasChange{{Revision: 2, PreviousFriendlyName: "Previous", FriendlyName: "Current", ChangedAt: at.Add(time.Minute)}},
	}, at)
	if truncated.FriendlyNameAtCaptureKnown || truncated.FriendlyNameAtCapture != "Previous" {
		t.Fatalf("truncated projection overstated capture-time certainty: %#v", truncated)
	}
}
