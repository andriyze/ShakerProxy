package ingest

import (
	"net/url"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/querylang"
)

func TestEventQuerySnapshotContractIsStrictAndBounded(t *testing.T) {
	created := time.Date(2026, 9, 1, 15, 0, 0, 0, time.UTC)
	snapshot := EventQuerySnapshot{
		Schema: QuerySnapshotSchemaVersion, ID: "qsnap-0123456789abcdef0123456789abcdef",
		CanonicalQuery: "protocol:tcp", Sort: DefaultEventQuerySort(), MatchedCount: 42, CountRelation: "eq",
		CreatedAt: created, ExpiresAt: created.Add(DefaultQuerySnapshotTTL),
		DatasetWatermark: EventDatasetWatermark{ReceivedAt: created, RecordID: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		SnapshotSHA256:   "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", PolicyVersion: QuerySnapshotPolicyVersion,
	}
	if err := ValidateEventQuerySnapshot(snapshot); err != nil {
		t.Fatal(err)
	}
	invalid := snapshot
	invalid.Sort = []EventQuerySort{{Field: "payload", Direction: "asc"}}
	if ValidateEventQuerySnapshot(invalid) == nil {
		t.Fatal("unsafe event snapshot sort was accepted")
	}
	invalid = snapshot
	invalid.MatchedCount = MaxQuerySnapshotCountScan + 1
	if ValidateEventQuerySnapshot(invalid) == nil {
		t.Fatal("unbounded event snapshot count was accepted")
	}
	if ValidQuerySnapshotID("qsnap-../../events") || !ValidQuerySnapshotID(snapshot.ID) {
		t.Fatal("event query snapshot ID validation is unsafe")
	}
}

func TestSnapshotFilterMappingSurvivesInternalTransport(t *testing.T) {
	public, err := querylang.Parse(`time:last_15m AND device.name:"Bench Camera" AND device.tag:camera AND protocol:tcp`)
	if err != nil {
		t.Fatal(err)
	}
	deviceID := "device-0123456789abcdef0123456789abcdef"
	query := RecentEventQuery{Limit: 1, Filter: public, DeviceNameResolutions: map[string][]string{"Bench Camera": {deviceID}}, DeviceTagResolutions: map[string][]string{"camera": {deviceID}}}
	storage, err := prepareStorageRecentQuery(query)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := encodeInternalRecentEventQuery(storage)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := ParseInternalRecentEventQuery(url.Values(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateSnapshotFilterMapping(public, decoded.Filter); err != nil {
		t.Fatalf("public/storage query equivalence was lost: public=%q storage=%q: %v", public.Canonical, decoded.Filter.Canonical, err)
	}
	tampered, err := querylang.Parse(`time:last_15m AND device.name:alias-ref-01 AND device.tag:tag-ref-01 AND protocol:udp`)
	if err != nil {
		t.Fatal(err)
	}
	if validateSnapshotFilterMapping(public, tampered) == nil {
		t.Fatal("a storage filter that changed a non-alias predicate was accepted")
	}
}
