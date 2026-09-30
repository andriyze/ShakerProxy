package ingest

import (
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/querylang"
)

func TestRecentEventQueryIsStrictAndBounded(t *testing.T) {
	deviceID := "device-0123456789abcdef0123456789abcdef"
	captureID := "capture-0123456789abcdef0123456789abcdef"
	values := url.Values{"limit": {"100"}, "source": {"ZEEK"}, "kind": {"zeek.conn"}, "device_id": {deviceID}, "capture_session_id": {captureID}, "q": {"protocol:TCP bytes:>10KB"}}
	query, err := ParseRecentEventQuery(values)
	if err != nil || query.Limit != 100 || query.Source != SourceZeek || query.Kind != "zeek.conn" || query.DeviceID != deviceID || query.CaptureSessionID != captureID || query.Filter.Canonical != "protocol:tcp AND bytes>10240" {
		t.Fatalf("valid query rejected: %#v %v", query, err)
	}
	for name, invalid := range map[string]url.Values{
		"too many": {"limit": {"101"}},
		"repeated": {"limit": {"1", "2"}},
		"unknown":  {"search": {"anything"}},
		"source":   {"source": {"SQL"}},
		"device":   {"device_id": {"device-invalid"}},
		"capture":  {"capture_session_id": {"capture-invalid"}},
		"kind":     {"kind": {"bad\nkind"}},
		"typed":    {"q": {"src.ip:not-an-ip"}},
	} {
		if _, err := ParseRecentEventQuery(invalid); err == nil {
			t.Fatalf("%s query was accepted", name)
		}
	}
}

func TestRecentEventQueryEncodesCanonicalTypedFilter(t *testing.T) {
	filter, err := querylang.Parse("protocol:TCP dst.port:443")
	if err != nil {
		t.Fatal(err)
	}
	encoded := EncodeRecentEventQuery(RecentEventQuery{Limit: 25, Filter: filter})
	if encoded.Get("q") != "protocol:tcp AND dst.port:443" {
		t.Fatalf("typed query did not encode canonically: %q", encoded.Get("q"))
	}
}

func TestInternalQueryRoundTripsBoundedDeviceSelectorResolutionsOnly(t *testing.T) {
	filter, err := querylang.Parse(`(name:"Bench Camera" OR device.name:"Missing") AND tag:camera`)
	if err != nil {
		t.Fatal(err)
	}
	deviceID := "device-0123456789abcdef0123456789abcdef"
	query := RecentEventQuery{Limit: 25, Filter: filter, DeviceNameResolutions: map[string][]string{"Bench Camera": {deviceID}, "Missing": {}}, DeviceTagResolutions: map[string][]string{"camera": {deviceID}}}
	storageQuery, err := prepareStorageRecentQuery(query)
	if err != nil {
		t.Fatal(err)
	}
	values, err := encodeInternalRecentEventQuery(storageQuery)
	if err != nil || values.Get(internalNameResolutionParameter) == "" || values.Get(internalTagResolutionParameter) == "" {
		t.Fatalf("internal selector resolutions did not encode: %#v %v", values, err)
	}
	if _, err := ParseRecentEventQuery(values); err == nil {
		t.Fatal("public query parser accepted the private resolution parameter")
	}
	decoded, err := ParseInternalRecentEventQuery(values)
	if err != nil || decoded.Filter.Canonical != `(device.name:alias-ref-01 OR device.name:alias-ref-02) AND device.tag:tag-ref-01` || len(decoded.DeviceNameResolutions["alias-ref-01"]) != 1 || decoded.DeviceNameResolutions["alias-ref-01"][0] != deviceID || len(decoded.DeviceTagResolutions["tag-ref-01"]) != 1 {
		t.Fatalf("internal selector resolutions did not round trip: %#v %v", decoded, err)
	}
	missing := EncodeRecentEventQuery(storageQuery)
	if _, err := ParseInternalRecentEventQuery(missing); err == nil {
		t.Fatal("internal parser accepted an unresolved device name")
	}
	forged, err := encodeInternalRecentEventQuery(query)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseInternalRecentEventQuery(forged); err == nil {
		t.Fatal("internal parser accepted a raw inventory name")
	}
}

func TestRecentEventQueryRejectsASTThatDoesNotMatchCanonicalForm(t *testing.T) {
	canonical, err := querylang.Parse(`device.name:"Bench Camera"`)
	if err != nil {
		t.Fatal(err)
	}
	forgedRoot, err := querylang.Parse(`protocol:tcp`)
	if err != nil {
		t.Fatal(err)
	}
	canonical.Root = forgedRoot.Root
	query := RecentEventQuery{Limit: 10, Filter: canonical, DeviceNameResolutions: map[string][]string{"Bench Camera": {}}}
	if err := validateRecentEventQuery(query); err == nil {
		t.Fatal("typed filter AST that disagreed with its canonical form was accepted")
	}
}

func TestRelativeRecentCursorRequiresFrozenAnchorDuringValidation(t *testing.T) {
	filter, err := querylang.Parse(`time:last_15m`)
	if err != nil {
		t.Fatal(err)
	}
	query := RecentEventQuery{Limit: 10, Filter: filter, BeforeOccurredAt: time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC), BeforeRecordID: strings.Repeat("a", 64)}
	if err := validateRecentEventQuery(query); err == nil {
		t.Fatal("relative pagination query without a frozen anchor was accepted")
	}
}

func TestRecentEventCursorRoundTripsAndRejectsTampering(t *testing.T) {
	occurredAt := time.Date(2026, 9, 1, 12, 34, 56, 123456789, time.FixedZone("local", -5*60*60))
	recordID := strings.Repeat("a", 64)
	anchor := occurredAt.Add(time.Minute)
	cursor := encodeRecentEventCursor(occurredAt, recordID, anchor)
	decoded, err := decodeRecentEventCursor(cursor)
	if err != nil || !decoded.BeforeOccurredAt.Equal(occurredAt) || decoded.RecordID != recordID || !decoded.TimeAnchor.Equal(anchor) {
		t.Fatalf("cursor did not round trip: %#v %v", decoded, err)
	}
	legacy := base64.RawURLEncoding.EncodeToString([]byte(occurredAt.UTC().Format(time.RFC3339Nano) + "\n" + recordID))
	legacyDecoded, err := decodeRecentEventCursor(legacy)
	if err != nil || !legacyDecoded.BeforeOccurredAt.Equal(occurredAt) || legacyDecoded.RecordID != recordID || !legacyDecoded.TimeAnchor.IsZero() {
		t.Fatalf("legacy cursor compatibility failed: %#v %v", legacyDecoded, err)
	}
	anchoredQuery, err := ParseRecentEventQuery(url.Values{"q": {"time:last_15m"}, "cursor": {cursor}})
	if err != nil || !anchoredQuery.TimeAnchor.Equal(anchor) {
		t.Fatalf("relative recent cursor did not restore its anchor: %#v %v", anchoredQuery, err)
	}
	if _, err := ParseRecentEventQuery(url.Values{"q": {"time:last_15m"}, "cursor": {legacy}}); err == nil {
		t.Fatal("relative recent query accepted a legacy cursor without an anchor")
	}
	if _, err := ParseRecentEventQuery(url.Values{"q": {"protocol:tcp"}, "cursor": {cursor}}); err == nil {
		t.Fatal("non-relative recent query accepted an anchored cursor")
	}
	for _, invalid := range []string{"%%%", cursor + "tampered", strings.Repeat("a", 257)} {
		if _, err := decodeRecentEventCursor(invalid); err == nil {
			t.Fatalf("invalid cursor was accepted: %q", invalid)
		}
	}
}

func TestRelativeLiveQueryKeepsAnchorAcrossReconnectAndPrivateHop(t *testing.T) {
	receivedAt := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	anchor := receivedAt.Add(-time.Minute)
	recordID := strings.Repeat("c", 64)
	cursor := encodeAnchoredLiveEventCursor(receivedAt, recordID, anchor)
	query, err := ParseLiveEventQuery(url.Values{"limit": {"10"}, "q": {"time:last_15m"}, "cursor": {cursor}}, receivedAt.Add(time.Hour))
	if err != nil || !query.TimeAnchor.Equal(anchor) || !query.AfterReceivedAt.Equal(receivedAt) || query.Filter.Canonical != "time:last_15m" {
		t.Fatalf("anchored live query was not restored: %#v %v", query, err)
	}
	encoded, err := encodeInternalLiveEventQuery(query)
	if err != nil || encoded.Get(internalQueryAnchorParameter) != anchor.Format(time.RFC3339Nano) {
		t.Fatalf("private query anchor was not encoded: %#v %v", encoded, err)
	}
	decoded, err := ParseInternalLiveEventQuery(encoded, receivedAt.Add(2*time.Hour))
	if err != nil || !decoded.TimeAnchor.Equal(anchor) || !decoded.AfterReceivedAt.Equal(receivedAt) || decoded.AfterRecordID != recordID {
		t.Fatalf("private live anchor did not round trip: %#v %v", decoded, err)
	}
	if _, err := ParseLiveEventQuery(encoded, receivedAt); err == nil {
		t.Fatal("public parser accepted the private query anchor")
	}
	if _, err := ParseLiveEventQuery(url.Values{"q": {"time:last_15m"}, "cursor": {encodeLiveEventCursor(receivedAt, recordID)}}, receivedAt); err == nil {
		t.Fatal("relative live query accepted a legacy cursor without an anchor")
	}
	if _, err := ParseLiveEventQuery(url.Values{"q": {"protocol:tcp"}, "cursor": {cursor}}, receivedAt); err == nil {
		t.Fatal("non-relative live query accepted an anchored cursor")
	}
}

func TestLiveEventQueryResumesStrictlyAfterCursor(t *testing.T) {
	receivedAt := time.Date(2026, 9, 1, 12, 34, 56, 123456789, time.FixedZone("local", -5*60*60))
	recordID := strings.Repeat("b", 64)
	cursor := encodeLiveEventCursor(receivedAt, recordID)
	query, err := ParseLiveEventQuery(url.Values{"limit": {"25"}, "source": {"SURICATA"}, "q": {"protocol:TCP"}, "cursor": {cursor}}, time.Now())
	if err != nil || query.Limit != 25 || query.Source != SourceSuricata || query.Filter.Canonical != "protocol:tcp" || !query.AfterReceivedAt.Equal(receivedAt) || query.AfterRecordID != recordID {
		t.Fatalf("valid live query rejected: %#v %v", query, err)
	}
	encoded := EncodeLiveEventQuery(query)
	decodedTime, decodedID, err := DecodeLiveEventCursor(encoded.Get("cursor"))
	if err != nil || !decodedTime.Equal(receivedAt) || decodedID != recordID || encoded.Get("q") != "protocol:tcp" {
		t.Fatalf("live query did not round trip: %s %s %#v %v", decodedTime, decodedID, encoded, err)
	}
	for name, values := range map[string]url.Values{
		"repeated cursor": {"cursor": {cursor, cursor}},
		"tampered cursor": {"cursor": {cursor + "tampered"}},
		"unsupported":     {"follow": {"true"}},
	} {
		if _, err := ParseLiveEventQuery(values, receivedAt); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}
