package cloudconnector

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/ingest"
)

type rollupFlow struct {
	id         string
	kind       string
	device     string
	protocol   string
	evidence   string
	port       int
	bytes      uint64
	durationMS uint64
	at         time.Time
}

func rollupFlowEvent(t *testing.T, flow rollupFlow) LocalMetadataEvent {
	t.Helper()
	if flow.kind == "" {
		flow.kind = "zeek.conn"
	}
	if flow.evidence == "" {
		flow.evidence = "ANALYZER"
	}
	payload, err := json.Marshal(map[string]any{
		"local_device_id":      flow.device,
		"source_ip":            "10.77.0.20",
		"destination_ip":       "198.51.100.7",
		"destination_port":     flow.port,
		"transport":            "tcp",
		"application_protocol": flow.protocol,
		"bytes_sent":           flow.bytes / 2,
		"bytes_received":       flow.bytes - flow.bytes/2,
		"duration_ms":          flow.durationMS,
		"attributes": map[string]any{
			"source":            strings.SplitN(flow.kind, ".", 2)[0],
			"event_kind":        flow.kind,
			"protocol_evidence": flow.evidence,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return LocalMetadataEvent{EventID: flow.id, Type: MetadataFlowSummary, ObservedAt: flow.at, Payload: payload}
}

func emitSummaries(t *testing.T, rollup *ProtocolRollup, categories map[string]string) []ProtocolSummary {
	t.Helper()
	var summaries []ProtocolSummary
	_, err := rollup.Emit(categories, func(events []LocalMetadataEvent) error {
		for _, event := range events {
			if event.Type != MetadataProtocolSummary || !strings.HasPrefix(event.EventID, "protocol-summary-") || !metadataEventIDPattern.MatchString(event.EventID) {
				t.Fatalf("unexpected emitted event %#v", event)
			}
			var summary ProtocolSummary
			decoder := json.NewDecoder(strings.NewReader(string(event.Payload)))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&summary); err != nil {
				t.Fatalf("decode summary: %v", err)
			}
			if !event.ObservedAt.Equal(summary.LastSeen) {
				t.Fatalf("observed_at %s does not match last_seen %s", event.ObservedAt, summary.LastSeen)
			}
			summaries = append(summaries, summary)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	return summaries
}

func summaryFor(summaries []ProtocolSummary, device, protocol string) (ProtocolSummary, bool) {
	for _, summary := range summaries {
		if summary.LocalDeviceID == device && summary.Protocol == protocol {
			return summary, true
		}
	}
	return ProtocolSummary{}, false
}

func TestProtocolRollupAggregatesConnectionsPerDeviceProtocolAndHour(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 30, 0, 0, time.UTC)
	rollup := &ProtocolRollup{Root: t.TempDir(), Now: func() time.Time { return now }}
	hour := time.Date(2026, 9, 29, 11, 0, 0, 0, time.UTC)
	events := []LocalMetadataEvent{
		rollupFlowEvent(t, rollupFlow{id: "a", device: "device-cam", protocol: "mqtt", port: 1883, bytes: 1000, durationMS: 2000, at: hour.Add(5 * time.Minute)}),
		rollupFlowEvent(t, rollupFlow{id: "b", device: "device-cam", protocol: "mqtt", port: 1883, bytes: 500, durationMS: 1000, at: hour.Add(40 * time.Minute)}),
		rollupFlowEvent(t, rollupFlow{id: "c", device: "device-cam", protocol: "mqtt", evidence: "PORT_HEURISTIC", port: 8884, bytes: 20, at: hour.Add(41 * time.Minute)}),
		// Suricata saw two of the same three connections: an alternative view,
		// not additional traffic.
		rollupFlowEvent(t, rollupFlow{id: "d", kind: "suricata.flow", device: "device-cam", protocol: "mqtt", port: 1883, bytes: 1100, at: hour.Add(5 * time.Minute)}),
		rollupFlowEvent(t, rollupFlow{id: "e", kind: "suricata.flow", device: "device-cam", protocol: "mqtt", port: 1883, bytes: 600, at: hour.Add(40 * time.Minute)}),
		// DNS and alert records describe connections already counted above.
		rollupFlowEvent(t, rollupFlow{id: "f", kind: "suricata.dns", device: "device-cam", protocol: "dns", port: 53, bytes: 90, at: hour.Add(6 * time.Minute)}),
		rollupFlowEvent(t, rollupFlow{id: "g", kind: "suricata.alert", device: "device-cam", protocol: "mqtt", port: 1883, bytes: 90, at: hour.Add(6 * time.Minute)}),
		// Unattributed and unidentified traffic stays visible.
		rollupFlowEvent(t, rollupFlow{id: "h", protocol: "unknown-tcp", evidence: "UNCLASSIFIED", port: 34567, bytes: 4096, at: hour.Add(10 * time.Minute)}),
		// A different hour is a different bucket.
		rollupFlowEvent(t, rollupFlow{id: "i", device: "device-cam", protocol: "mqtt", port: 1883, bytes: 7, at: hour.Add(-30 * time.Minute)}),
		{EventID: "j", Type: MetadataDNSEvent, ObservedAt: hour, Payload: json.RawMessage(`{"query_name":"example.com"}`)},
	}
	if err := rollup.Observe(events); err != nil {
		t.Fatalf("observe: %v", err)
	}
	summaries := emitSummaries(t, rollup, map[string]string{"device-cam": "camera"})
	if len(summaries) != 3 {
		t.Fatalf("expected 3 summaries, got %d: %#v", len(summaries), summaries)
	}
	for index := 1; index < len(summaries); index++ {
		if summaries[index].BucketStart.Before(summaries[index-1].BucketStart) {
			t.Fatal("summaries are not emitted oldest hour first")
		}
	}
	var mqtt ProtocolSummary
	for _, summary := range summaries {
		if summary.Protocol == "mqtt" && summary.BucketStart.Equal(hour) {
			mqtt = summary
		}
	}
	if mqtt.Flows != 3 || mqtt.Bytes != 1520 {
		t.Fatalf("mqtt totals = %d flows / %d bytes, want 3 / 1520 (Zeek view, no double count)", mqtt.Flows, mqtt.Bytes)
	}
	if mqtt.Schema != 1 || mqtt.BucketSeconds != 3600 || mqtt.Label != "MQTT" || mqtt.Category != "iot-messaging" || mqtt.Visibility != "CLEARTEXT" || mqtt.Evidence != "ANALYZER" || !mqtt.Exotic || mqtt.Description == "" {
		t.Fatalf("mqtt classification is incomplete: %#v", mqtt)
	}
	if mqtt.DeviceCategory != "camera" {
		t.Fatalf("device category = %q, want camera", mqtt.DeviceCategory)
	}
	if !mqtt.FirstSeen.Equal(hour.Add(5*time.Minute)) || !mqtt.LastSeen.Equal(hour.Add(41*time.Minute)) {
		t.Fatalf("first/last seen = %s / %s", mqtt.FirstSeen, mqtt.LastSeen)
	}
	if len(mqtt.Ports) != 2 || mqtt.Ports[0] != (ProtocolSummaryPort{Transport: "tcp", Port: 1883, Flows: 2}) || mqtt.Ports[1].Port != 8884 {
		t.Fatalf("ports = %#v", mqtt.Ports)
	}
	unknown, ok := summaryFor(summaries, "", "unknown-tcp")
	if !ok || unknown.Flows != 1 || unknown.Bytes != 4096 || unknown.Evidence != "UNCLASSIFIED" || unknown.Visibility != "OPAQUE" || unknown.DeviceCategory != "" {
		t.Fatalf("unattributed unknown traffic summary = %#v (found %v)", unknown, ok)
	}
	if _, ok := summaryFor(summaries, "device-cam", "dns"); ok {
		t.Fatal("DNS records were counted as connections")
	}
}

func TestProtocolRollupFallsBackToSuricataAndClassifiesLegacyServices(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 30, 0, 0, time.UTC)
	rollup := &ProtocolRollup{Root: t.TempDir(), Now: func() time.Time { return now }}
	at := time.Date(2026, 9, 29, 12, 1, 0, 0, time.UTC)
	legacy := rollupFlowEvent(t, rollupFlow{id: "legacy", kind: "suricata.flow", device: "device-tv", protocol: "ssl", evidence: "-", port: 443, bytes: 10, at: at})
	portOnly := rollupFlowEvent(t, rollupFlow{id: "tuya", kind: "suricata.flow", device: "device-plug", protocol: "failed", evidence: "-", port: 6668, bytes: 5, at: at})
	if err := rollup.Observe([]LocalMetadataEvent{legacy, portOnly}); err != nil {
		t.Fatal(err)
	}
	summaries := emitSummaries(t, rollup, nil)
	tls, ok := summaryFor(summaries, "device-tv", "tls")
	if !ok || tls.Flows != 1 || tls.Evidence != "ANALYZER" || tls.Exotic {
		t.Fatalf("legacy analyzer service was not classified: %#v", summaries)
	}
	tuya, ok := summaryFor(summaries, "device-plug", "tuya")
	if !ok || tuya.Evidence != "PORT_HEURISTIC" || !tuya.Exotic || tuya.Visibility != "OPAQUE" {
		t.Fatalf("port-only protocol was not classified: %#v", summaries)
	}
}

func TestProtocolRollupEmitsCumulativeTotalsAndThrottlesOpenHour(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 10, 0, 0, time.UTC)
	rollup := &ProtocolRollup{Root: t.TempDir(), Now: func() time.Time { return now }}
	openHour := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	observe := func(id string, bytes uint64) {
		t.Helper()
		if err := rollup.Observe([]LocalMetadataEvent{rollupFlowEvent(t, rollupFlow{id: id, device: "device-cam", protocol: "rtsp", port: 554, bytes: bytes, at: openHour.Add(5 * time.Minute)})}); err != nil {
			t.Fatal(err)
		}
	}
	observe("one", 100)
	first := emitSummaries(t, rollup, nil)
	if len(first) != 1 || first[0].Flows != 1 {
		t.Fatalf("first emission = %#v", first)
	}
	if again := emitSummaries(t, rollup, nil); len(again) != 0 {
		t.Fatalf("unchanged aggregate was re-emitted: %#v", again)
	}
	observe("two", 50)
	now = now.Add(5 * time.Minute)
	if throttled := emitSummaries(t, rollup, nil); len(throttled) != 0 {
		t.Fatalf("open hour was re-emitted before the throttle interval: %#v", throttled)
	}
	now = now.Add(protocolRollupOpenBucketInterval)
	second := emitSummaries(t, rollup, nil)
	if len(second) != 1 || second[0].Flows != 2 || second[0].Bytes != 150 {
		t.Fatalf("cumulative re-emission = %#v", second)
	}
	observe("three", 25)
	now = openHour.Add(ProtocolSummaryBucket + time.Second)
	closed := emitSummaries(t, rollup, nil)
	if len(closed) != 1 || closed[0].Flows != 3 || closed[0].Bytes != 175 {
		t.Fatalf("closed hour was not emitted immediately with cumulative totals: %#v", closed)
	}
}

func TestProtocolRollupKeepsPendingWorkWhenEnqueueFails(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 10, 0, 0, time.UTC)
	rollup := &ProtocolRollup{Root: t.TempDir(), Now: func() time.Time { return now }}
	if err := rollup.Observe([]LocalMetadataEvent{rollupFlowEvent(t, rollupFlow{id: "a", device: "device-cam", protocol: "rtsp", port: 554, bytes: 1, at: now.Add(-time.Minute)})}); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("queue full")
	if _, err := rollup.Emit(nil, func([]LocalMetadataEvent) error { return failure }); !errors.Is(err, failure) {
		t.Fatalf("emit error = %v", err)
	}
	if summaries := emitSummaries(t, rollup, nil); len(summaries) != 1 {
		t.Fatalf("pending aggregate was lost after a failed enqueue: %#v", summaries)
	}
}

func TestProtocolRollupBucketsLongConnectionsByLastActivityAndDropsLateRecords(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 10, 0, 0, time.UTC)
	rollup := &ProtocolRollup{Root: t.TempDir(), Now: func() time.Time { return now }}
	started := now.Add(-50 * time.Hour)
	longLived := rollupFlowEvent(t, rollupFlow{id: "vpn", device: "device-tv", protocol: "wireguard", port: 51820, bytes: 9, durationMS: uint64((49*time.Hour + 30*time.Minute) / time.Millisecond), at: started})
	late := rollupFlowEvent(t, rollupFlow{id: "late", device: "device-tv", protocol: "mqtt", port: 1883, bytes: 9, at: now.Add(-ProtocolRollupLateWindow - 3*time.Hour)})
	if err := rollup.Observe([]LocalMetadataEvent{longLived, late}); err != nil {
		t.Fatal(err)
	}
	summaries := emitSummaries(t, rollup, nil)
	if len(summaries) != 1 || summaries[0].Protocol != "wireguard" {
		t.Fatalf("summaries = %#v", summaries)
	}
	if !summaries[0].BucketStart.Equal(time.Date(2026, 9, 29, 11, 0, 0, 0, time.UTC)) || !summaries[0].FirstSeen.Equal(started) {
		t.Fatalf("long connection bucket = %s first_seen = %s", summaries[0].BucketStart, summaries[0].FirstSeen)
	}
	if rollup.Summary()["late_flows"] != uint64(1) {
		t.Fatalf("late record was not counted as dropped: %#v", rollup.Summary())
	}
}

func TestProtocolRollupSurvivesRestartAndIgnoresCorruptState(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 9, 29, 12, 10, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	first := &ProtocolRollup{Root: root, Now: clock}
	if err := first.Observe([]LocalMetadataEvent{rollupFlowEvent(t, rollupFlow{id: "a", device: "device-cam", protocol: "rtsp", port: 554, bytes: 10, at: now.Add(-time.Minute)})}); err != nil {
		t.Fatal(err)
	}
	if err := first.Persist(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(root, protocolRollupFile))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("rollup state file missing or not private: %v %v", info, err)
	}
	restarted := &ProtocolRollup{Root: root, Now: clock}
	if err := restarted.Observe([]LocalMetadataEvent{rollupFlowEvent(t, rollupFlow{id: "b", device: "device-cam", protocol: "rtsp", port: 554, bytes: 5, at: now.Add(-time.Minute)})}); err != nil {
		t.Fatal(err)
	}
	summaries := emitSummaries(t, restarted, nil)
	if len(summaries) != 1 || summaries[0].Flows != 2 || summaries[0].Bytes != 15 {
		t.Fatalf("rollup did not resume from persisted state: %#v", summaries)
	}

	if err := os.WriteFile(filepath.Join(root, protocolRollupFile), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	corrupt := &ProtocolRollup{Root: root, Now: clock}
	if summary := corrupt.Summary(); summary["aggregates"] != 0 {
		t.Fatalf("corrupt state was not discarded: %#v", summary)
	}
	if err := corrupt.Persist(); err != nil {
		t.Fatalf("corrupt state was not rewritten: %v", err)
	}
}

func TestProtocolRollupStateIsBounded(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 10, 0, 0, time.UTC)
	rollup := &ProtocolRollup{Root: t.TempDir(), Now: func() time.Time { return now }}
	events := make([]LocalMetadataEvent, 0, 500)
	for index := 0; index < MaxProtocolRollupAggregates+10; index++ {
		events = append(events, rollupFlowEvent(t, rollupFlow{id: fmt.Sprintf("e%d", index), device: fmt.Sprintf("device-%05d", index), protocol: "mqtt", port: 1883, bytes: 1, at: now.Add(-time.Minute)}))
		if len(events) == cap(events) {
			if err := rollup.Observe(events); err != nil {
				t.Fatal(err)
			}
			events = events[:0]
		}
	}
	if err := rollup.Observe(events); err != nil {
		t.Fatal(err)
	}
	summary := rollup.Summary()
	if count := summary["aggregates"].(int); count > MaxProtocolRollupAggregates || count == 0 {
		t.Fatalf("aggregate count %d exceeds bound %d", count, MaxProtocolRollupAggregates)
	}
	if summary["evicted_aggregates"].(uint64) == 0 {
		t.Fatal("eviction was not recorded")
	}
	emitted := emitSummaries(t, rollup, nil)
	if len(emitted) != MaxMetadataEnqueueEvents {
		t.Fatalf("one emission queued %d events, want the enqueue bound %d", len(emitted), MaxMetadataEnqueueEvents)
	}
}

func TestProtocolRollupFromProjectedZeekConnection(t *testing.T) {
	now := time.Now().UTC()
	raw := []byte(fmt.Sprintf(`{"ts":%f,"uid":"Cmqtt1","_path":"conn","id.orig_h":"10.77.0.30","id.orig_p":50000,"id.resp_h":"198.51.100.40","id.resp_p":1883,"proto":"tcp","service":"mqtt","orig_ip_bytes":300,"resp_ip_bytes":200,"duration":0.5}`, float64(now.Add(-2*time.Minute).UnixNano())/1e9))
	envelope, err := ingest.NormalizeZeekJSON(raw, "8.2.1", "")
	if err != nil {
		t.Fatal(err)
	}
	projected := ProjectNormalizedEvents(envelope, now)
	rollup := &ProtocolRollup{Root: t.TempDir(), Now: func() time.Time { return now }}
	if err := rollup.Observe(projected); err != nil {
		t.Fatal(err)
	}
	summaries := emitSummaries(t, rollup, nil)
	if len(summaries) != 1 || summaries[0].Protocol != "mqtt" || summaries[0].Flows != 1 || summaries[0].Bytes != 500 || summaries[0].Evidence != "ANALYZER" {
		t.Fatalf("projected Zeek connection summary = %#v", summaries)
	}
	if len(summaries[0].Ports) != 1 || summaries[0].Ports[0].Port != 1883 {
		t.Fatalf("ports = %#v", summaries[0].Ports)
	}
}
