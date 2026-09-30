package cloudconnector

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

func TestProtocolSummariesWaitForCloudCapability(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC()
	queue := &MetadataQueue{Root: root, Now: func() time.Time { return now }}
	rollup := &ProtocolRollup{Root: root, Now: func() time.Time { return now }}
	deviceRuntime := &DeviceRuntimeStore{Root: root, Now: func() time.Time { return now }}
	upsert, _ := json.Marshal(map[string]any{"local_device_id": "device-cam", "category": "Camera", "platform": "embedded"})
	if err := deviceRuntime.ObserveMetadata([]LocalMetadataEvent{{Type: MetadataDeviceUpsert, ObservedAt: now, Payload: upsert}}); err != nil {
		t.Fatal(err)
	}
	if err := rollup.Observe([]LocalMetadataEvent{rollupFlowEvent(t, rollupFlow{id: "a", device: "device-cam", protocol: "rtsp", port: 554, bytes: 10, at: now.Add(-time.Minute)})}); err != nil {
		t.Fatal(err)
	}

	if err := queueDaemonProtocolSummaries(rollup, queue, deviceRuntime, []string{"something.else"}); err != nil {
		t.Fatal(err)
	}
	if summary, _ := queue.Summary(); summary["event_count"] != 0 {
		t.Fatalf("summaries were queued for a cloud without the capability: %#v", summary)
	}
	if rollup.Summary()["pending"] != 1 {
		t.Fatal("rollup lost pending work while the cloud lacked the capability")
	}

	if err := queueDaemonProtocolSummaries(rollup, queue, deviceRuntime, []string{ProtocolSummaryCapability}); err != nil {
		t.Fatal(err)
	}
	batch, ok, err := queue.NextBatch(State{SensorID: "sensor", OrganizationID: "org"}, 10)
	if err != nil || !ok || len(batch.Events) != 1 || batch.Events[0].Type != MetadataProtocolSummary {
		t.Fatalf("capability-gated summary was not queued: ok=%v err=%v %#v", ok, err, batch)
	}
	var summary ProtocolSummary
	if err := json.Unmarshal(batch.Events[0].Payload, &summary); err != nil {
		t.Fatal(err)
	}
	if summary.DeviceCategory != "camera" || summary.Protocol != "rtsp" {
		t.Fatalf("queued summary = %#v", summary)
	}

	dropped, err := queue.DropType(MetadataProtocolSummary)
	if err != nil || dropped != 1 {
		t.Fatalf("DropType = %d, %v", dropped, err)
	}
	if summary, _ := queue.Summary(); summary["event_count"] != 0 || summary["dropped_events"] != uint64(1) {
		t.Fatalf("queue after DropType = %#v", summary)
	}
}

func TestLocalEnqueueFeedsRollupOnceAndRejectsExternalSummaries(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC()
	queue := &MetadataQueue{Root: root, Now: func() time.Time { return now }}
	rollup := &ProtocolRollup{Root: root, Now: func() time.Time { return now }}
	handler := LocalServer{MetadataQueue: queue, ProtocolRollup: rollup}.Handler()
	post := func(events []LocalMetadataEvent) int {
		t.Helper()
		body, err := json.Marshal(map[string]any{"events": events})
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPost, "/v1/metadata/enqueue", bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response.Code
	}
	flow := rollupFlowEvent(t, rollupFlow{id: "flow-1", device: "device-cam", protocol: "rtsp", port: 554, bytes: 10, at: now.Add(-time.Minute)})
	for attempt := 0; attempt < 2; attempt++ {
		if code := post([]LocalMetadataEvent{flow}); code != http.StatusAccepted {
			t.Fatalf("enqueue attempt %d status %d", attempt, code)
		}
	}
	summaries := emitSummaries(t, rollup, nil)
	if len(summaries) != 1 || summaries[0].Flows != 1 {
		t.Fatalf("a retried delivery was counted twice: %#v", summaries)
	}
	external := LocalMetadataEvent{EventID: "forged", Type: MetadataProtocolSummary, ObservedAt: now, Payload: json.RawMessage(`{"schema":1}`)}
	if code := post([]LocalMetadataEvent{external}); code != http.StatusBadRequest {
		t.Fatalf("external protocol.summary status %d, want 400", code)
	}
}

func TestNormalizeCloudCapabilities(t *testing.T) {
	values := normalizeCloudCapabilities([]string{" metadata.protocol-summary ", "", "metadata.protocol-summary", "bad value", "a.b"})
	if !reflect.DeepEqual(values, []string{"a.b", "metadata.protocol-summary"}) {
		t.Fatalf("normalized capabilities = %#v", values)
	}
	if !containsCapability(daemonCapabilities(DaemonConfig{}), ProtocolSummaryCapability) {
		t.Fatal("sensor does not advertise protocol summaries")
	}
}
