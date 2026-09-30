package cloudconnector

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestMetadataQueuePersistsContiguousBatchesAndAcknowledges(t *testing.T) {
	now := time.Date(2026, 9, 2, 20, 0, 0, 0, time.UTC)
	queue := &MetadataQueue{Root: t.TempDir(), Now: func() time.Time { return now }}
	payloadOne, _ := json.Marshal(map[string]any{
		"local_device_id": "device-1",
		"friendly_name":   "Living Room TV",
		"platform":        "tvos",
		"confidence":      0.9,
		"first_seen_at":   now,
		"last_seen_at":    now,
	})
	payloadTwo, _ := json.Marshal(map[string]any{
		"local_device_id":      "device-1",
		"destination_ip":       "192.0.2.10",
		"destination_port":     443,
		"transport":            "tcp",
		"application_protocol": "tls",
		"bytes_sent":           100,
		"bytes_received":       200,
		"duration_ms":          50,
	})
	accepted, err := queue.Enqueue([]LocalMetadataEvent{
		{EventID: "event-one", Type: MetadataDeviceUpsert, ObservedAt: now, Payload: payloadOne},
		{EventID: "event-two", Type: MetadataFlowSummary, ObservedAt: now, Payload: payloadTwo},
	})
	if err != nil || accepted != 2 {
		t.Fatalf("enqueue failed: accepted=%d err=%v", accepted, err)
	}
	state := State{SensorID: "sensor-1", OrganizationID: "org-1"}
	batch, available, err := queue.NextBatch(state, 100)
	if err != nil || !available {
		t.Fatalf("next batch failed: available=%t err=%v", available, err)
	}
	if batch.SequenceStart != 1 || batch.SequenceEnd != 2 || len(batch.Events) != 2 || batch.SensorID != state.SensorID {
		t.Fatalf("unexpected metadata batch: %#v", batch)
	}
	if err := queue.AckThrough(1); err != nil {
		t.Fatal(err)
	}
	batch, available, err = queue.NextBatch(state, 100)
	if err != nil || !available || batch.SequenceStart != 2 || batch.SequenceEnd != 2 || len(batch.Events) != 1 {
		t.Fatalf("partial acknowledgement failed: %#v available=%t err=%v", batch, available, err)
	}
	if err := queue.AckThrough(2); err != nil {
		t.Fatal(err)
	}
	if _, available, err := queue.NextBatch(state, 100); err != nil || available {
		t.Fatalf("fully acknowledged queue remained available: %t %v", available, err)
	}
}

func TestMetadataQueueRejectsUnknownEventTypeAndOversizedPayload(t *testing.T) {
	queue := &MetadataQueue{Root: t.TempDir()}
	if _, err := queue.Enqueue([]LocalMetadataEvent{{EventID: "../../escape", Type: MetadataTLSEvent, Payload: json.RawMessage(`{}`)}}); err == nil {
		t.Fatal("unsafe metadata event ID was accepted")
	}
	if _, err := queue.Enqueue([]LocalMetadataEvent{{Type: "shell.output", Payload: json.RawMessage(`{}`)}}); err == nil {
		t.Fatal("unknown metadata type was accepted")
	}
	oversized := make(json.RawMessage, (64<<10)+1)
	for index := range oversized {
		oversized[index] = 'x'
	}
	if _, err := queue.Enqueue([]LocalMetadataEvent{{Type: MetadataTLSEvent, Payload: oversized}}); err == nil {
		t.Fatal("oversized metadata payload was accepted")
	}
}

func TestMetadataQueueDeduplicatesEventIDs(t *testing.T) {
	now := time.Now().UTC()
	queue := &MetadataQueue{Root: t.TempDir(), Now: func() time.Time { return now }}
	payload := json.RawMessage(`{"local_capture_id":"capture-1","state":"running","packet_count":0,"byte_count":0,"local_only":true}`)
	event := LocalMetadataEvent{EventID: "event-duplicate", Type: MetadataCaptureSummary, ObservedAt: now, Payload: payload}
	if _, err := queue.Enqueue([]LocalMetadataEvent{event}); err != nil {
		t.Fatal(err)
	}
	if _, err := queue.Enqueue([]LocalMetadataEvent{event}); err != nil {
		t.Fatal(err)
	}
	summary, err := queue.Summary()
	if err != nil {
		t.Fatal(err)
	}
	if summary["event_count"] != 1 {
		t.Fatalf("duplicate event was stored twice: %#v", summary)
	}
}

func TestMetadataQueueSplitsUploadsAtCloudBodyLimit(t *testing.T) {
	now := time.Now().UTC()
	queue := &MetadataQueue{Root: t.TempDir(), Now: func() time.Time { return now }}
	payload, err := json.Marshal(map[string]string{"padding": strings.Repeat("x", 48<<10)})
	if err != nil {
		t.Fatal(err)
	}
	for batch := 0; batch < 2; batch++ {
		events := make([]LocalMetadataEvent, 30)
		for index := range events {
			events[index] = LocalMetadataEvent{
				EventID:    fmt.Sprintf("bounded-%d-%d", batch, index),
				Type:       MetadataTLSEvent,
				ObservedAt: now,
				Payload:    payload,
			}
		}
		if _, err := queue.Enqueue(events); err != nil {
			t.Fatal(err)
		}
	}
	request, available, err := queue.NextBatch(State{SensorID: "sensor-1", OrganizationID: "org-1"}, MaxMetadataUploadEvents)
	if err != nil || !available {
		t.Fatalf("bounded batch was unavailable: %t %v", available, err)
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > MaxMetadataRequestBytes {
		t.Fatalf("metadata request is %d bytes, limit is %d", len(encoded), MaxMetadataRequestBytes)
	}
	if len(request.Events) == 0 || len(request.Events) >= 60 {
		t.Fatalf("queue did not split the oversized upload: %d events", len(request.Events))
	}
}

func TestMetadataQueueDropsExpiredPrefixWithoutBlockingNewEvents(t *testing.T) {
	now := time.Date(2026, 9, 2, 20, 0, 0, 0, time.UTC)
	queue := &MetadataQueue{Root: t.TempDir(), Now: func() time.Time { return now }}
	if _, err := queue.Enqueue([]LocalMetadataEvent{{EventID: "expired-later", Type: MetadataTLSEvent, ObservedAt: now, Payload: json.RawMessage(`{"server_name":"example.test"}`)}}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(MaxMetadataQueueAge + time.Second)
	if _, err := queue.Enqueue([]LocalMetadataEvent{{EventID: "current", Type: MetadataTLSEvent, ObservedAt: now, Payload: json.RawMessage(`{"server_name":"current.test"}`)}}); err != nil {
		t.Fatal(err)
	}
	batch, available, err := queue.NextBatch(State{SensorID: "sensor-1", OrganizationID: "org-1"}, 10)
	if err != nil || !available || len(batch.Events) != 1 || batch.Events[0].EventID != "current" || batch.SequenceStart != 2 {
		t.Fatalf("expired metadata blocked the current queue: %#v available=%t err=%v", batch, available, err)
	}
	summary, err := queue.Summary()
	if err != nil || summary["dropped_events"] != uint64(1) || summary["max_queue_age_seconds"] != int64(MaxMetadataQueueAge/time.Second) {
		t.Fatalf("queue retention was not observable: %#v err=%v", summary, err)
	}
}

func TestMetadataQueueByteCompactionDropsOnlyOldestPrefix(t *testing.T) {
	document := metadataQueueDocument{SchemaVersion: metadataQueueSchema, NextSequence: 7}
	for sequence := uint64(1); sequence <= 6; sequence++ {
		document.Events = append(document.Events, QueuedMetadataEvent{Sequence: sequence, EventID: fmt.Sprintf("event-%d", sequence), Type: MetadataTLSEvent, ObservedAt: time.Now().UTC(), Payload: json.RawMessage(`{"padding":"` + strings.Repeat("x", 900) + `"}`), QueuedAt: time.Now().UTC()})
	}
	encoded, err := encodeBoundedMetadataQueue(&document, 4096)
	if err != nil || len(encoded) > 4096 || len(document.Events) == 0 || document.Events[len(document.Events)-1].Sequence != 6 || document.DroppedEvents == 0 {
		t.Fatalf("byte compaction failed: bytes=%d events=%d dropped=%d err=%v", len(encoded), len(document.Events), document.DroppedEvents, err)
	}
	if document.Events[0].Sequence != document.DroppedEvents+1 {
		t.Fatalf("byte compaction did not remove a contiguous prefix: %#v", document.Events)
	}
}
