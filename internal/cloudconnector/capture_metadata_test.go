package cloudconnector

import (
	"encoding/json"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/capture"
)

func TestEnqueueCaptureSummaryProjectsBoundedCloudMetadata(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	endedAt := now.Add(90 * time.Second)
	view := capture.View{
		Session: capture.Session{
			ID:        "capture-0123456789abcdef0123456789abcdef",
			Request:   capture.StartRequest{Name: "TV regression"},
			StartedAt: now,
		},
		State: capture.StateCompleted,
		Worker: &capture.WorkerStatus{
			EndedAt:         endedAt,
			PacketsCaptured: 40,
		},
		Manifest: &capture.Manifest{
			PacketsCaptured: 42,
			TotalSizeBytes:  8192,
		},
	}
	encoded, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(encoded, &result); err != nil {
		t.Fatal(err)
	}
	queue := &MetadataQueue{Root: t.TempDir(), Now: func() time.Time { return endedAt }}
	job := CloudJob{ID: "job-capture-stop", IdempotencyKey: "capture-stop-key", Type: JobCaptureStop}
	if err := enqueueCaptureSummary(queue, job, result, endedAt); err != nil {
		t.Fatal(err)
	}
	if err := enqueueCaptureSummary(queue, job, result, endedAt); err != nil {
		t.Fatal(err)
	}
	batch, available, err := queue.NextBatch(State{SensorID: "sensor-1", OrganizationID: "org-1"}, 10)
	if err != nil || !available || len(batch.Events) != 1 {
		t.Fatalf("unexpected queued capture batch: available=%t events=%d err=%v", available, len(batch.Events), err)
	}
	if batch.Events[0].Type != MetadataCaptureSummary {
		t.Fatalf("unexpected metadata type %q", batch.Events[0].Type)
	}
	var payload captureMetadataPayload
	if err := json.Unmarshal(batch.Events[0].Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.LocalCaptureID != view.Session.ID || payload.Name != "TV regression" || payload.State != "completed" || payload.PacketCount != 42 || payload.ByteCount != 8192 || !payload.LocalOnly {
		t.Fatalf("unexpected capture metadata payload: %#v", payload)
	}
	if payload.StartedAt == nil || !payload.StartedAt.Equal(now) || payload.StoppedAt == nil || !payload.StoppedAt.Equal(endedAt) {
		t.Fatalf("unexpected capture metadata timestamps: %#v", payload)
	}
}

func TestEnqueueCaptureSummaryRejectsMalformedLocalResult(t *testing.T) {
	queue := &MetadataQueue{Root: t.TempDir()}
	err := enqueueCaptureSummary(queue, CloudJob{ID: "job", IdempotencyKey: "key", Type: JobCaptureStart}, map[string]any{"state": "RUNNING"}, time.Now().UTC())
	if err == nil {
		t.Fatal("malformed capture result was accepted")
	}
}
