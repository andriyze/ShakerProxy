package cloudconnector

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func TestPermanentMetadataRejection(t *testing.T) {
	if !permanentMetadataRejection(HTTPStatusError{StatusCode: http.StatusBadRequest}) {
		t.Fatal("expected HTTP 400 to be permanent")
	}
	if permanentMetadataRejection(HTTPStatusError{StatusCode: http.StatusServiceUnavailable}) {
		t.Fatal("expected HTTP 503 to remain retryable")
	}
}

func TestDropRejectedMetadataEvent(t *testing.T) {
	now := time.Date(2026, 9, 4, 22, 0, 0, 0, time.UTC)
	queue := &MetadataQueue{Root: t.TempDir(), Now: func() time.Time { return now }}
	_, err := queue.Enqueue([]LocalMetadataEvent{
		{EventID: "event-a", Type: MetadataDNSEvent, ObservedAt: now, Payload: json.RawMessage(`{"query_name":"example.com"}`)},
		{EventID: "event-b", Type: MetadataDNSEvent, ObservedAt: now, Payload: json.RawMessage(`{"query_name":"example.net"}`)},
	})
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	batch, ok, err := queue.NextBatch(State{SensorID: "sensor", OrganizationID: "org"}, 1)
	if err != nil || !ok {
		t.Fatalf("next batch: ok=%v err=%v", ok, err)
	}
	if err := queue.DropRejected(batch.SequenceStart); err != nil {
		t.Fatalf("drop rejected: %v", err)
	}
	summary, err := queue.Summary()
	if err != nil {
		t.Fatalf("summary: %v", err)
	}
	if summary["event_count"] != 1 {
		t.Fatalf("event_count=%v, want 1", summary["event_count"])
	}
	if summary["dropped_events"] != uint64(1) {
		t.Fatalf("dropped_events=%v, want 1", summary["dropped_events"])
	}
}
