package cloudconnector

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	metadataQueueSchema      = 1
	metadataQueueFile        = "metadata-queue.json"
	MaxLocalMetadataEvents   = 20000
	MaxLocalMetadataBytes    = 32 << 20
	MaxMetadataEnqueueEvents = 500
	MaxMetadataUploadEvents  = 500
	MaxMetadataRequestBytes  = 2 << 20
	MaxMetadataQueueAge      = 7 * 24 * time.Hour
)

var metadataEventIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type MetadataEventType string

const (
	MetadataDeviceUpsert   MetadataEventType = "device.upsert"
	MetadataFlowSummary    MetadataEventType = "flow.summary"
	MetadataDNSEvent       MetadataEventType = "dns.event"
	MetadataTLSEvent       MetadataEventType = "tls.event"
	MetadataCaptureSummary MetadataEventType = "capture.summary"
)

type LocalMetadataEvent struct {
	EventID    string            `json:"event_id,omitempty"`
	Type       MetadataEventType `json:"type"`
	ObservedAt time.Time         `json:"observed_at"`
	Payload    json.RawMessage   `json:"payload"`
}

type QueuedMetadataEvent struct {
	Sequence   uint64            `json:"sequence"`
	EventID    string            `json:"event_id"`
	Type       MetadataEventType `json:"type"`
	ObservedAt time.Time         `json:"observed_at"`
	Payload    json.RawMessage   `json:"payload"`
	QueuedAt   time.Time         `json:"queued_at"`
}

type metadataQueueDocument struct {
	SchemaVersion int                   `json:"schema_version"`
	NextSequence  uint64                `json:"next_sequence"`
	Events        []QueuedMetadataEvent `json:"events"`
	DroppedEvents uint64                `json:"dropped_events"`
}

type MetadataQueue struct {
	Root string
	Now  func() time.Time
	mu   sync.Mutex
}

type MetadataBatchRequest struct {
	ProtocolVersion string          `json:"protocol_version"`
	SensorID        string          `json:"sensor_id"`
	OrganizationID  string          `json:"organization_id"`
	BatchID         string          `json:"batch_id"`
	SequenceStart   uint64          `json:"sequence_start"`
	SequenceEnd     uint64          `json:"sequence_end"`
	Events          []MetadataEvent `json:"events"`
}

type MetadataEvent struct {
	EventID    string            `json:"event_id"`
	Type       MetadataEventType `json:"type"`
	ObservedAt time.Time         `json:"observed_at"`
	Payload    json.RawMessage   `json:"payload"`
}

type MetadataBatchResponse struct {
	Accepted            bool   `json:"accepted"`
	Duplicate           bool   `json:"duplicate"`
	AcknowledgedThrough uint64 `json:"acknowledged_through"`
	ProtocolVersion     string `json:"protocol_version"`
}

func (queue *MetadataQueue) Enqueue(events []LocalMetadataEvent) (int, error) {
	if _, err := queue.enqueue(events); err != nil {
		return 0, err
	}
	return len(events), nil
}

// enqueue validates and appends events and returns the ones that were new;
// events whose ID is already queued are skipped so retried deliveries from
// ingestd are not observed twice.
func (queue *MetadataQueue) enqueue(events []LocalMetadataEvent) ([]LocalMetadataEvent, error) {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	if len(events) == 0 || len(events) > MaxMetadataEnqueueEvents {
		return nil, errors.New("metadata enqueue batch must contain between 1 and 500 events")
	}
	now := queue.now()
	totalBytes := 0
	for index := range events {
		event := &events[index]
		event.EventID = strings.TrimSpace(event.EventID)
		if event.EventID != "" && !metadataEventIDPattern.MatchString(event.EventID) {
			return nil, fmt.Errorf("metadata event %d ID is invalid", index)
		}
		if !allowedMetadataEventType(event.Type) {
			return nil, fmt.Errorf("metadata event %d type %q is unsupported", index, event.Type)
		}
		if event.ObservedAt.IsZero() {
			event.ObservedAt = now
		}
		if event.ObservedAt.Before(now.Add(-MaxMetadataQueueAge)) || event.ObservedAt.After(now.Add(2*time.Minute)) {
			return nil, fmt.Errorf("metadata event %d timestamp is outside the accepted window", index)
		}
		if len(event.Payload) == 0 || len(event.Payload) > 64<<10 || !json.Valid(event.Payload) {
			return nil, fmt.Errorf("metadata event %d payload is invalid or too large", index)
		}
		totalBytes += len(event.Payload)
		if totalBytes > 2<<20 {
			return nil, errors.New("metadata enqueue batch exceeds 2 MiB")
		}
	}
	document, err := queue.load()
	if err != nil {
		return nil, err
	}
	added := make([]LocalMetadataEvent, 0, len(events))
	for _, event := range events {
		if event.EventID == "" {
			value, err := randomMetadataID()
			if err != nil {
				return nil, err
			}
			event.EventID = value
		}
		if metadataEventExists(document.Events, event.EventID) {
			continue
		}
		added = append(added, event)
		sequence := document.NextSequence
		if sequence == 0 {
			sequence = 1
		}
		document.NextSequence = sequence + 1
		document.Events = append(document.Events, QueuedMetadataEvent{
			Sequence:   sequence,
			EventID:    event.EventID,
			Type:       event.Type,
			ObservedAt: event.ObservedAt.UTC(),
			Payload:    append(json.RawMessage(nil), event.Payload...),
			QueuedAt:   now,
		})
	}
	pruneMetadataQueue(&document, now)
	if err := queue.save(document); err != nil {
		return nil, err
	}
	return added, nil
}

func (queue *MetadataQueue) NextBatch(state State, maximum int) (MetadataBatchRequest, bool, error) {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	if maximum <= 0 || maximum > MaxMetadataUploadEvents {
		maximum = MaxMetadataUploadEvents
	}
	document, err := queue.load()
	if err != nil {
		return MetadataBatchRequest{}, false, err
	}
	if len(document.Events) == 0 {
		return MetadataBatchRequest{}, false, nil
	}
	if pruneMetadataQueue(&document, queue.now()) {
		if err := queue.save(document); err != nil {
			return MetadataBatchRequest{}, false, err
		}
		if len(document.Events) == 0 {
			return MetadataBatchRequest{}, false, nil
		}
	}
	sort.Slice(document.Events, func(i, j int) bool { return document.Events[i].Sequence < document.Events[j].Sequence })
	available := document.Events
	if len(available) > maximum {
		available = available[:maximum]
	}
	selected := make([]QueuedMetadataEvent, 0, len(available))
	estimatedBytes := 4096
	for _, event := range available {
		eventBytes := len(event.Payload) + len(event.EventID) + len(event.Type) + 256
		if len(selected) != 0 && estimatedBytes+eventBytes > MaxMetadataRequestBytes {
			break
		}
		selected = append(selected, event)
		estimatedBytes += eventBytes
	}
	if len(selected) == 0 {
		return MetadataBatchRequest{}, false, errors.New("queued metadata event cannot fit in an upload request")
	}
	for len(selected) != 0 {
		batch, err := buildMetadataBatch(state, selected)
		if err != nil {
			return MetadataBatchRequest{}, false, err
		}
		encoded, err := json.Marshal(batch)
		if err != nil {
			return MetadataBatchRequest{}, false, err
		}
		if len(encoded) <= MaxMetadataRequestBytes {
			return batch, true, nil
		}
		selected = selected[:len(selected)-1]
	}
	return MetadataBatchRequest{}, false, errors.New("queued metadata event cannot fit in an upload request")
}

func buildMetadataBatch(state State, selected []QueuedMetadataEvent) (MetadataBatchRequest, error) {
	events := make([]MetadataEvent, len(selected))
	for index, event := range selected {
		events[index] = MetadataEvent{
			EventID:    event.EventID,
			Type:       event.Type,
			ObservedAt: event.ObservedAt,
			Payload:    append(json.RawMessage(nil), event.Payload...),
		}
	}
	encoded, err := json.Marshal(events)
	if err != nil {
		return MetadataBatchRequest{}, err
	}
	digest := sha256.Sum256(encoded)
	start := selected[0].Sequence
	end := selected[len(selected)-1].Sequence
	batchID := fmt.Sprintf("batch_%d_%d_%s", start, end, hex.EncodeToString(digest[:8]))
	return MetadataBatchRequest{
		ProtocolVersion: ProtocolVersion,
		SensorID:        state.SensorID,
		OrganizationID:  state.OrganizationID,
		BatchID:         batchID,
		SequenceStart:   start,
		SequenceEnd:     end,
		Events:          events,
	}, nil
}

func (queue *MetadataQueue) AckThrough(sequence uint64) error {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	document, err := queue.load()
	if err != nil {
		return err
	}
	remaining := document.Events[:0]
	for _, event := range document.Events {
		if event.Sequence <= sequence {
			continue
		}
		remaining = append(remaining, event)
	}
	document.Events = remaining
	return queue.save(document)
}

func (queue *MetadataQueue) DropRejected(sequence uint64) error {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	document, err := queue.load()
	if err != nil {
		return err
	}
	remaining := document.Events[:0]
	dropped := uint64(0)
	for _, event := range document.Events {
		if event.Sequence == sequence {
			dropped++
			continue
		}
		remaining = append(remaining, event)
	}
	if dropped == 0 {
		return errors.New("rejected metadata sequence was not found")
	}
	document.Events = remaining
	document.DroppedEvents += dropped
	return queue.save(document)
}

// DropType removes every queued event of one type and returns how many were
// removed. The daemon uses it when the cloud stops advertising support for an
// optional event type, so those events cannot stall the queue as rejections.
func (queue *MetadataQueue) DropType(eventType MetadataEventType) (int, error) {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	document, err := queue.load()
	if err != nil {
		return 0, err
	}
	remaining := document.Events[:0]
	dropped := 0
	for _, event := range document.Events {
		if event.Type == eventType {
			dropped++
			continue
		}
		remaining = append(remaining, event)
	}
	if dropped == 0 {
		return 0, nil
	}
	document.Events = remaining
	document.DroppedEvents += uint64(dropped)
	return dropped, queue.save(document)
}

func (queue *MetadataQueue) Summary() (map[string]any, error) {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	document, err := queue.load()
	if err != nil {
		return nil, err
	}
	if pruneMetadataQueue(&document, queue.now()) {
		if err := queue.save(document); err != nil {
			return nil, err
		}
	}
	var oldest *time.Time
	if len(document.Events) != 0 {
		value := document.Events[0].QueuedAt
		for _, event := range document.Events[1:] {
			if event.QueuedAt.Before(value) {
				value = event.QueuedAt
			}
		}
		oldest = &value
	}
	info, _ := os.Stat(filepath.Join(queue.Root, metadataQueueFile))
	var bytesOnDisk int64
	if info != nil {
		bytesOnDisk = info.Size()
	}
	return map[string]any{
		"event_count":           len(document.Events),
		"dropped_events":        document.DroppedEvents,
		"bytes_on_disk":         bytesOnDisk,
		"oldest_queued_at":      oldest,
		"max_queue_bytes":       MaxLocalMetadataBytes,
		"max_queue_age_seconds": int64(MaxMetadataQueueAge / time.Second),
	}, nil
}

func (client Client) SendMetadataBatch(ctx context.Context, request MetadataBatchRequest) (MetadataBatchResponse, error) {
	state, err := client.LoadState()
	if err != nil {
		return MetadataBatchResponse{}, err
	}
	identity, leaf, err := client.loadCurrentIdentity()
	if err != nil {
		return MetadataBatchResponse{}, err
	}
	if !leaf.NotAfter.After(client.now()) {
		return MetadataBatchResponse{}, errors.New("sensor certificate has expired")
	}
	httpClient, err := client.clientWithIdentity(identity)
	if err != nil {
		return MetadataBatchResponse{}, err
	}
	request.ProtocolVersion = ProtocolVersion
	request.SensorID = state.SensorID
	request.OrganizationID = state.OrganizationID
	var response MetadataBatchResponse
	if err := client.doCompressedJSONWithClientLimit(ctx, httpClient, http.MethodPost, state.CloudURL+"/connector/v1/metadata", request, &response, nil, MaxMetadataRequestBytes); err != nil {
		return MetadataBatchResponse{}, err
	}
	if !response.Accepted || response.ProtocolVersion != ProtocolVersion || response.AcknowledgedThrough != request.SequenceEnd {
		return MetadataBatchResponse{}, errors.New("cloud metadata acknowledgement is invalid")
	}
	return response, nil
}

func (queue *MetadataQueue) FlushOne(ctx context.Context, client Client) (bool, error) {
	state, err := client.LoadState()
	if err != nil {
		return false, err
	}
	batch, available, err := queue.NextBatch(state, MaxMetadataUploadEvents)
	if err != nil || !available {
		return false, err
	}
	response, err := client.SendMetadataBatch(ctx, batch)
	if err == nil {
		if err := queue.AckThrough(response.AcknowledgedThrough); err != nil {
			return false, err
		}
		return true, nil
	}
	if !permanentMetadataRejection(err) {
		return false, err
	}

	// A cloud-side schema rejection may be caused by one poison event. Retry the
	// queue head alone so valid events ahead of the poison record are preserved.
	single, available, singleErr := queue.NextBatch(state, 1)
	if singleErr != nil || !available {
		if singleErr != nil {
			return false, singleErr
		}
		return false, err
	}
	singleResponse, singleErr := client.SendMetadataBatch(ctx, single)
	if singleErr == nil {
		if err := queue.AckThrough(singleResponse.AcknowledgedThrough); err != nil {
			return false, err
		}
		return true, nil
	}
	if !permanentMetadataRejection(singleErr) {
		return false, singleErr
	}
	if err := queue.DropRejected(single.SequenceStart); err != nil {
		return false, err
	}
	return true, nil
}

func permanentMetadataRejection(err error) bool {
	var status HTTPStatusError
	return errors.As(err, &status) && status.StatusCode == http.StatusBadRequest
}

func (queue *MetadataQueue) load() (metadataQueueDocument, error) {
	if strings.TrimSpace(queue.Root) == "" {
		return metadataQueueDocument{}, errors.New("metadata queue root is required")
	}
	data, err := os.ReadFile(filepath.Join(queue.Root, metadataQueueFile))
	if errors.Is(err, os.ErrNotExist) {
		return metadataQueueDocument{SchemaVersion: metadataQueueSchema, NextSequence: 1, Events: []QueuedMetadataEvent{}}, nil
	}
	if err != nil {
		return metadataQueueDocument{}, err
	}
	if len(data) > MaxLocalMetadataBytes+1 {
		return metadataQueueDocument{}, errors.New("metadata queue exceeds 32 MiB")
	}
	var document metadataQueueDocument
	if err := json.Unmarshal(data, &document); err != nil {
		return metadataQueueDocument{}, fmt.Errorf("decode metadata queue: %w", err)
	}
	if document.SchemaVersion != metadataQueueSchema || len(document.Events) > MaxLocalMetadataEvents {
		return metadataQueueDocument{}, errors.New("metadata queue schema or event count is invalid")
	}
	if document.NextSequence == 0 {
		document.NextSequence = 1
	}
	return document, nil
}

func (queue *MetadataQueue) save(document metadataQueueDocument) error {
	document.SchemaVersion = metadataQueueSchema
	pruneMetadataQueue(&document, queue.now())
	encoded, err := encodeBoundedMetadataQueue(&document, MaxLocalMetadataBytes-1)
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(queue.Root, metadataQueueFile), append(encoded, '\n'), 0o600)
}

func pruneMetadataQueue(document *metadataQueueDocument, now time.Time) bool {
	sort.Slice(document.Events, func(i, j int) bool { return document.Events[i].Sequence < document.Events[j].Sequence })
	drop := 0
	cutoff := now.Add(-MaxMetadataQueueAge)
	for index, event := range document.Events {
		if event.QueuedAt.IsZero() || event.QueuedAt.Before(cutoff) || event.ObservedAt.IsZero() || event.ObservedAt.Before(cutoff) {
			drop = index + 1
		}
	}
	if remaining := len(document.Events) - drop; remaining > MaxLocalMetadataEvents {
		drop += remaining - MaxLocalMetadataEvents
	}
	if drop == 0 {
		return false
	}
	document.Events = append([]QueuedMetadataEvent(nil), document.Events[drop:]...)
	document.DroppedEvents += uint64(drop)
	return true
}

func encodeBoundedMetadataQueue(document *metadataQueueDocument, maximum int) ([]byte, error) {
	if maximum < 1024 {
		return nil, errors.New("metadata queue serialization limit is invalid")
	}
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil || len(encoded) <= maximum {
		return encoded, err
	}
	if len(document.Events) == 0 {
		return nil, errors.New("metadata queue metadata exceeds its byte limit")
	}
	low, high := 1, len(document.Events)
	for low < high {
		middle := low + (high-low)/2
		candidate := *document
		candidate.Events = document.Events[middle:]
		candidate.DroppedEvents += uint64(middle)
		data, marshalErr := json.MarshalIndent(candidate, "", "  ")
		if marshalErr != nil {
			return nil, marshalErr
		}
		if len(data) <= maximum {
			high = middle
		} else {
			low = middle + 1
		}
	}
	document.Events = append([]QueuedMetadataEvent(nil), document.Events[low:]...)
	document.DroppedEvents += uint64(low)
	encoded, err = json.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, err
	}
	if len(encoded) > maximum {
		return nil, errors.New("metadata queue cannot satisfy its byte limit")
	}
	return encoded, nil
}

func metadataEventExists(events []QueuedMetadataEvent, eventID string) bool {
	for _, event := range events {
		if event.EventID == eventID {
			return true
		}
	}
	return false
}

func allowedMetadataEventType(value MetadataEventType) bool {
	switch value {
	case MetadataDeviceUpsert, MetadataFlowSummary, MetadataDNSEvent, MetadataTLSEvent, MetadataCaptureSummary, MetadataProtocolSummary:
		return true
	default:
		return false
	}
}

func randomMetadataID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return "event_" + hex.EncodeToString(value), nil
}

func (queue *MetadataQueue) now() time.Time {
	if queue.Now != nil {
		return queue.Now().UTC()
	}
	return time.Now().UTC()
}

func decodeMetadataEnqueue(r io.Reader, maximum int64) ([]LocalMetadataEvent, error) {
	limited := io.LimitReader(r, maximum+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximum {
		return nil, errors.New("metadata enqueue request exceeds maximum size")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var request struct {
		Events []LocalMetadataEvent `json:"events"`
	}
	if err := decoder.Decode(&request); err != nil {
		return nil, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("metadata enqueue request must contain exactly one JSON value")
	}
	return request.Events, nil
}
