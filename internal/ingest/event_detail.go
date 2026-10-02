package ingest

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
)

const EventDetailSchemaVersion = 1

var ErrEventNotFound = errors.New("normalized event was not found")

type EventDetail struct {
	Schema       int             `json:"schema"`
	Event        RecentEvent     `json:"event"`
	Payload      json.RawMessage `json:"payload"`
	PayloadBytes int             `json:"payload_bytes"`
}

type EventDetailReader interface {
	GetEventDetail(context.Context, string) (EventDetail, error)
}

// wireEventPayload returns a stored payload exactly as encoding/json writes
// it inside a response: compacted, with <, > and & escaped. PostgreSQL
// renders jsonb with spaces after ':' and ',', so PayloadBytes measured on
// that text never matched the payload the services send, and every consumer
// rejected every event detail as invalid.
func wireEventPayload(stored []byte) (json.RawMessage, error) {
	encoded, err := json.Marshal(json.RawMessage(stored))
	if err != nil {
		return nil, err
	}
	return encoded, nil
}

func (detail EventDetail) Validate() error {
	if detail.Schema != EventDetailSchemaVersion || !validRecordID(detail.Event.RecordID) {
		return errors.New("event detail identity is invalid")
	}
	if len(detail.Payload) == 0 || len(detail.Payload) > MaxPayloadBytes || detail.PayloadBytes != len(detail.Payload) || !json.Valid(detail.Payload) {
		return errors.New("event detail payload is invalid")
	}
	return nil
}

func (s PostgresSink) GetEventDetail(ctx context.Context, recordID string) (EventDetail, error) {
	if s.DB == nil {
		return EventDetail{}, errors.New("PostgreSQL connection is required")
	}
	if !validRecordID(recordID) {
		return EventDetail{}, errors.New("event record ID is invalid")
	}
	// A repeatable-read snapshot keeps the metadata and payload views coherent
	// without taking a table-wide lock that could stall ingestion on busy TVs or
	// mobile devices while an operator opens the inspector.
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return EventDetail{}, fmt.Errorf("begin normalized event detail query: %w", err)
	}
	defer tx.Rollback()
	events, err := readEvents(ctx, tx, eventSelect+" WHERE record_id = $1 ORDER BY occurred_at DESC LIMIT 2", []any{recordID}, "detail")
	if err != nil {
		return EventDetail{}, err
	}
	if len(events) == 0 {
		return EventDetail{}, ErrEventNotFound
	}
	if len(events) != 1 {
		return EventDetail{}, errors.New("normalized event identity is not unique")
	}
	var payload []byte
	if err := tx.QueryRowContext(ctx, "SELECT payload::text FROM normalized_events WHERE record_id = $1 ORDER BY occurred_at DESC LIMIT 1", recordID).Scan(&payload); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return EventDetail{}, ErrEventNotFound
		}
		return EventDetail{}, fmt.Errorf("read normalized event payload: %w", err)
	}
	detail, err := newEventDetail(events[0], payload)
	if err != nil {
		return EventDetail{}, err
	}
	if err := tx.Commit(); err != nil {
		return EventDetail{}, fmt.Errorf("commit normalized event detail query: %w", err)
	}
	return detail, nil
}

// newEventDetail builds the detail from a stored payload as PostgreSQL
// renders it (payload::text).
func newEventDetail(event RecentEvent, stored []byte) (EventDetail, error) {
	if len(stored) == 0 || !json.Valid(stored) {
		return EventDetail{}, errors.New("stored normalized event payload is invalid")
	}
	wire, err := wireEventPayload(stored)
	if err != nil || len(wire) > MaxPayloadBytes {
		return EventDetail{}, errors.New("stored normalized event payload is invalid")
	}
	detail := EventDetail{Schema: EventDetailSchemaVersion, Event: event, Payload: wire, PayloadBytes: len(wire)}
	if err := detail.Validate(); err != nil {
		return EventDetail{}, err
	}
	return detail, nil
}
