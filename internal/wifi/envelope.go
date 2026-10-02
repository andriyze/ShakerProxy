package wifi

import (
	"encoding/json"
	"errors"
	"time"
)

const (
	// SourceVersion and ParserVersion identify the worker's events.
	SourceVersion   = "shakerproxy-wifi-worker-1"
	ParserVersion   = "shakerproxy-wifi-v1"
	maxPayloadBytes = 8 << 10
)

type envelope struct {
	Schema        int             `json:"schema"`
	EventID       string          `json:"event_id"`
	Source        string          `json:"source"`
	Kind          string          `json:"kind"`
	OccurredAt    time.Time       `json:"occurred_at"`
	SourceVersion string          `json:"source_version"`
	ParserVersion string          `json:"parser_version"`
	Confidence    int             `json:"confidence"`
	Payload       json.RawMessage `json:"payload"`
}

// KnownKind reports a Wi-Fi event kind.
func KnownKind(kind string) bool {
	for _, known := range Kinds {
		if kind == known {
			return true
		}
	}
	return false
}

// Encode writes the event as a HOST ingest event with the given ID.
func (e Event) Encode(id string) ([]byte, error) {
	if !KnownKind(e.Kind) || e.At.IsZero() || e.Payload.Scope != ScopeLab && e.Payload.Scope != ScopeNearby {
		return nil, errors.New("Wi-Fi event is incomplete")
	}
	payload, err := json.Marshal(e.Payload)
	if err != nil {
		return nil, err
	}
	if len(payload) > maxPayloadBytes {
		return nil, errors.New("Wi-Fi event payload exceeds its bound")
	}
	return json.Marshal(envelope{
		Schema: 1, EventID: id, Source: "HOST", Kind: e.Kind, OccurredAt: e.At.UTC(),
		SourceVersion: SourceVersion, ParserVersion: ParserVersion, Confidence: 100, Payload: payload,
	})
}
