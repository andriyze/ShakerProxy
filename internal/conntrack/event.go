package conntrack

import (
	"encoding/json"
	"errors"
	"time"
)

const (
	// EventKind is the ingest kind of a connection a lab device opened. The
	// host event forwarder accepts it from the DNS event spool next to
	// lookups.
	EventKind          = "shakerproxy.conn"
	eventSourceVersion = "shakerproxy-gatewayd-conntrack-1"
	eventParserVersion = "shakerproxy-conn-v1"
)

type eventEnvelope struct {
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

type eventPayload struct {
	SourceIP        string `json:"source_ip"`
	SourcePort      int    `json:"source_port,omitempty"`
	DestinationIP   string `json:"destination_ip"`
	DestinationPort int    `json:"destination_port,omitempty"`
	Protocol        string `json:"protocol"`
}

// EncodeEvent encodes a new connection as an ingest event envelope (source
// HOST, kind shakerproxy.conn). Ingest attributes the device from the client
// address and names the destination from the client's own DNS answers.
func EncodeEvent(id string, at time.Time, event Event) ([]byte, error) {
	if !event.Source.Addr().IsValid() || !event.Destination.Addr().IsValid() || event.Protocol == "" {
		return nil, errors.New("connection has no endpoints or protocol")
	}
	payload, err := json.Marshal(eventPayload{
		SourceIP: event.Source.Addr().String(), SourcePort: int(event.Source.Port()),
		DestinationIP: event.Destination.Addr().String(), DestinationPort: int(event.Destination.Port()),
		Protocol: event.Protocol,
	})
	if err != nil {
		return nil, err
	}
	return json.Marshal(eventEnvelope{
		Schema: 1, EventID: id, Source: "HOST", Kind: EventKind, OccurredAt: at.UTC(),
		SourceVersion: eventSourceVersion, ParserVersion: eventParserVersion, Confidence: 100, Payload: payload,
	})
}
