// Package hostevents encodes the HOST ingest events the gateway writes into
// the host event spool it shares with shakerproxy-dnsd.
package hostevents

import (
	"encoding/json"
	"errors"
	"time"

	"shakerproxy.dev/shakerproxy/internal/nflog"
	"shakerproxy.dev/shakerproxy/internal/trafficpolicy"
)

const (
	// BlockedKind is the Traffic event of a connection ShakerProxy refused:
	// DNS over TLS/QUIC, or a known DNS-over-HTTPS resolver.
	BlockedKind = "shakerproxy.blocked"
	// DefaultSpool is shared with shakerproxy-dnsd; the dns-event-forwarder
	// delivers both to ingest.
	DefaultSpool = "/var/lib/shakerproxy/dns-events/pending"

	blockedSourceVersion = "shakerproxy-gatewayd-1"
	blockedParserVersion = "shakerproxy-blocked-v1"
)

// BlockedPayload describes one refused connection attempt.
type BlockedPayload struct {
	SourceIP        string `json:"source_ip"`
	SourcePort      int    `json:"source_port,omitempty"`
	DestinationIP   string `json:"destination_ip"`
	DestinationPort int    `json:"destination_port,omitempty"`
	Protocol        string `json:"protocol,omitempty"`
	Service         string `json:"service"`
	Blocked         bool   `json:"blocked"`
	// Reason is one of trafficpolicy.BlockReason*.
	Reason string `json:"reason"`
	// Resolver names the catalog resolver at the destination, if known.
	Resolver string `json:"resolver,omitempty"`
}

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

// BlockedEvent encodes one blocked attempt as a HOST ingest event.
func BlockedEvent(id string, at time.Time, flow nflog.Flow, reason string) ([]byte, error) {
	if !flow.Source.IsValid() || !flow.Destination.IsValid() || reason == "" {
		return nil, errors.New("blocked attempt has no addresses or reason")
	}
	resolver := ""
	if classification := trafficpolicy.Classify(flow.Destination.String(), "", int(flow.DestinationPort), flow.Protocol == "udp", ""); classification.Detected {
		resolver = classification.Provider
	}
	payload, err := json.Marshal(BlockedPayload{
		SourceIP: flow.Source.Unmap().String(), SourcePort: int(flow.SourcePort),
		DestinationIP: flow.Destination.Unmap().String(), DestinationPort: int(flow.DestinationPort),
		Protocol: flow.Protocol, Service: "dns", Blocked: true, Reason: reason, Resolver: resolver,
	})
	if err != nil {
		return nil, err
	}
	return json.Marshal(envelope{
		Schema: 1, EventID: id, Source: "HOST", Kind: BlockedKind, OccurredAt: at.UTC(),
		SourceVersion: blockedSourceVersion, ParserVersion: blockedParserVersion, Confidence: 100, Payload: payload,
	})
}
