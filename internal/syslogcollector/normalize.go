package syslogcollector

import (
	"time"

	"shakerproxy.dev/shakerproxy/internal/ingest"
)

// Normalize turns a recognized record and the source address of the device
// that sent it into a normalized ingest envelope. The source address is
// recorded in the payload so the Integrations status and the event can show
// which device reported it.
func Normalize(record Record, syslogSource string, occurredAt time.Time) (ingest.Envelope, error) {
	payload := map[string]any{}
	for key, value := range record.Payload {
		payload[key] = value
	}
	if syslogSource != "" {
		payload["reported_by"] = syslogSource
	}
	return ingest.NormalizeNetworkGearEvent(record.Kind, occurredAt, payload)
}
