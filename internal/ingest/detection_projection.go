package ingest

import (
	"bytes"
	"encoding/json"
	"io"
	"regexp"
	"strings"
	"time"
)

var detectionScopePattern = regexp.MustCompile(`^[A-Za-z0-9_.:/=@-]{1,256}$`)

type DetectionProjection struct {
	Type     string
	Severity string
	State    string
	Summary  string
	Scope    string
}

func ProjectDetectionFields(envelope Envelope) DetectionProjection {
	if envelope.Source != SourceHost || !strings.HasPrefix(envelope.Kind, "shakerproxy.detection.") {
		return DetectionProjection{}
	}
	var event struct {
		Schema      int       `json:"schema"`
		ID          string    `json:"id"`
		Type        string    `json:"type"`
		Severity    string    `json:"severity"`
		State       string    `json:"state"`
		Summary     string    `json:"summary"`
		Scope       string    `json:"scope"`
		FirstSeenAt time.Time `json:"first_seen_at"`
		LastSeenAt  time.Time `json:"last_seen_at"`
		Revision    uint64    `json:"revision"`
	}
	decoder := json.NewDecoder(bytes.NewReader(envelope.Payload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&event) != nil || decoder.Decode(&struct{}{}) != io.EOF || event.Schema != 1 || event.ID != envelope.EventID || event.Revision == 0 || event.FirstSeenAt.IsZero() || event.LastSeenAt.IsZero() || !event.LastSeenAt.Equal(envelope.OccurredAt) || event.LastSeenAt.Before(event.FirstSeenAt) || !validDetectionType(event.Type) || !validDetectionSeverity(event.Severity) || !validDetectionState(event.State) || !validText(event.Summary, 1, 256) || !detectionScopePattern.MatchString(event.Scope) {
		return DetectionProjection{}
	}
	return DetectionProjection{Type: event.Type, Severity: event.Severity, State: event.State, Summary: event.Summary, Scope: event.Scope}
}

func validDetectionType(value string) bool {
	switch value {
	case "ROGUE_DHCP", "ROGUE_RA", "GATEWAY_SPOOF_SUSPECTED", "CLOCK_DRIFT", "CAPTURE_DEGRADED", "STORAGE_PRESSURE", "CPU_PRESSURE", "MEMORY_PRESSURE", "CLEARTEXT_CREDENTIAL":
		return true
	}
	return false
}

func validDetectionSeverity(value string) bool {
	return value == "WARNING" || value == "HIGH" || value == "CRITICAL"
}

func validDetectionState(value string) bool {
	return value == "OPEN" || value == "RESOLVED"
}
