package ingest

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"time"

	"shakerproxy.dev/shakerproxy/internal/capture"
)

const (
	SchemaVersion   = 1
	MaxEventBytes   = 256 << 10
	MaxPayloadBytes = 192 << 10
	// MaxAdapterBatchBytes bounds one NDJSON batch from an analyzer.
	MaxAdapterBatchBytes = 8 << 20
	MaxTextBytes         = 256
	DefaultSpoolBytes    = int64(1 << 30)
	DefaultReserve       = uint64(1 << 30)
	MaxPendingRecords    = 100000
	MaxQuarantineBytes   = 4096
)

type Source string

const (
	SourceHost      Source = "HOST"
	SourceZeek      Source = "ZEEK"
	SourceSuricata  Source = "SURICATA"
	SourceMitmproxy Source = "MITMPROXY"
)

var opaqueIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
var deviceIDPattern = regexp.MustCompile(`^device-[a-f0-9]{32}$`)

type Envelope struct {
	Schema           int             `json:"schema"`
	EventID          string          `json:"event_id"`
	Source           Source          `json:"source"`
	Kind             string          `json:"kind"`
	OccurredAt       time.Time       `json:"occurred_at"`
	SourceVersion    string          `json:"source_version"`
	ParserVersion    string          `json:"parser_version"`
	CaptureSessionID string          `json:"capture_session_id,omitempty"`
	FlowID           string          `json:"flow_id,omitempty"`
	DeviceID         string          `json:"device_id,omitempty"`
	Confidence       int             `json:"confidence,omitempty"`
	Payload          json.RawMessage `json:"payload"`
}

type Record struct {
	Schema      int       `json:"schema"`
	ReceivedAt  time.Time `json:"received_at"`
	EventSHA256 string    `json:"event_sha256"`
	Envelope    Envelope  `json:"event"`
}

type PendingRecord struct {
	RecordID string `json:"record_id"`
	Record   Record `json:"record"`
}

type DrainResult struct {
	Attempted int `json:"attempted"`
	Committed int `json:"committed"`
	// Rejected records were moved to the spool's rejected directory and Purged
	// records (deleted captures or selections) were discarded; both are removed
	// from the pending queue so the rest of the backlog can make progress.
	Rejected       int    `json:"rejected,omitempty"`
	Purged         int    `json:"purged,omitempty"`
	SetAsideReason string `json:"set_aside_reason,omitempty"`
}

type QuarantineRecord struct {
	Schema       int       `json:"schema"`
	ReceivedAt   time.Time `json:"received_at"`
	InputSHA256  string    `json:"input_sha256"`
	Reason       string    `json:"reason"`
	PrefixBase64 string    `json:"prefix_base64,omitempty"`
}

type AcceptResult struct {
	Accepted    bool   `json:"accepted"`
	Duplicate   bool   `json:"duplicate"`
	Quarantined bool   `json:"quarantined"`
	RecordID    string `json:"record_id"`
	Reason      string `json:"reason,omitempty"`
}

type Stats struct {
	Schema             int       `json:"schema"`
	GeneratedAt        time.Time `json:"generated_at"`
	PendingRecords     int       `json:"pending_records"`
	PendingBytes       int64     `json:"pending_bytes"`
	QuarantinedRecords int       `json:"quarantined_records"`
	QuarantinedBytes   int64     `json:"quarantined_bytes"`
	OldestPendingAt    time.Time `json:"oldest_pending_at,omitempty"`
	IngestLagSeconds   float64   `json:"ingest_lag_seconds"`
	StoragePressure    bool      `json:"storage_pressure"`
	DatabaseConfigured bool      `json:"database_configured"`
	DatabaseConnected  bool      `json:"database_connected"`
}

func DecodeEnvelope(raw []byte) (Envelope, error) {
	if len(raw) == 0 || len(raw) > MaxEventBytes {
		return Envelope{}, errors.New("event exceeds its byte limit")
	}
	var envelope Envelope
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return Envelope{}, errors.New("event does not match the versioned envelope")
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return Envelope{}, errors.New("event contains multiple JSON values")
	}
	if err := envelope.Validate(); err != nil {
		return Envelope{}, err
	}
	compact := bytes.NewBuffer(make([]byte, 0, len(envelope.Payload)))
	if err := json.Compact(compact, envelope.Payload); err != nil || compact.Len() > MaxPayloadBytes {
		return Envelope{}, errors.New("event payload is invalid or exceeds its byte limit")
	}
	envelope.Payload = append(json.RawMessage(nil), compact.Bytes()...)
	return envelope, nil
}

func (e Envelope) Validate() error {
	if e.Schema != SchemaVersion || !opaqueIDPattern.MatchString(e.EventID) {
		return errors.New("event schema or ID is invalid")
	}
	switch e.Source {
	case SourceHost, SourceZeek, SourceSuricata, SourceMitmproxy:
	default:
		return errors.New("event source is unsupported")
	}
	for label, value := range map[string]string{"kind": e.Kind, "source version": e.SourceVersion, "parser version": e.ParserVersion} {
		if !validText(value, 1, MaxTextBytes) {
			return errors.New(label + " is invalid")
		}
	}
	if e.OccurredAt.IsZero() || e.OccurredAt.Year() < 2000 || e.OccurredAt.Year() > 3000 {
		return errors.New("event timestamp is invalid")
	}
	if e.CaptureSessionID != "" && !capture.ValidSessionID(e.CaptureSessionID) {
		return errors.New("capture session ID is invalid")
	}
	if e.FlowID != "" && !opaqueIDPattern.MatchString(e.FlowID) {
		return errors.New("flow ID is invalid")
	}
	if e.DeviceID != "" && !deviceIDPattern.MatchString(e.DeviceID) {
		return errors.New("device ID is invalid")
	}
	if e.Confidence < 0 || e.Confidence > 100 {
		return errors.New("event confidence is invalid")
	}
	if len(e.Payload) == 0 || len(e.Payload) > MaxPayloadBytes || !json.Valid(e.Payload) {
		return errors.New("event payload is invalid or exceeds its byte limit")
	}
	return nil
}

func validText(value string, min, max int) bool {
	if len(value) < min || len(value) > max || value != strings.TrimSpace(value) {
		return false
	}
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			return false
		}
	}
	return true
}
