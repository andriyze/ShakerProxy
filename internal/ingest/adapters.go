package ingest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"shakerproxy.dev/shakerproxy/internal/capture"
)

const (
	ZeekParserVersion     = "shakerproxy-zeek-json-v1"
	SuricataParserVersion = "shakerproxy-suricata-eve-v1"
)

var zeekUIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,96}$`)

func NormalizeZeekJSON(raw []byte, sourceVersion, captureSessionID string) (Envelope, error) {
	fields, compact, err := adapterFields(raw, sourceVersion, captureSessionID)
	if err != nil {
		return Envelope{}, err
	}
	path, err := stringField(fields, "_path", 1, 128)
	if err != nil {
		return Envelope{}, errors.New("Zeek event path is missing or invalid")
	}
	tsRaw, ok := fields["ts"]
	if !ok {
		return Envelope{}, errors.New("Zeek event timestamp is missing")
	}
	var timestamp json.Number
	decoder := json.NewDecoder(bytes.NewReader(tsRaw))
	decoder.UseNumber()
	if decoder.Decode(&timestamp) != nil {
		return Envelope{}, errors.New("Zeek event timestamp is invalid")
	}
	seconds, err := strconv.ParseFloat(timestamp.String(), 64)
	if err != nil || math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds < 946684800 || seconds > 32503680000 {
		return Envelope{}, errors.New("Zeek event timestamp is invalid")
	}
	whole, fraction := math.Modf(seconds)
	occurred := time.Unix(int64(whole), int64(math.Round(fraction*1e9))).UTC()
	digest := sha256.Sum256(append([]byte("ZEEK\x00"), compact...))
	envelope := Envelope{Schema: SchemaVersion, EventID: "zeek-" + hex.EncodeToString(digest[:]), Source: SourceZeek, Kind: "zeek." + path, OccurredAt: occurred, SourceVersion: sourceVersion, ParserVersion: ZeekParserVersion, CaptureSessionID: captureSessionID, Confidence: 80, Payload: compact}
	if uid, uidErr := stringField(fields, "uid", 1, 96); uidErr == nil && zeekUIDPattern.MatchString(uid) && opaqueIDPattern.MatchString("flow-zeek-"+uid) {
		envelope.FlowID = "flow-zeek-" + uid
	}
	if err := envelope.Validate(); err != nil {
		return Envelope{}, err
	}
	return envelope, nil
}

func NormalizeSuricataEVE(raw []byte, sourceVersion, captureSessionID string) (Envelope, error) {
	fields, compact, err := adapterFields(raw, sourceVersion, captureSessionID)
	if err != nil {
		return Envelope{}, err
	}
	eventType, err := stringField(fields, "event_type", 1, 128)
	if err != nil {
		return Envelope{}, errors.New("Suricata event type is missing or invalid")
	}
	timestamp, err := stringField(fields, "timestamp", 1, 64)
	if err != nil {
		return Envelope{}, errors.New("Suricata event timestamp is missing or invalid")
	}
	occurred, err := parseSuricataTime(timestamp)
	if err != nil || occurred.Year() < 2000 || occurred.Year() > 3000 {
		return Envelope{}, errors.New("Suricata event timestamp is invalid")
	}
	digest := sha256.Sum256(append([]byte("SURICATA\x00"), compact...))
	envelope := Envelope{Schema: SchemaVersion, EventID: "suricata-" + hex.EncodeToString(digest[:]), Source: SourceSuricata, Kind: "suricata." + eventType, OccurredAt: occurred.UTC(), SourceVersion: sourceVersion, ParserVersion: SuricataParserVersion, CaptureSessionID: captureSessionID, Confidence: 85, Payload: compact}
	if rawFlow, ok := fields["flow_id"]; ok {
		flowText := strings.Trim(string(rawFlow), `"`)
		// A flow correlation hint must never make an otherwise valid event
		// unacceptable, so identifiers too short for the envelope are dropped.
		if _, parseErr := strconv.ParseUint(flowText, 10, 64); parseErr == nil && opaqueIDPattern.MatchString("flow-suricata-"+flowText) {
			envelope.FlowID = "flow-suricata-" + flowText
		}
	}
	if err := envelope.Validate(); err != nil {
		return Envelope{}, err
	}
	return envelope, nil
}

func adapterFields(raw []byte, sourceVersion, captureSessionID string) (map[string]json.RawMessage, json.RawMessage, error) {
	if len(raw) == 0 || len(raw) > MaxPayloadBytes || !validText(sourceVersion, 1, MaxTextBytes) {
		return nil, nil, errors.New("adapter input or source version is invalid")
	}
	if captureSessionID != "" && !capture.ValidSessionID(captureSessionID) {
		return nil, nil, errors.New("adapter capture session ID is invalid")
	}
	compactBuffer := bytes.NewBuffer(make([]byte, 0, len(raw)))
	if json.Compact(compactBuffer, raw) != nil || compactBuffer.Len() > MaxPayloadBytes {
		return nil, nil, errors.New("adapter input is not bounded JSON")
	}
	compact := append(json.RawMessage(nil), compactBuffer.Bytes()...)
	var fields map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(compact))
	if err := decoder.Decode(&fields); err != nil || fields == nil {
		return nil, nil, errors.New("adapter input must be a JSON object")
	}
	return fields, compact, nil
}

func stringField(fields map[string]json.RawMessage, name string, min, max int) (string, error) {
	raw, ok := fields[name]
	if !ok {
		return "", errors.New("missing field")
	}
	var value string
	if json.Unmarshal(raw, &value) != nil || !validText(value, min, max) {
		return "", errors.New("invalid field")
	}
	return value, nil
}

func parseSuricataTime(value string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999-0700"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed, nil
		}
	}
	return time.Time{}, fmt.Errorf("unsupported Suricata timestamp")
}
