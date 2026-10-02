package ingest

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"shakerproxy.dev/shakerproxy/internal/capture"
	"shakerproxy.dev/shakerproxy/internal/querylang"
)

const (
	MaxRecentEventLimit = 100
	MaxEventFacetInput  = 10_000
	MaxEventFacetValues = 12
	// The Domains facet groups host names by registrable domain.
	MaxEventDomainValues            = 15
	MaxEventDomainHosts             = 5
	maxEventDomainHostRows          = 500
	internalNameResolutionParameter = "_device_name_ids"
	internalTagResolutionParameter  = "_device_tag_ids"
	internalQueryAnchorParameter    = "_query_anchor"
	maxInternalNameResolutionBytes  = 16 << 10
	internalNameResolutionSchema    = 1
)

type RecentEvent struct {
	RecordID                         string               `json:"record_id"`
	Source                           Source               `json:"source"`
	Kind                             string               `json:"kind"`
	OccurredAt                       time.Time            `json:"occurred_at"`
	ReceivedAt                       time.Time            `json:"received_at"`
	SourceVersion                    string               `json:"source_version"`
	ParserVersion                    string               `json:"parser_version"`
	CaptureSessionID                 string               `json:"capture_session_id,omitempty"`
	FlowID                           string               `json:"flow_id,omitempty"`
	DeviceID                         string               `json:"device_id,omitempty"`
	DeviceFriendlyName               string               `json:"device_friendly_name,omitempty"`
	DeviceFriendlyNameAtCapture      string               `json:"device_friendly_name_at_capture,omitempty"`
	DeviceFriendlyNameAtCaptureKnown bool                 `json:"device_friendly_name_at_capture_known"`
	DeviceAliasRevision              uint64               `json:"device_alias_revision,omitempty"`
	DeviceFriendlyNameConflict       bool                 `json:"device_friendly_name_conflict,omitempty"`
	AttributionEvidence              *AttributionEvidence `json:"attribution_evidence,omitempty"`
	Confidence                       int                  `json:"confidence"`
	SourceIP                         string               `json:"source_ip,omitempty"`
	DestinationIP                    string               `json:"destination_ip,omitempty"`
	SourcePort                       int                  `json:"source_port,omitempty"`
	DestinationPort                  int                  `json:"destination_port,omitempty"`
	Protocol                         string               `json:"protocol,omitempty"`
	Service                          string               `json:"service,omitempty"`
	NetworkBytes                     int64                `json:"network_bytes,omitempty"`
	DNSQuery                         string               `json:"dns_query,omitempty"`
	DNSRecordType                    string               `json:"dns_record_type,omitempty"`
	DNSResponseCode                  string               `json:"dns_response_code,omitempty"`
	DNSAnswerCount                   *int                 `json:"dns_answer_count,omitempty"`
	DNSAnswers                       []string             `json:"dns_answers,omitempty"`
	// Blocked is set for lookups ShakerProxy refused (NXDOMAIN on purpose)
	// and connections the gateway refused; BlockedReason says why
	// (trafficpolicy.BlockReason*).
	Blocked                bool   `json:"blocked,omitempty"`
	BlockedReason          string `json:"blocked_reason,omitempty"`
	DetectionType          string `json:"detection_type,omitempty"`
	DetectionSeverity      string `json:"detection_severity,omitempty"`
	DetectionState         string `json:"detection_state,omitempty"`
	DetectionSummary       string `json:"detection_summary,omitempty"`
	DetectionScope         string `json:"detection_scope,omitempty"`
	TLSServerName          string `json:"tls_server_name,omitempty"`
	TLSInterceptionState   string `json:"tls_interception_state,omitempty"`
	TLSFailureReason       string `json:"tls_failure_reason,omitempty"`
	TLSPinningSuspected    bool   `json:"tls_pinning_suspected,omitempty"`
	TLSClientRecentSuccess *bool  `json:"tls_client_recent_success,omitempty"`
	TLSBypassActivated     bool   `json:"tls_bypass_activated,omitempty"`
	TLSPlatform            string `json:"tls_platform,omitempty"`
	AppProtocol            string `json:"app_protocol,omitempty"`
	ProtocolCategory       string `json:"protocol_category,omitempty"`
	ProtocolVisibility     string `json:"protocol_visibility,omitempty"`
	ProtocolEvidence       string `json:"protocol_evidence,omitempty"`
	ProtocolExotic         bool   `json:"protocol_exotic,omitempty"`
	HTTPMethod             string `json:"http_method,omitempty"`
	HTTPHost               string `json:"http_host,omitempty"`
	HTTPPath               string `json:"http_path,omitempty"`
	HTTPStatus             int    `json:"http_status,omitempty"`
	AlertSignature         string `json:"alert_signature,omitempty"`
	AlertSeverity          int    `json:"alert_severity,omitempty"`
	AlertCategory          string `json:"alert_category,omitempty"`
	// Summary is one plain-language line built by EventSummary.
	Summary string `json:"summary,omitempty"`
}

type RecentEventQuery struct {
	Limit            int
	Source           Source
	Kind             string
	CaptureSessionID string
	DeviceID         string
	BeforeOccurredAt time.Time
	BeforeRecordID   string
	TimeAnchor       time.Time
	Filter           querylang.Query
	// DeviceNameResolutions is populated only by the control plane after it
	// resolves current and retained historical aliases. Storage receives IDs,
	// never inventory names or inventory write authority.
	DeviceNameResolutions map[string][]string
	// DeviceTagResolutions follows the same boundary for normalized inventory
	// tags. Both selector classes share one association budget.
	DeviceTagResolutions map[string][]string
}

type deviceNameResolution struct {
	Reference string   `json:"ref"`
	DeviceIDs []string `json:"device_ids"`
}

type deviceNameResolutionEnvelope struct {
	Schema      int                    `json:"schema"`
	Resolutions []deviceNameResolution `json:"resolutions"`
}

type RecentEventPage struct {
	Schema                int           `json:"schema"`
	GeneratedAt           time.Time     `json:"generated_at"`
	Events                []RecentEvent `json:"events"`
	NextCursor            string        `json:"next_cursor,omitempty"`
	CanonicalQuery        string        `json:"canonical_query,omitempty"`
	QueryAnchor           time.Time     `json:"query_anchor,omitempty"`
	Facets                *EventFacets  `json:"facets,omitempty"`
	LiveCursor            string        `json:"live_cursor,omitempty"`
	DeviceLabelsAvailable bool          `json:"device_labels_available"`
}

type EventFacetValue struct {
	Value string `json:"value"`
	Count int64  `json:"count"`
}

type EventFacet struct {
	Field      string            `json:"field"`
	Values     []EventFacetValue `json:"values"`
	OtherCount int64             `json:"other_count"`
}

type EventFacets struct {
	Exact         bool         `json:"exact"`
	MatchedCount  int64        `json:"matched_count"`
	CountRelation string       `json:"count_relation"`
	Basis         string       `json:"basis"`
	Fields        []EventFacet `json:"fields"`
	// Domains is computed over the same events as Fields.
	Domains EventDomainFacet `json:"domains"`
}

// EventDomainFacet lists the internet domains the matching events name: DNS
// questions, TLS server names (SNI) and HTTP hosts, grouped by registrable
// domain ("connectivitycheck.grapheneos.network" counts toward
// "grapheneos.network"). Local names (.local, .arpa) and IP literals are left
// out.
type EventDomainFacet struct {
	Values []EventDomainValue `json:"values"`
	// OtherCount counts connections and lookups of domains not listed.
	OtherCount int64 `json:"other_count"`
}

// EventDomainValue counts the distinct connections and DNS lookups that named
// a domain. A connection seen by several analyzers (Zeek conn and ssl logs,
// Suricata, mitmproxy) or split across capture segments counts once.
type EventDomainValue struct {
	Domain string   `json:"domain"`
	Count  int64    `json:"count"`
	Hosts  []string `json:"hosts"`
}

type RecentEventReader interface {
	QueryRecent(context.Context, RecentEventQuery) (RecentEventPage, error)
}

type LiveEventQuery struct {
	RecentEventQuery
	AfterReceivedAt time.Time
	AfterRecordID   string
}

type LiveEventBatch struct {
	Schema                int           `json:"schema"`
	GeneratedAt           time.Time     `json:"generated_at"`
	Events                []RecentEvent `json:"events"`
	NextCursor            string        `json:"next_cursor"`
	CanonicalQuery        string        `json:"canonical_query,omitempty"`
	QueryAnchor           time.Time     `json:"query_anchor,omitempty"`
	DeviceLabelsAvailable bool          `json:"device_labels_available"`
}

type LiveEventReader interface {
	QueryAfter(context.Context, LiveEventQuery) (LiveEventBatch, error)
}

type StatusReader interface {
	IngestStatus(context.Context) (Stats, error)
}

func ParseRecentEventQuery(values url.Values) (RecentEventQuery, error) {
	allowed := map[string]bool{"limit": true, "source": true, "kind": true, "capture_session_id": true, "device_id": true, "cursor": true, "q": true}
	for key, entries := range values {
		if !allowed[key] || len(entries) != 1 {
			return RecentEventQuery{}, errors.New("event query contains an unsupported or repeated parameter")
		}
	}
	query := RecentEventQuery{Limit: 50}
	if raw := values.Get("limit"); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > MaxRecentEventLimit {
			return RecentEventQuery{}, errors.New("event query limit must be between 1 and 100")
		}
		query.Limit = limit
	}
	if raw := values.Get("source"); raw != "" {
		query.Source = Source(raw)
		switch query.Source {
		case SourceHost, SourceZeek, SourceSuricata, SourceMitmproxy:
		default:
			return RecentEventQuery{}, errors.New("event query source is unsupported")
		}
	}
	query.Kind = values.Get("kind")
	if query.Kind != "" && !validText(query.Kind, 1, MaxTextBytes) {
		return RecentEventQuery{}, errors.New("event query kind is invalid")
	}
	query.CaptureSessionID = values.Get("capture_session_id")
	if query.CaptureSessionID != "" && !capture.ValidSessionID(query.CaptureSessionID) {
		return RecentEventQuery{}, errors.New("event query capture session ID is invalid")
	}
	query.DeviceID = values.Get("device_id")
	if query.DeviceID != "" && !deviceIDPattern.MatchString(query.DeviceID) {
		return RecentEventQuery{}, errors.New("event query device ID is invalid")
	}
	filter, err := querylang.Parse(values.Get("q"))
	if err != nil {
		return RecentEventQuery{}, fmt.Errorf("event query language is invalid: %w", err)
	}
	query.Filter = filter
	if raw := values.Get("cursor"); raw != "" {
		cursor, err := decodeRecentEventCursor(raw)
		if err != nil {
			return RecentEventQuery{}, err
		}
		query.BeforeOccurredAt, query.BeforeRecordID, query.TimeAnchor = cursor.BeforeOccurredAt, cursor.RecordID, cursor.TimeAnchor
		hasRelativeTime := querylang.HasRelativeTime(query.Filter)
		if hasRelativeTime && query.TimeAnchor.IsZero() || !hasRelativeTime && !query.TimeAnchor.IsZero() {
			return RecentEventQuery{}, errors.New("event query cursor does not match its time filter")
		}
	}
	return query, nil
}

func ParseLiveEventQuery(values url.Values, defaultAfter time.Time) (LiveEventQuery, error) {
	return parseLiveEventQuery(values, defaultAfter, ParseRecentEventQuery)
}

// ParseInternalRecentEventQuery accepts the private selector-resolution and
// time-anchor parameters emitted by QueryClient. Public control-plane parsing
// deliberately rejects them.
func ParseInternalRecentEventQuery(values url.Values) (RecentEventQuery, error) {
	copyValues := cloneValues(values)
	nameEntries, namesPresent := copyValues[internalNameResolutionParameter]
	if namesPresent && len(nameEntries) != 1 {
		return RecentEventQuery{}, errors.New("internal event query contains a repeated name resolution")
	}
	copyValues.Del(internalNameResolutionParameter)
	tagEntries, tagsPresent := copyValues[internalTagResolutionParameter]
	if tagsPresent && len(tagEntries) != 1 {
		return RecentEventQuery{}, errors.New("internal event query contains a repeated tag resolution")
	}
	copyValues.Del(internalTagResolutionParameter)
	anchorEntries, anchorPresent := copyValues[internalQueryAnchorParameter]
	if anchorPresent && len(anchorEntries) != 1 {
		return RecentEventQuery{}, errors.New("internal event query contains a repeated query anchor")
	}
	copyValues.Del(internalQueryAnchorParameter)
	query, err := ParseRecentEventQuery(copyValues)
	if err != nil {
		return RecentEventQuery{}, err
	}
	if namesPresent {
		query.DeviceNameResolutions, err = decodeDeviceResolutions(nameEntries[0])
		if err != nil {
			return RecentEventQuery{}, err
		}
	}
	if tagsPresent {
		query.DeviceTagResolutions, err = decodeDeviceResolutions(tagEntries[0])
		if err != nil {
			return RecentEventQuery{}, err
		}
	}
	if anchorPresent {
		anchor, parseErr := parseQueryAnchor(anchorEntries[0])
		if parseErr != nil || !query.TimeAnchor.IsZero() && !query.TimeAnchor.Equal(anchor) {
			return RecentEventQuery{}, errors.New("internal event query anchor is invalid")
		}
		query.TimeAnchor = anchor
	}
	if err := validateInternalDeviceReferences(query); err != nil {
		return RecentEventQuery{}, err
	}
	if err := validateRecentEventQuery(query); err != nil {
		return RecentEventQuery{}, err
	}
	return query, nil
}

func validateInternalDeviceReferences(query RecentEventQuery) error {
	for index, reference := range querylang.DeviceNameValues(query.Filter) {
		if reference != fmt.Sprintf("alias-ref-%02d", index+1) {
			return errors.New("internal device friendly-name reference is invalid")
		}
	}
	for index, reference := range querylang.DeviceTagValues(query.Filter) {
		if reference != fmt.Sprintf("tag-ref-%02d", index+1) {
			return errors.New("internal device tag reference is invalid")
		}
	}
	return nil
}

func ParseInternalLiveEventQuery(values url.Values, defaultAfter time.Time) (LiveEventQuery, error) {
	return parseLiveEventQuery(values, defaultAfter, ParseInternalRecentEventQuery)
}

func parseLiveEventQuery(values url.Values, defaultAfter time.Time, parseBase func(url.Values) (RecentEventQuery, error)) (LiveEventQuery, error) {
	if entries, present := values["cursor"]; present && len(entries) != 1 {
		return LiveEventQuery{}, errors.New("live event query contains a repeated cursor")
	}
	copyValues := cloneValues(values)
	rawCursor := copyValues.Get("cursor")
	copyValues.Del("cursor")
	base, err := parseBase(copyValues)
	if err != nil {
		return LiveEventQuery{}, err
	}
	base.BeforeOccurredAt, base.BeforeRecordID = time.Time{}, ""
	query := LiveEventQuery{RecentEventQuery: base, AfterReceivedAt: defaultAfter.UTC(), AfterRecordID: strings.Repeat("0", 64)}
	if rawCursor != "" {
		cursor, decodeErr := decodeLiveEventCursor(rawCursor)
		err = decodeErr
		if err != nil {
			return LiveEventQuery{}, err
		}
		query.AfterReceivedAt, query.AfterRecordID = cursor.AfterReceivedAt, cursor.RecordID
		if !cursor.TimeAnchor.IsZero() {
			if !query.TimeAnchor.IsZero() && !query.TimeAnchor.Equal(cursor.TimeAnchor) {
				return LiveEventQuery{}, errors.New("live event query anchor does not match its cursor")
			}
			query.TimeAnchor = cursor.TimeAnchor
		}
		hasRelativeTime := querylang.HasRelativeTime(query.Filter)
		if hasRelativeTime && cursor.TimeAnchor.IsZero() || !hasRelativeTime && !cursor.TimeAnchor.IsZero() {
			return LiveEventQuery{}, errors.New("live event query cursor does not match its time filter")
		}
	}
	if query.AfterReceivedAt.Year() < 2000 || query.AfterReceivedAt.Year() > 3000 || !validRecordID(query.AfterRecordID) {
		return LiveEventQuery{}, errors.New("live event query cursor is invalid")
	}
	if querylang.HasRelativeTime(query.Filter) && query.TimeAnchor.IsZero() {
		query.TimeAnchor = defaultAfter.UTC()
	}
	return query, nil
}

func cloneValues(values url.Values) url.Values {
	cloned := make(url.Values, len(values))
	for key, entries := range values {
		cloned[key] = append([]string(nil), entries...)
	}
	return cloned
}

func validateLiveEventQuery(query LiveEventQuery) error {
	if err := validateRecentEventQuery(query.RecentEventQuery); err != nil {
		return err
	}
	if query.AfterReceivedAt.Year() < 2000 || query.AfterReceivedAt.Year() > 3000 || !validRecordID(query.AfterRecordID) {
		return errors.New("live event query cursor is invalid")
	}
	return nil
}

func EncodeLiveEventQuery(query LiveEventQuery) url.Values {
	values := EncodeRecentEventQuery(query.RecentEventQuery)
	values.Del("cursor")
	values.Set("cursor", encodeAnchoredLiveEventCursor(query.AfterReceivedAt, query.AfterRecordID, query.TimeAnchor))
	return values
}

func validateRecentEventQuery(query RecentEventQuery) error {
	if query.Limit < 1 || query.Limit > MaxRecentEventLimit {
		return errors.New("recent event query limit is invalid")
	}
	if query.Source != "" {
		switch query.Source {
		case SourceHost, SourceZeek, SourceSuricata, SourceMitmproxy:
		default:
			return errors.New("recent event query source is invalid")
		}
	}
	if query.Kind != "" && !validText(query.Kind, 1, MaxTextBytes) || query.CaptureSessionID != "" && !capture.ValidSessionID(query.CaptureSessionID) || query.DeviceID != "" && !deviceIDPattern.MatchString(query.DeviceID) {
		return errors.New("recent event query filter is invalid")
	}
	if query.BeforeOccurredAt.IsZero() != (query.BeforeRecordID == "") || !query.BeforeOccurredAt.IsZero() && (query.BeforeOccurredAt.Year() < 2000 || query.BeforeOccurredAt.Year() > 3000 || !validRecordID(query.BeforeRecordID)) {
		return errors.New("recent event query cursor is invalid")
	}
	hasRelativeTime := querylang.HasRelativeTime(query.Filter)
	if hasRelativeTime && !query.BeforeOccurredAt.IsZero() && query.TimeAnchor.IsZero() || !query.TimeAnchor.IsZero() && (query.TimeAnchor.Year() < 2000 || query.TimeAnchor.Year() > 3000 || !hasRelativeTime) {
		return errors.New("recent event query time anchor is invalid")
	}
	if query.Filter.Root == nil {
		if query.Filter.Canonical != "" || len(query.DeviceNameResolutions) != 0 || len(query.DeviceTagResolutions) != 0 {
			return errors.New("recent event typed filter is invalid")
		}
	} else {
		parsed, err := querylang.Parse(query.Filter.Canonical)
		if err != nil || parsed.Canonical != query.Filter.Canonical || !reflect.DeepEqual(parsed.Root, query.Filter.Root) {
			return errors.New("recent event typed filter is invalid")
		}
		nameValues := querylang.DeviceNameValues(parsed)
		tagValues := querylang.DeviceTagValues(parsed)
		if len(nameValues)+len(tagValues) > 32 {
			return errors.New("device selector query exceeds its operand bound")
		}
		if err := validateDeviceNameResolutions(nameValues, query.DeviceNameResolutions); err != nil {
			return err
		}
		if err := validateDeviceTagResolutions(tagValues, query.DeviceTagResolutions); err != nil {
			return err
		}
		if resolutionAssociationCount(query.DeviceNameResolutions)+resolutionAssociationCount(query.DeviceTagResolutions) > 256 {
			return errors.New("device selector resolution exceeds its shared bound")
		}
	}
	return nil
}

func validateDeviceNameResolutions(names []string, resolutions map[string][]string) error {
	return validateDeviceResolutions(names, resolutions, "friendly-name")
}

func validateDeviceTagResolutions(tags []string, resolutions map[string][]string) error {
	return validateDeviceResolutions(tags, resolutions, "tag")
}

func validateDeviceResolutions(values []string, resolutions map[string][]string, kind string) error {
	if len(values) != len(resolutions) || len(values) > 32 {
		return fmt.Errorf("device %s resolution is missing or invalid", kind)
	}
	for _, value := range values {
		ids, exists := resolutions[value]
		if !exists {
			return fmt.Errorf("device %s resolution is missing or invalid", kind)
		}
		for index, id := range ids {
			if !deviceIDPattern.MatchString(id) || index > 0 && ids[index-1] >= id {
				return fmt.Errorf("device %s resolution contains an invalid device ID", kind)
			}
		}
	}
	return nil
}

func resolutionAssociationCount(resolutions map[string][]string) int {
	total := 0
	for _, ids := range resolutions {
		total += len(ids)
	}
	return total
}

func EncodeRecentEventQuery(query RecentEventQuery) url.Values {
	values := make(url.Values)
	values.Set("limit", strconv.Itoa(query.Limit))
	if query.Source != "" {
		values.Set("source", string(query.Source))
	}
	if query.Kind != "" {
		values.Set("kind", query.Kind)
	}
	if query.CaptureSessionID != "" {
		values.Set("capture_session_id", query.CaptureSessionID)
	}
	if query.DeviceID != "" {
		values.Set("device_id", query.DeviceID)
	}
	if query.Filter.Root != nil {
		values.Set("q", query.Filter.Canonical)
	}
	if !query.BeforeOccurredAt.IsZero() {
		values.Set("cursor", encodeRecentEventCursor(query.BeforeOccurredAt, query.BeforeRecordID, query.TimeAnchor))
	}
	return values
}

func encodeInternalRecentEventQuery(query RecentEventQuery) (url.Values, error) {
	values := EncodeRecentEventQuery(query)
	if !query.TimeAnchor.IsZero() {
		values.Set(internalQueryAnchorParameter, query.TimeAnchor.UTC().Format(time.RFC3339Nano))
	}
	if len(query.DeviceNameResolutions) > 0 {
		encoded, err := encodeDeviceResolutions(query.DeviceNameResolutions)
		if err != nil {
			return nil, err
		}
		values.Set(internalNameResolutionParameter, encoded)
	}
	if len(query.DeviceTagResolutions) > 0 {
		encoded, err := encodeDeviceResolutions(query.DeviceTagResolutions)
		if err != nil {
			return nil, err
		}
		values.Set(internalTagResolutionParameter, encoded)
	}
	return values, nil
}

func encodeDeviceResolutions(resolutions map[string][]string) (string, error) {
	names := make([]string, 0, len(resolutions))
	for name := range resolutions {
		names = append(names, name)
	}
	sort.Strings(names)
	envelope := deviceNameResolutionEnvelope{Schema: internalNameResolutionSchema, Resolutions: make([]deviceNameResolution, 0, len(names))}
	for _, name := range names {
		envelope.Resolutions = append(envelope.Resolutions, deviceNameResolution{Reference: name, DeviceIDs: resolutions[name]})
	}
	raw, err := json.Marshal(envelope)
	if err != nil || len(raw) > maxInternalNameResolutionBytes {
		return "", errors.New("encode bounded device selector resolution")
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func encodeInternalLiveEventQuery(query LiveEventQuery) (url.Values, error) {
	values, err := encodeInternalRecentEventQuery(query.RecentEventQuery)
	if err != nil {
		return nil, err
	}
	values.Del("cursor")
	values.Set("cursor", encodeAnchoredLiveEventCursor(query.AfterReceivedAt, query.AfterRecordID, query.TimeAnchor))
	return values, nil
}

func decodeDeviceResolutions(encoded string) (map[string][]string, error) {
	if encoded == "" || len(encoded) > base64.RawURLEncoding.EncodedLen(maxInternalNameResolutionBytes) {
		return nil, errors.New("internal device selector resolution is invalid")
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(raw) > maxInternalNameResolutionBytes {
		return nil, errors.New("internal device selector resolution is invalid")
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	var envelope deviceNameResolutionEnvelope
	if err := decoder.Decode(&envelope); err != nil || decoder.Decode(&struct{}{}) != io.EOF || envelope.Schema != internalNameResolutionSchema || len(envelope.Resolutions) > 32 {
		return nil, errors.New("internal device selector resolution is invalid")
	}
	resolutions := make(map[string][]string, len(envelope.Resolutions))
	for _, resolution := range envelope.Resolutions {
		if resolution.Reference == "" {
			return nil, errors.New("internal device selector resolution is invalid")
		}
		if _, duplicate := resolutions[resolution.Reference]; duplicate {
			return nil, errors.New("internal device selector resolution is invalid")
		}
		resolutions[resolution.Reference] = append([]string(nil), resolution.DeviceIDs...)
	}
	return resolutions, nil
}

type recentEventCursor struct {
	BeforeOccurredAt time.Time
	RecordID         string
	TimeAnchor       time.Time
}

func encodeRecentEventCursor(occurredAt time.Time, recordID string, timeAnchor time.Time) string {
	payload := occurredAt.UTC().Format(time.RFC3339Nano) + "\n" + recordID
	if !timeAnchor.IsZero() {
		payload = "v2\n" + timeAnchor.UTC().Format(time.RFC3339Nano) + "\n" + payload
	}
	return base64.RawURLEncoding.EncodeToString([]byte(payload))
}

func decodeRecentEventCursor(value string) (recentEventCursor, error) {
	if len(value) > 256 {
		return recentEventCursor{}, errors.New("event query cursor is invalid")
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return recentEventCursor{}, errors.New("event query cursor is invalid")
	}
	parts := strings.Split(string(raw), "\n")
	cursor := recentEventCursor{}
	if len(parts) == 4 && parts[0] == "v2" {
		cursor.TimeAnchor, err = parseQueryAnchor(parts[1])
		parts = parts[2:]
	}
	if err != nil || len(parts) != 2 || !validRecordID(parts[1]) {
		return recentEventCursor{}, errors.New("event query cursor is invalid")
	}
	occurredAt, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil || occurredAt.Year() < 2000 || occurredAt.Year() > 3000 {
		return recentEventCursor{}, errors.New("event query cursor is invalid")
	}
	cursor.BeforeOccurredAt, cursor.RecordID = occurredAt.UTC(), parts[1]
	return cursor, nil
}

func parseQueryAnchor(value string) (time.Time, error) {
	anchor, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || anchor.Year() < 2000 || anchor.Year() > 3000 || anchor.UTC().Format(time.RFC3339Nano) != value {
		return time.Time{}, errors.New("query anchor is invalid")
	}
	return anchor.UTC(), nil
}

func encodeLiveEventCursor(receivedAt time.Time, recordID string) string {
	return encodeAnchoredLiveEventCursor(receivedAt, recordID, time.Time{})
}

type liveEventCursor struct {
	AfterReceivedAt time.Time
	RecordID        string
	TimeAnchor      time.Time
}

func encodeAnchoredLiveEventCursor(receivedAt time.Time, recordID string, timeAnchor time.Time) string {
	payload := receivedAt.UTC().Format(time.RFC3339Nano) + "\n" + recordID
	if !timeAnchor.IsZero() {
		payload = "v2\n" + timeAnchor.UTC().Format(time.RFC3339Nano) + "\n" + payload
	}
	return base64.RawURLEncoding.EncodeToString([]byte(payload))
}

func decodeLiveEventCursor(value string) (liveEventCursor, error) {
	if len(value) > 256 {
		return liveEventCursor{}, errors.New("live event cursor is invalid")
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return liveEventCursor{}, errors.New("live event cursor is invalid")
	}
	parts := strings.Split(string(raw), "\n")
	cursor := liveEventCursor{}
	if len(parts) == 4 && parts[0] == "v2" {
		cursor.TimeAnchor, err = parseQueryAnchor(parts[1])
		parts = parts[2:]
	}
	if err != nil || len(parts) != 2 || !validRecordID(parts[1]) {
		return liveEventCursor{}, errors.New("live event cursor is invalid")
	}
	receivedAt, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil || receivedAt.Year() < 2000 || receivedAt.Year() > 3000 {
		return liveEventCursor{}, errors.New("live event cursor is invalid")
	}
	cursor.AfterReceivedAt, cursor.RecordID = receivedAt.UTC(), parts[1]
	return cursor, nil
}

func DecodeLiveEventCursor(value string) (time.Time, string, error) {
	cursor, err := decodeLiveEventCursor(value)
	return cursor.AfterReceivedAt, cursor.RecordID, err
}
