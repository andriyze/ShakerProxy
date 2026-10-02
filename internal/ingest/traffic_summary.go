package ingest

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"shakerproxy.dev/shakerproxy/internal/querylang"
)

// The events summary feeds the live Traffic view's timeline and facet
// sidebar, and the MCP traffic_summary tool: counts per stream type over
// time, the top devices, destinations and protocols, and totals, for the
// same filter the event list takes. Analyzer duplicates are always left out
// (docs/traffic-stream-types.md).
const (
	TrafficSummarySchemaVersion  = 1
	DefaultTrafficSummaryBuckets = 60
	MaxTrafficSummaryBuckets     = 240
	DefaultTrafficSummaryWindow  = 15 * time.Minute
	MinTrafficSummaryWindow      = time.Second
	MaxTrafficSummaryWindow      = 30 * 24 * time.Hour
	// MaxTrafficSummarySample bounds the newest matching events whose
	// destination owner and category are worked out in Go (the curated
	// domain table is not in the database).
	MaxTrafficSummarySample      = 20_000
	MaxTrafficSummaryFacetValues = 20
	maxTrafficSummaryValueBytes  = 256
	maxTrafficSummaryLabelBytes  = 128
	maxTrafficSummaryCount       = int64(1) << 50
	// trafficSummaryStatementTimeout keeps one summary from holding the
	// database; the whole request has a 3 s budget in ingestd.
	trafficSummaryStatementTimeout = "2500ms"
)

// Summary facet fields. Device values are device IDs, or "ip:<address>" for
// traffic no device was attributed.
const (
	SummaryFacetDevice          = "device"
	SummaryFacetType            = "type"
	SummaryFacetOrganization    = "organization"
	SummaryFacetCategory        = "category"
	SummaryFacetDestinationPort = "destination_port"
	SummaryFacetAppProtocol     = "app_protocol"
)

// TrafficSummaryFacetFields lists the facets in display order.
var TrafficSummaryFacetFields = []string{SummaryFacetDevice, SummaryFacetType, SummaryFacetOrganization, SummaryFacetCategory, SummaryFacetDestinationPort, SummaryFacetAppProtocol}

type TrafficSummaryQuery struct {
	// Events carries the filter: q, source, kind, device and capture, with
	// device-name resolutions; its limit and cursor are not used.
	Events RecentEventQuery
	// From and To bound the timeline. Both empty means the window of the
	// filter's relative time (time:last_1h), else the last 15 minutes.
	From    time.Time
	To      time.Time
	Buckets int
}

type StreamTypeCounts struct {
	DNS       int64 `json:"dns"`
	TLS       int64 `json:"tls"`
	QUIC      int64 `json:"quic"`
	HTTP      int64 `json:"http"`
	Discovery int64 `json:"discovery"`
	Alert     int64 `json:"alert"`
	Other     int64 `json:"other"`
	Blocked   int64 `json:"blocked"`
}

func (c *StreamTypeCounts) slot(streamType string) *int64 {
	switch streamType {
	case StreamDNS:
		return &c.DNS
	case StreamTLS:
		return &c.TLS
	case StreamQUIC:
		return &c.QUIC
	case StreamHTTP:
		return &c.HTTP
	case StreamDiscovery:
		return &c.Discovery
	case StreamAlert:
		return &c.Alert
	case StreamBlocked:
		return &c.Blocked
	}
	return &c.Other
}

// Get returns the count of one stream type.
func (c StreamTypeCounts) Get(streamType string) int64 { return *c.slot(streamType) }

func (c StreamTypeCounts) Total() int64 {
	return c.DNS + c.TLS + c.QUIC + c.HTTP + c.Discovery + c.Alert + c.Other + c.Blocked
}

type TrafficSummaryBucket struct {
	Start  time.Time        `json:"start"`
	Counts StreamTypeCounts `json:"counts"`
}

type TrafficSummaryTotals struct {
	Events        int64            `json:"events"`
	BytesSent     int64            `json:"bytes_sent"`
	BytesReceived int64            `json:"bytes_received"`
	Types         StreamTypeCounts `json:"types"`
}

type TrafficSummaryFacetValue struct {
	Value string `json:"value"`
	// Label is a display name where the value is an ID: a device's
	// friendly name, or the address of unattributed traffic.
	Label string `json:"label,omitempty"`
	Count int64  `json:"count"`
}

type TrafficSummaryFacet struct {
	Field  string                     `json:"field"`
	Values []TrafficSummaryFacetValue `json:"values"`
	// OtherCount counts the events (sampled events for a sampled facet)
	// not in Values, including those without a value.
	OtherCount int64 `json:"other_count"`
	// Exact is false when the facet was counted over the newest
	// SampledEvents matching events only.
	Exact         bool  `json:"exact"`
	SampledEvents int64 `json:"sampled_events,omitempty"`
}

type TrafficSummary struct {
	Schema         int                    `json:"schema"`
	GeneratedAt    time.Time              `json:"generated_at"`
	From           time.Time              `json:"from"`
	To             time.Time              `json:"to"`
	BucketSeconds  float64                `json:"bucket_seconds"`
	Buckets        []TrafficSummaryBucket `json:"buckets"`
	Totals         TrafficSummaryTotals   `json:"totals"`
	Facets         []TrafficSummaryFacet  `json:"facets"`
	CanonicalQuery string                 `json:"canonical_query,omitempty"`
}

type TrafficSummaryReader interface {
	QueryTrafficSummary(context.Context, TrafficSummaryQuery) (TrafficSummary, error)
}

// ParseTrafficSummaryQuery parses the public control-plane summary query.
func ParseTrafficSummaryQuery(values url.Values) (TrafficSummaryQuery, error) {
	return parseTrafficSummaryQuery(values, ParseRecentEventQuery)
}

// ParseInternalTrafficSummaryQuery accepts the private device-resolution and
// time-anchor parameters QueryClient sends to ingestd.
func ParseInternalTrafficSummaryQuery(values url.Values) (TrafficSummaryQuery, error) {
	return parseTrafficSummaryQuery(values, ParseInternalRecentEventQuery)
}

func parseTrafficSummaryQuery(values url.Values, parseEvents func(url.Values) (RecentEventQuery, error)) (TrafficSummaryQuery, error) {
	rest := cloneValues(values)
	for _, key := range []string{"limit", "cursor"} {
		if _, present := rest[key]; present {
			return TrafficSummaryQuery{}, errors.New("the events summary takes no limit or cursor")
		}
	}
	query := TrafficSummaryQuery{Buckets: DefaultTrafficSummaryBuckets}
	single := func(key string) (string, bool, error) {
		entries, present := rest[key]
		if !present {
			return "", false, nil
		}
		rest.Del(key)
		if len(entries) != 1 {
			return "", false, fmt.Errorf("events summary %s is repeated", key)
		}
		return entries[0], true, nil
	}
	for _, field := range []struct {
		key string
		dst *time.Time
	}{{"from", &query.From}, {"to", &query.To}} {
		raw, present, err := single(field.key)
		if err != nil {
			return TrafficSummaryQuery{}, err
		}
		if present {
			parsed, parseErr := time.Parse(time.RFC3339Nano, raw)
			if parseErr != nil {
				return TrafficSummaryQuery{}, fmt.Errorf("events summary %s must be an RFC 3339 time, such as 2026-10-02T14:00:00Z", field.key)
			}
			*field.dst = parsed.UTC()
		}
	}
	raw, present, err := single("buckets")
	if err != nil {
		return TrafficSummaryQuery{}, err
	}
	if present {
		buckets, parseErr := strconv.Atoi(raw)
		if parseErr != nil {
			return TrafficSummaryQuery{}, errors.New("events summary buckets must be a whole number")
		}
		query.Buckets = buckets
	}
	events, err := parseEvents(rest)
	if err != nil {
		return TrafficSummaryQuery{}, err
	}
	events.Limit = 1
	query.Events = events
	// The event filter was checked by its parser; device selectors are
	// resolved after public parsing, so only the window is checked here.
	if err := query.validateWindow(); err != nil {
		return TrafficSummaryQuery{}, err
	}
	return query, nil
}

// Validate checks a summary query, including its resolved event filter.
func (query TrafficSummaryQuery) Validate() error {
	if err := query.validateWindow(); err != nil {
		return err
	}
	if !query.Events.BeforeOccurredAt.IsZero() {
		return errors.New("the events summary takes no cursor")
	}
	events := query.Events
	if events.Limit == 0 {
		events.Limit = 1
	}
	return validateRecentEventQuery(events)
}

func (query TrafficSummaryQuery) validateWindow() error {
	if query.Buckets < 1 || query.Buckets > MaxTrafficSummaryBuckets {
		return fmt.Errorf("events summary buckets must be between 1 and %d", MaxTrafficSummaryBuckets)
	}
	for _, at := range []time.Time{query.From, query.To} {
		if !at.IsZero() && (at.Year() < 2000 || at.Year() > 3000) {
			return errors.New("events summary time is out of range")
		}
	}
	if !query.From.IsZero() && !query.To.IsZero() {
		if query.To.Sub(query.From) < MinTrafficSummaryWindow {
			return errors.New("events summary to must be at least a second after from")
		}
		if query.To.Sub(query.From) > MaxTrafficSummaryWindow {
			return errors.New("events summary window is at most 30 days")
		}
	}
	return nil
}

// window resolves the timeline bounds against now.
func (query TrafficSummaryQuery) window(now time.Time) (time.Time, time.Time) {
	from, to := query.From, query.To
	if to.IsZero() {
		to = now
		if !from.IsZero() && to.Sub(from) < MinTrafficSummaryWindow {
			to = from.Add(DefaultTrafficSummaryWindow)
		}
	}
	if from.IsZero() {
		width := DefaultTrafficSummaryWindow
		if relative, ok := relativeTimeWindow(query.Events.Filter); ok {
			width = relative
		}
		from = to.Add(-width)
	}
	if to.Sub(from) > MaxTrafficSummaryWindow {
		from = to.Add(-MaxTrafficSummaryWindow)
	}
	return from.UTC(), to.UTC()
}

// relativeTimeWindow is the narrowest time:last_… window in a filter.
func relativeTimeWindow(filter querylang.Query) (time.Duration, bool) {
	var narrowest time.Duration
	var visit func(*querylang.Node)
	visit = func(node *querylang.Node) {
		if node == nil {
			return
		}
		if node.Type == querylang.NodePredicate && node.Predicate != nil && node.Predicate.Field == "time" && node.Predicate.IsRelativeTime && node.Predicate.RelativeNanos > 0 {
			if width := time.Duration(node.Predicate.RelativeNanos); narrowest == 0 || width < narrowest {
				narrowest = width
			}
		}
		for _, child := range node.Children {
			visit(child)
		}
	}
	visit(filter.Root)
	return narrowest, narrowest > 0
}

func encodeInternalTrafficSummaryQuery(query TrafficSummaryQuery) (url.Values, error) {
	values, err := encodeInternalRecentEventQuery(query.Events)
	if err != nil {
		return nil, err
	}
	values.Del("limit")
	values.Del("cursor")
	if !query.From.IsZero() {
		values.Set("from", query.From.UTC().Format(time.RFC3339Nano))
	}
	if !query.To.IsZero() {
		values.Set("to", query.To.UTC().Format(time.RFC3339Nano))
	}
	values.Set("buckets", strconv.Itoa(query.Buckets))
	return values, nil
}

var analyzerDuplicates = mustParseFilter(analyzerDuplicatesFilter)

func mustParseFilter(text string) querylang.Query {
	parsed, err := querylang.Parse(text)
	if err != nil {
		panic(fmt.Sprintf("built-in event filter %q is invalid: %v", text, err))
	}
	return parsed
}

// QueryTrafficSummary builds the summary in one read-only snapshot: the
// timeline, type counts and totals exactly over the window; device, port and
// protocol facets exactly; owner and category facets over the newest
// MaxTrafficSummarySample matching events.
func (s PostgresSink) QueryTrafficSummary(ctx context.Context, query TrafficSummaryQuery) (TrafficSummary, error) {
	if s.DB == nil {
		return TrafficSummary{}, errors.New("PostgreSQL connection is required")
	}
	if err := query.Validate(); err != nil {
		return TrafficSummary{}, err
	}
	generatedAt, err := s.liveEventBoundary(ctx)
	if err != nil {
		return TrafficSummary{}, err
	}
	events := query.Events
	events.Limit = 1
	if querylang.HasRelativeTime(events.Filter) && events.TimeAnchor.IsZero() {
		events.TimeAnchor = generatedAt
	}
	// A relative window ends where its time:last_… term is anchored.
	windowEnd := generatedAt
	if !events.TimeAnchor.IsZero() && events.TimeAnchor.Before(generatedAt) {
		windowEnd = events.TimeAnchor
	}
	from, to := query.window(windowEnd)
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return TrafficSummary{}, fmt.Errorf("begin events summary: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "SET LOCAL statement_timeout = '"+trafficSummaryStatementTimeout+"'"); err != nil {
		return TrafficSummary{}, fmt.Errorf("bound events summary: %w", err)
	}
	clauses, args, err := buildEventWhere(events, true)
	if err != nil {
		return TrafficSummary{}, err
	}
	duplicates, err := compileEventFilter(analyzerDuplicates.Root, nil, nil, events.TimeAnchor, true, &args)
	if err != nil {
		return TrafficSummary{}, err
	}
	args = append(args, from, to, generatedAt)
	clauses = append(clauses, duplicates, fmt.Sprintf("occurred_at >= $%d AND occurred_at < $%d AND received_at <= $%d", len(args)-2, len(args)-1, len(args)))
	where := strings.Join(clauses, " AND ")

	summary := TrafficSummary{Schema: TrafficSummarySchemaVersion, GeneratedAt: generatedAt, From: from, To: to, Buckets: make([]TrafficSummaryBucket, query.Buckets), CanonicalQuery: query.Events.Filter.Canonical}
	width := to.Sub(from) / time.Duration(query.Buckets)
	summary.BucketSeconds = width.Seconds()
	for index := range summary.Buckets {
		summary.Buckets[index].Start = from.Add(time.Duration(index) * width)
	}
	if err := readSummaryTimeline(ctx, tx, where, args, from, width, &summary); err != nil {
		return TrafficSummary{}, err
	}
	exact, err := readSummaryExactFacets(ctx, tx, where, args, summary.Totals.Events)
	if err != nil {
		return TrafficSummary{}, err
	}
	sampled, err := readSummarySampledFacets(ctx, tx, where, args, summary.Totals.Events)
	if err != nil {
		return TrafficSummary{}, err
	}
	if err := tx.Commit(); err != nil {
		return TrafficSummary{}, fmt.Errorf("commit events summary: %w", err)
	}
	for _, field := range TrafficSummaryFacetFields {
		switch field {
		case SummaryFacetType:
			summary.Facets = append(summary.Facets, typeFacet(summary.Totals.Types))
		case SummaryFacetOrganization, SummaryFacetCategory:
			summary.Facets = append(summary.Facets, sampled[field])
		default:
			summary.Facets = append(summary.Facets, exact[field])
		}
	}
	return summary, nil
}

func readSummaryTimeline(ctx context.Context, queryer eventQueryer, where string, args []any, from time.Time, width time.Duration, summary *TrafficSummary) error {
	args = append(append([]any(nil), args...), from, width.Seconds(), len(summary.Buckets))
	// One pass gives the timeline, the type counts and the byte totals.
	statement := fmt.Sprintf(`SELECT LEAST(GREATEST(floor(extract(epoch FROM (occurred_at - $%[1]d::timestamptz)) / $%[2]d::float8)::int, 0), $%[3]d::int - 1) AS bucket,
`+streamTypeSQL+` AS stream_type, count(*)::bigint, COALESCE(sum(`+bytesSentSQL+`), 0)::bigint, COALESCE(sum(`+bytesReceivedSQL+`), 0)::bigint
FROM normalized_events WHERE `+where+`
GROUP BY 1, 2`, len(args)-2, len(args)-1, len(args))
	rows, err := queryer.QueryContext(ctx, statement, args...)
	if err != nil {
		return fmt.Errorf("query events summary timeline: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var bucket int
		var streamType string
		var count, sent, received int64
		if err := rows.Scan(&bucket, &streamType, &count, &sent, &received); err != nil {
			return fmt.Errorf("decode events summary timeline: %w", err)
		}
		if bucket < 0 || bucket >= len(summary.Buckets) {
			return errors.New("events summary bucket is out of range")
		}
		*summary.Buckets[bucket].Counts.slot(streamType) += count
		*summary.Totals.Types.slot(streamType) += count
		summary.Totals.Events += count
		summary.Totals.BytesSent += sent
		summary.Totals.BytesReceived += received
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read events summary timeline: %w", err)
	}
	return nil
}

func readSummaryExactFacets(ctx context.Context, queryer eventQueryer, where string, args []any, matched int64) (map[string]TrafficSummaryFacet, error) {
	statement := fmt.Sprintf(`WITH matching AS MATERIALIZED (
SELECT COALESCE(NULLIF(device_id, ''), CASE WHEN source_ip IS NULL THEN '' ELSE 'ip:' || host(source_ip) END) AS device,
COALESCE(destination_port::text, '') AS destination_port, COALESCE(app_protocol, '') AS app_protocol
FROM normalized_events WHERE `+where+`
), counts AS (
SELECT '`+SummaryFacetDevice+`'::text AS field, device AS value, count(*)::bigint AS count FROM matching WHERE device <> '' GROUP BY device
UNION ALL SELECT '`+SummaryFacetDestinationPort+`', destination_port, count(*)::bigint FROM matching WHERE destination_port <> '' GROUP BY destination_port
UNION ALL SELECT '`+SummaryFacetAppProtocol+`', app_protocol, count(*)::bigint FROM matching WHERE app_protocol <> '' GROUP BY app_protocol
), ranked AS (
SELECT field, value, count, row_number() OVER (PARTITION BY field ORDER BY count DESC, value) AS rank FROM counts
)
SELECT field, value, count FROM ranked WHERE rank <= %d ORDER BY field, rank`, MaxTrafficSummaryFacetValues)
	rows, err := queryer.QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, fmt.Errorf("query events summary facets: %w", err)
	}
	defer rows.Close()
	facets := map[string]TrafficSummaryFacet{}
	for _, field := range []string{SummaryFacetDevice, SummaryFacetDestinationPort, SummaryFacetAppProtocol} {
		facets[field] = TrafficSummaryFacet{Field: field, Values: []TrafficSummaryFacetValue{}, Exact: true}
	}
	for rows.Next() {
		var field string
		var value TrafficSummaryFacetValue
		if err := rows.Scan(&field, &value.Value, &value.Count); err != nil {
			return nil, fmt.Errorf("decode events summary facets: %w", err)
		}
		facet := facets[field]
		if strings.HasPrefix(value.Value, "ip:") {
			value.Label = strings.TrimPrefix(value.Value, "ip:")
		}
		facet.Values = append(facet.Values, value)
		facets[field] = facet
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read events summary facets: %w", err)
	}
	for field, facet := range facets {
		facet.OtherCount = otherCount(matched, facet.Values)
		facets[field] = facet
	}
	return facets, nil
}

// readSummarySampledFacets counts destination owners and categories over the
// newest matching events; the curated domain table lives in Go.
func readSummarySampledFacets(ctx context.Context, queryer eventQueryer, where string, args []any, matched int64) (map[string]TrafficSummaryFacet, error) {
	statement := fmt.Sprintf(`SELECT COALESCE(tls_server_name, ''), COALESCE(http_host, ''), COALESCE(dns_query, ''), COALESCE(dns_name, '')
FROM normalized_events WHERE `+where+` ORDER BY occurred_at DESC, record_id DESC LIMIT %d`, MaxTrafficSummarySample)
	rows, err := queryer.QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, fmt.Errorf("query events summary destinations: %w", err)
	}
	defer rows.Close()
	organizations, categories := map[string]int64{}, map[string]int64{}
	var sampled int64
	for rows.Next() {
		var event RecentEvent
		if err := rows.Scan(&event.TLSServerName, &event.HTTPHost, &event.DNSQuery, &event.DNSName); err != nil {
			return nil, fmt.Errorf("decode events summary destinations: %w", err)
		}
		sampled++
		if organization, category := destinationOwner(event); organization != "" {
			organizations[organization]++
			categories[category]++
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read events summary destinations: %w", err)
	}
	exact := sampled >= matched
	facet := func(field string, counts map[string]int64) TrafficSummaryFacet {
		values := topValues(counts, MaxTrafficSummaryFacetValues)
		result := TrafficSummaryFacet{Field: field, Values: values, OtherCount: otherCount(sampled, values), Exact: exact}
		if !exact {
			result.SampledEvents = sampled
		}
		return result
	}
	return map[string]TrafficSummaryFacet{
		SummaryFacetOrganization: facet(SummaryFacetOrganization, organizations),
		SummaryFacetCategory:     facet(SummaryFacetCategory, categories),
	}, nil
}

func typeFacet(types StreamTypeCounts) TrafficSummaryFacet {
	facet := TrafficSummaryFacet{Field: SummaryFacetType, Values: []TrafficSummaryFacetValue{}, Exact: true}
	for _, streamType := range StreamTypes {
		if count := types.Get(streamType); count > 0 {
			facet.Values = append(facet.Values, TrafficSummaryFacetValue{Value: streamType, Count: count})
		}
	}
	sort.SliceStable(facet.Values, func(i, j int) bool { return facet.Values[i].Count > facet.Values[j].Count })
	return facet
}

func topValues(counts map[string]int64, limit int) []TrafficSummaryFacetValue {
	values := make([]TrafficSummaryFacetValue, 0, len(counts))
	for value, count := range counts {
		values = append(values, TrafficSummaryFacetValue{Value: value, Count: count})
	}
	sort.Slice(values, func(i, j int) bool {
		if values[i].Count != values[j].Count {
			return values[i].Count > values[j].Count
		}
		return values[i].Value < values[j].Value
	})
	if len(values) > limit {
		values = values[:limit]
	}
	return values
}

func otherCount(total int64, values []TrafficSummaryFacetValue) int64 {
	for _, value := range values {
		total -= value.Count
	}
	return max(total, 0)
}

// ValidateTrafficSummary checks a summary from ingestd before control-api
// serves it.
func ValidateTrafficSummary(summary TrafficSummary, query TrafficSummaryQuery) error {
	if summary.Schema != TrafficSummarySchemaVersion || summary.GeneratedAt.IsZero() || !summary.To.After(summary.From) || summary.To.Sub(summary.From) > MaxTrafficSummaryWindow+time.Second {
		return errors.New("events summary header is invalid")
	}
	if len(summary.Buckets) != query.Buckets || math.IsNaN(summary.BucketSeconds) || summary.BucketSeconds <= 0 {
		return errors.New("events summary timeline is invalid")
	}
	var timeline StreamTypeCounts
	for index, bucket := range summary.Buckets {
		if bucket.Start.Before(summary.From) || !bucket.Start.Before(summary.To) || index > 0 && !bucket.Start.After(summary.Buckets[index-1].Start) {
			return errors.New("events summary bucket is out of order")
		}
		for _, streamType := range StreamTypes {
			count := bucket.Counts.Get(streamType)
			if count < 0 || count > maxTrafficSummaryCount {
				return errors.New("events summary count is invalid")
			}
			*timeline.slot(streamType) += count
		}
	}
	if timeline != summary.Totals.Types || summary.Totals.Types.Total() != summary.Totals.Events {
		return errors.New("events summary totals do not match the timeline")
	}
	for _, total := range []int64{summary.Totals.Events, summary.Totals.BytesSent, summary.Totals.BytesReceived} {
		if total < 0 || total > maxTrafficSummaryCount {
			return errors.New("events summary totals are invalid")
		}
	}
	if len(summary.Facets) != len(TrafficSummaryFacetFields) {
		return errors.New("events summary facets are invalid")
	}
	for index, facet := range summary.Facets {
		if facet.Field != TrafficSummaryFacetFields[index] || len(facet.Values) > MaxTrafficSummaryFacetValues || facet.OtherCount < 0 || facet.SampledEvents < 0 || facet.SampledEvents > MaxTrafficSummarySample || facet.Exact != (facet.SampledEvents == 0) {
			return errors.New("events summary facet is invalid")
		}
		for _, value := range facet.Values {
			if !validText(value.Value, 1, maxTrafficSummaryValueBytes) || value.Label != "" && !validText(value.Label, 1, maxTrafficSummaryLabelBytes) || value.Count < 1 || value.Count > maxTrafficSummaryCount {
				return errors.New("events summary facet value is invalid")
			}
		}
	}
	return nil
}
