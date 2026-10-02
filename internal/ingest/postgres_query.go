package ingest

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"shakerproxy.dev/shakerproxy/internal/querylang"
)

func (s PostgresSink) QueryRecent(ctx context.Context, query RecentEventQuery) (RecentEventPage, error) {
	if s.DB == nil {
		return RecentEventPage{}, errors.New("PostgreSQL connection is required")
	}
	if err := validateRecentEventQuery(query); err != nil {
		return RecentEventPage{}, err
	}
	generatedAt, err := s.liveEventBoundary(ctx)
	if err != nil {
		return RecentEventPage{}, err
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return RecentEventPage{}, fmt.Errorf("begin recent normalized event query: %w", err)
	}
	defer tx.Rollback()
	if querylang.HasRelativeTime(query.Filter) && query.TimeAnchor.IsZero() {
		query.TimeAnchor = generatedAt
	}
	clauses, args, err := buildEventWhere(query, true)
	if err != nil {
		return RecentEventPage{}, err
	}
	// The page is exactly the data committed at the live boundary, so a live
	// stream started from the returned cursor neither misses nor repeats rows.
	args = append(args, generatedAt)
	clauses = append(clauses, fmt.Sprintf("received_at <= $%d", len(args)))
	args = append(args, query.Limit+1)
	statement := eventSelect + ` WHERE ` + strings.Join(clauses, " AND ") + fmt.Sprintf(" ORDER BY occurred_at DESC, record_id DESC LIMIT $%d", len(args))
	events, err := readEvents(ctx, tx, statement, args, "recent")
	if err != nil {
		return RecentEventPage{}, err
	}
	var facets *EventFacets
	if query.BeforeOccurredAt.IsZero() {
		facetResult, facetErr := readEventFacets(ctx, tx, clauses, args[:len(args)-1])
		if facetErr != nil {
			return RecentEventPage{}, facetErr
		}
		facets = &facetResult
	}
	if err := tx.Commit(); err != nil {
		return RecentEventPage{}, fmt.Errorf("commit recent normalized event query: %w", err)
	}
	page := RecentEventPage{Schema: SchemaVersion, GeneratedAt: generatedAt, Events: events, CanonicalQuery: query.Filter.Canonical, Facets: facets, LiveCursor: encodeAnchoredLiveEventCursor(generatedAt, strings.Repeat("0", 64), query.TimeAnchor)}
	if querylang.HasRelativeTime(query.Filter) {
		page.QueryAnchor = query.TimeAnchor
	}
	if len(page.Events) > query.Limit {
		page.Events = page.Events[:query.Limit]
		last := page.Events[len(page.Events)-1]
		page.NextCursor = encodeRecentEventCursor(last.OccurredAt, last.RecordID, query.TimeAnchor)
	}
	return page, nil
}

// liveEventBoundary returns a timestamp such that every row with an earlier
// received_at is already committed. It holds a SHARE lock only long enough to
// wait for in-flight ingest transactions and read the clock, instead of for
// the whole (possibly 10,000-row facet) query, so the drain is not blocked
// while an operator browses events.
func (s PostgresSink) liveEventBoundary(ctx context.Context) (time.Time, error) {
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return time.Time{}, fmt.Errorf("begin live normalized event boundary: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "LOCK TABLE normalized_events IN SHARE MODE"); err != nil {
		return time.Time{}, fmt.Errorf("establish live normalized event boundary: %w", err)
	}
	var boundary time.Time
	if err := tx.QueryRowContext(ctx, "SELECT clock_timestamp()").Scan(&boundary); err != nil {
		return time.Time{}, fmt.Errorf("read live normalized event boundary: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return time.Time{}, fmt.Errorf("release live normalized event boundary: %w", err)
	}
	return boundary.UTC(), nil
}

func readEventFacets(ctx context.Context, queryer eventQueryer, clauses []string, args []any) (EventFacets, error) {
	statement := fmt.Sprintf(`WITH facet_candidates AS MATERIALIZED (
SELECT source::text AS source, kind, COALESCE(protocol, '') AS protocol, COALESCE(service, '') AS service, occurred_at, record_id
FROM normalized_events WHERE `+strings.Join(clauses, " AND ")+`
ORDER BY occurred_at DESC, record_id DESC LIMIT %d
), facet_input AS MATERIALIZED (
SELECT * FROM facet_candidates ORDER BY occurred_at DESC, record_id DESC LIMIT %d
), facet_counts AS (
SELECT 'source'::text AS field, source AS value, count(*)::bigint AS count FROM facet_input GROUP BY source
UNION ALL SELECT 'kind', kind, count(*)::bigint FROM facet_input GROUP BY kind
UNION ALL SELECT 'protocol', protocol, count(*)::bigint FROM facet_input GROUP BY protocol
UNION ALL SELECT 'service', service, count(*)::bigint FROM facet_input GROUP BY service
), ranked AS (
SELECT field, value, count, row_number() OVER (PARTITION BY field ORDER BY count DESC, value ASC) AS rank
FROM facet_counts
)
SELECT '__meta__', '', 0::bigint, 0::bigint, (SELECT count(*)::bigint FROM facet_candidates)
UNION ALL
SELECT field, value, count, rank, (SELECT count(*)::bigint FROM facet_candidates)
FROM ranked WHERE rank <= %d
ORDER BY 1, 4, 2`, MaxEventFacetInput+1, MaxEventFacetInput, MaxEventFacetValues)
	rows, err := queryer.QueryContext(ctx, statement, args...)
	if err != nil {
		return EventFacets{}, fmt.Errorf("query normalized event facets: %w", err)
	}
	defer rows.Close()
	fields := map[string]*EventFacet{}
	var candidateCount int64
	for rows.Next() {
		var field, value string
		var count, rank, candidates int64
		if err := rows.Scan(&field, &value, &count, &rank, &candidates); err != nil {
			return EventFacets{}, fmt.Errorf("decode normalized event facets: %w", err)
		}
		candidateCount = candidates
		if field == "__meta__" {
			continue
		}
		facet := fields[field]
		if facet == nil {
			facet = &EventFacet{Field: field, Values: make([]EventFacetValue, 0, MaxEventFacetValues)}
			fields[field] = facet
		}
		facet.Values = append(facet.Values, EventFacetValue{Value: value, Count: count})
	}
	if err := rows.Err(); err != nil {
		return EventFacets{}, fmt.Errorf("read normalized event facets: %w", err)
	}
	matchedCount := min(candidateCount, int64(MaxEventFacetInput))
	result := EventFacets{Exact: candidateCount <= MaxEventFacetInput, MatchedCount: matchedCount, CountRelation: "eq", Basis: "all_matches", Fields: make([]EventFacet, 0, 4)}
	if !result.Exact {
		result.CountRelation, result.Basis = "gte", "newest_sample"
	}
	for _, field := range []string{"source", "kind", "protocol", "service"} {
		facet := fields[field]
		if facet == nil {
			facet = &EventFacet{Field: field, Values: []EventFacetValue{}}
		}
		var shown int64
		for _, value := range facet.Values {
			shown += value.Count
		}
		facet.OtherCount = matchedCount - shown
		result.Fields = append(result.Fields, *facet)
	}
	domains, err := readEventDomains(ctx, queryer, clauses, args)
	if err != nil {
		return EventFacets{}, err
	}
	result.Domains = domains
	return result, nil
}

// readEventDomains builds the Domains facet from the same newest matching
// events as the other facets. An observation is the connection's addresses
// and ports (Zeek's ssl.log has no transport field), so the same connection
// reported by several analyzers, or split across capture segments, counts
// once; rows without addresses count individually. A connection the gateway
// reported counts under the name its client looked up until the analysis
// adds the server name for the same addresses and ports.
func readEventDomains(ctx context.Context, queryer eventQueryer, clauses []string, args []any) (EventDomainFacet, error) {
	statement := fmt.Sprintf(`WITH facet_input AS MATERIALIZED (
SELECT lower(rtrim(COALESCE(tls_server_name, http_host, dns_query, dns_name), '.')) AS host,
COALESCE(host(source_ip) || ' ' || source_port || ' ' || host(destination_ip) || ' ' || destination_port, record_id) AS observation
FROM normalized_events WHERE `+strings.Join(clauses, " AND ")+`
ORDER BY occurred_at DESC, record_id DESC LIMIT %d
), named AS MATERIALIZED (
SELECT host, observation FROM facet_input
WHERE host IS NOT NULL AND host <> '' AND host !~ '(^|[.])(local|arpa)$'
)
SELECT host, count(DISTINCT observation)::bigint, (SELECT count(DISTINCT observation) FROM named)::bigint
FROM named GROUP BY host ORDER BY 2 DESC, 1 LIMIT %d`, MaxEventFacetInput, maxEventDomainHostRows)
	rows, err := queryer.QueryContext(ctx, statement, args...)
	if err != nil {
		return EventDomainFacet{}, fmt.Errorf("query normalized event domains: %w", err)
	}
	defer rows.Close()
	var hosts []EventFacetValue
	var total int64
	for rows.Next() {
		var host EventFacetValue
		if err := rows.Scan(&host.Value, &host.Count, &total); err != nil {
			return EventDomainFacet{}, fmt.Errorf("decode normalized event domains: %w", err)
		}
		hosts = append(hosts, host)
	}
	if err := rows.Err(); err != nil {
		return EventDomainFacet{}, fmt.Errorf("read normalized event domains: %w", err)
	}
	return groupEventDomains(hosts, total), nil
}

func (s PostgresSink) QueryAfter(ctx context.Context, query LiveEventQuery) (LiveEventBatch, error) {
	if s.DB == nil {
		return LiveEventBatch{}, errors.New("PostgreSQL connection is required")
	}
	if querylang.HasRelativeTime(query.Filter) && query.TimeAnchor.IsZero() {
		query.TimeAnchor = query.AfterReceivedAt.UTC()
	}
	if err := validateLiveEventQuery(query); err != nil {
		return LiveEventBatch{}, err
	}
	clauses, args, err := buildEventWhere(query.RecentEventQuery, false)
	if err != nil {
		return LiveEventBatch{}, err
	}
	args = append(args, query.AfterReceivedAt.UTC(), query.AfterRecordID)
	clauses = append(clauses, fmt.Sprintf("(received_at, record_id) > ($%d, $%d)", len(args)-1, len(args)))
	args = append(args, query.Limit)
	statement := eventSelect + ` WHERE ` + strings.Join(clauses, " AND ") + fmt.Sprintf(" ORDER BY received_at ASC, record_id ASC LIMIT $%d", len(args))
	events, err := readEvents(ctx, s.DB, statement, args, "live")
	if err != nil {
		return LiveEventBatch{}, err
	}
	nextCursor := encodeAnchoredLiveEventCursor(query.AfterReceivedAt, query.AfterRecordID, query.TimeAnchor)
	if len(events) > 0 {
		last := events[len(events)-1]
		nextCursor = encodeAnchoredLiveEventCursor(last.ReceivedAt, last.RecordID, query.TimeAnchor)
	}
	batch := LiveEventBatch{Schema: SchemaVersion, GeneratedAt: time.Now().UTC(), Events: events, NextCursor: nextCursor, CanonicalQuery: query.Filter.Canonical}
	if querylang.HasRelativeTime(query.Filter) {
		batch.QueryAnchor = query.TimeAnchor
	}
	return batch, nil
}

func buildEventWhere(query RecentEventQuery, relativeUpperBound bool) ([]string, []any, error) {
	clauses := []string{"TRUE"}
	args := make([]any, 0, 8)
	add := func(clause string, value any) {
		args = append(args, value)
		clauses = append(clauses, fmt.Sprintf(clause, len(args)))
	}
	if query.Source != "" {
		add("source = $%d", query.Source)
	}
	if query.Kind != "" {
		add("kind = $%d", query.Kind)
	}
	if query.CaptureSessionID != "" {
		add("capture_session_id = $%d", query.CaptureSessionID)
	}
	if query.DeviceID != "" {
		add("device_id = $%d", query.DeviceID)
	}
	if query.Filter.Root != nil {
		parsed, err := querylang.Parse(query.Filter.Canonical)
		if err != nil {
			return nil, nil, errors.New("typed event filter is invalid")
		}
		clause, err := compileEventFilter(parsed.Root, query.DeviceNameResolutions, query.DeviceTagResolutions, query.TimeAnchor, relativeUpperBound, &args)
		if err != nil {
			return nil, nil, err
		}
		clauses = append(clauses, clause)
	}
	if !query.BeforeOccurredAt.IsZero() {
		args = append(args, query.BeforeOccurredAt.UTC(), query.BeforeRecordID)
		clauses = append(clauses, fmt.Sprintf("(occurred_at, record_id) < ($%d, $%d)", len(args)-1, len(args)))
	}
	return clauses, args, nil
}

const eventSelect = `SELECT record_id, source, kind, occurred_at, received_at, source_version, parser_version,
COALESCE(capture_session_id, ''), COALESCE(flow_id, ''), COALESCE(device_id, ''), confidence,
COALESCE(host(source_ip), ''), COALESCE(host(destination_ip), ''), COALESCE(source_port, 0),
COALESCE(destination_port, 0), COALESCE(protocol, ''), COALESCE(service, ''), COALESCE(network_bytes, 0),
COALESCE(dns_query, ''), COALESCE(dns_record_type, ''), COALESCE(dns_response_code, ''), dns_answer_count,
COALESCE(array_to_json(dns_answers)::text, ''), COALESCE(dns_name, ''),
COALESCE(detection_type, ''), COALESCE(detection_severity, ''), COALESCE(detection_state, ''),
COALESCE(detection_summary, ''), COALESCE(detection_scope, ''),
COALESCE(tls_server_name, ''), COALESCE(tls_interception_state, ''), COALESCE(tls_failure_reason, ''),
COALESCE(tls_pinning_suspected, false), tls_client_recent_success, COALESCE(tls_bypass_activated, false),
COALESCE(tls_platform, ''),
COALESCE(attribution_evidence::text, ''),
COALESCE(app_protocol, ''), COALESCE(protocol_category, ''), COALESCE(protocol_visibility, ''),
COALESCE(protocol_evidence, ''), COALESCE(protocol_exotic, false),
COALESCE(http_method, ''), COALESCE(http_host, ''), COALESCE(http_path, ''), COALESCE(http_status, 0),
COALESCE(alert_signature, ''), COALESCE(alert_severity, 0), COALESCE(alert_category, '')
FROM normalized_events`

type eventQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func readEvents(ctx context.Context, queryer eventQueryer, statement string, args []any, queryKind string) ([]RecentEvent, error) {
	rows, err := queryer.QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, fmt.Errorf("query %s normalized events: %w", queryKind, err)
	}
	defer rows.Close()
	events := make([]RecentEvent, 0, min(len(args)*8, MaxRecentEventLimit))
	for rows.Next() {
		var event RecentEvent
		var dnsAnswerCount sql.NullInt64
		var dnsAnswersJSON string
		var tlsClientRecentSuccess sql.NullBool
		var attributionJSON string
		if err := rows.Scan(&event.RecordID, &event.Source, &event.Kind, &event.OccurredAt, &event.ReceivedAt, &event.SourceVersion, &event.ParserVersion, &event.CaptureSessionID, &event.FlowID, &event.DeviceID, &event.Confidence, &event.SourceIP, &event.DestinationIP, &event.SourcePort, &event.DestinationPort, &event.Protocol, &event.Service, &event.NetworkBytes, &event.DNSQuery, &event.DNSRecordType, &event.DNSResponseCode, &dnsAnswerCount, &dnsAnswersJSON, &event.DNSName, &event.DetectionType, &event.DetectionSeverity, &event.DetectionState, &event.DetectionSummary, &event.DetectionScope, &event.TLSServerName, &event.TLSInterceptionState, &event.TLSFailureReason, &event.TLSPinningSuspected, &tlsClientRecentSuccess, &event.TLSBypassActivated, &event.TLSPlatform, &attributionJSON,
			&event.AppProtocol, &event.ProtocolCategory, &event.ProtocolVisibility, &event.ProtocolEvidence, &event.ProtocolExotic,
			&event.HTTPMethod, &event.HTTPHost, &event.HTTPPath, &event.HTTPStatus,
			&event.AlertSignature, &event.AlertSeverity, &event.AlertCategory); err != nil {
			return nil, fmt.Errorf("decode %s normalized event: %w", queryKind, err)
		}
		if dnsAnswerCount.Valid {
			count := int(dnsAnswerCount.Int64)
			event.DNSAnswerCount = &count
		}
		if dnsAnswersJSON != "" {
			if json.Unmarshal([]byte(dnsAnswersJSON), &event.DNSAnswers) != nil || !validEventDNSAnswers(event.DNSAnswers) {
				return nil, fmt.Errorf("decode %s normalized event DNS answers", queryKind)
			}
		}
		if tlsClientRecentSuccess.Valid {
			value := tlsClientRecentSuccess.Bool
			event.TLSClientRecentSuccess = &value
		}
		if attributionJSON != "" {
			var evidence AttributionEvidence
			decoder := json.NewDecoder(strings.NewReader(attributionJSON))
			decoder.DisallowUnknownFields()
			if decoder.Decode(&evidence) != nil || decoder.Decode(&struct{}{}) != io.EOF || evidence.Validate(event) != nil {
				return nil, fmt.Errorf("decode %s normalized event attribution evidence", queryKind)
			}
			event.AttributionEvidence = &evidence
		}
		event.Summary = EventSummary(event)
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read %s normalized events: %w", queryKind, err)
	}
	return events, nil
}
