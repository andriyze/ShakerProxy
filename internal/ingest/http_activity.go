package ingest

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultHTTPActivityLimit         = 50
	DefaultHTTPActivityWindowSeconds = 15 * 60
)

var allowedHTTPActivityWindows = map[int]struct{}{
	5 * 60: {}, 15 * 60: {}, 60 * 60: {}, 6 * 60 * 60: {}, 24 * 60 * 60: {},
}

type HTTPActivityQuery struct {
	Limit         int
	WindowSeconds int
	DeviceID      string
	Host          string
	Method        string
	Cursor        string
}

type HTTPActivityPage struct {
	Schema      int                 `json:"schema"`
	GeneratedAt time.Time           `json:"generated_at"`
	QueryAnchor time.Time           `json:"query_anchor"`
	Events      []HTTPActivityEvent `json:"events"`
	NextCursor  string              `json:"next_cursor,omitempty"`
}

type HTTPActivityReader interface {
	QueryHTTPActivity(context.Context, HTTPActivityQuery) (HTTPActivityPage, error)
}

func ParseInternalHTTPActivityQuery(values url.Values) (HTTPActivityQuery, error) {
	allowed := map[string]bool{"limit": true, "window_seconds": true, "device_id": true, "host": true, "method": true, "cursor": true}
	for key, entries := range values {
		if !allowed[key] || len(entries) != 1 {
			return HTTPActivityQuery{}, errors.New("HTTP activity query contains an unsupported or repeated parameter")
		}
	}
	query := HTTPActivityQuery{Limit: DefaultHTTPActivityLimit, WindowSeconds: DefaultHTTPActivityWindowSeconds}
	if raw := values.Get("limit"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil {
			return HTTPActivityQuery{}, errors.New("HTTP activity limit is invalid")
		}
		query.Limit = value
	}
	if raw := values.Get("window_seconds"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil {
			return HTTPActivityQuery{}, errors.New("HTTP activity window is invalid")
		}
		query.WindowSeconds = value
	}
	query.DeviceID = strings.TrimSpace(values.Get("device_id"))
	query.Host = strings.TrimSpace(values.Get("host"))
	query.Method = strings.TrimSpace(values.Get("method"))
	query.Cursor = strings.TrimSpace(values.Get("cursor"))
	if query.Host != "" {
		host, err := CanonicalHTTPHost(query.Host)
		if err != nil {
			return HTTPActivityQuery{}, err
		}
		query.Host = host
	}
	if query.Method != "" {
		method, err := CanonicalHTTPMethod(query.Method)
		if err != nil {
			return HTTPActivityQuery{}, err
		}
		query.Method = method
	}
	if err := validateHTTPActivityQuery(query); err != nil {
		return HTTPActivityQuery{}, err
	}
	return query, nil
}

func encodeHTTPActivityQuery(query HTTPActivityQuery) (url.Values, error) {
	if err := validateHTTPActivityQuery(query); err != nil {
		return nil, err
	}
	values := make(url.Values)
	values.Set("limit", strconv.Itoa(query.Limit))
	values.Set("window_seconds", strconv.Itoa(query.WindowSeconds))
	if query.DeviceID != "" {
		values.Set("device_id", query.DeviceID)
	}
	if query.Host != "" {
		values.Set("host", query.Host)
	}
	if query.Method != "" {
		values.Set("method", query.Method)
	}
	if query.Cursor != "" {
		values.Set("cursor", query.Cursor)
	}
	return values, nil
}

func validateHTTPActivityQuery(query HTTPActivityQuery) error {
	if query.Limit < 1 || query.Limit > MaxHTTPActivityLimit {
		return errors.New("HTTP activity limit must be between 1 and 100")
	}
	if _, ok := allowedHTTPActivityWindows[query.WindowSeconds]; !ok {
		return errors.New("HTTP activity window must be 300, 900, 3600, 21600, or 86400 seconds")
	}
	if query.DeviceID != "" && !deviceIDPattern.MatchString(query.DeviceID) {
		return errors.New("HTTP activity device ID is invalid")
	}
	if query.Host != "" {
		canonical, err := CanonicalHTTPHost(query.Host)
		if err != nil || canonical != query.Host {
			return errors.New("HTTP activity host is not canonical")
		}
	}
	if query.Method != "" {
		canonical, err := CanonicalHTTPMethod(query.Method)
		if err != nil || canonical != query.Method {
			return errors.New("HTTP activity method is not canonical")
		}
	}
	if query.Cursor != "" {
		cursor, err := decodeRecentEventCursor(query.Cursor)
		if err != nil || cursor.TimeAnchor.IsZero() {
			return errors.New("HTTP activity cursor is invalid")
		}
	}
	return nil
}

func (s PostgresSink) QueryHTTPActivity(ctx context.Context, query HTTPActivityQuery) (HTTPActivityPage, error) {
	if s.DB == nil {
		return HTTPActivityPage{}, errors.New("PostgreSQL connection is required")
	}
	if err := validateHTTPActivityQuery(query); err != nil {
		return HTTPActivityPage{}, err
	}
	// A read-only snapshot is enough: HTTP activity pages are anchored by
	// occurred_at and have no live cursor, so they must not block ingestion.
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return HTTPActivityPage{}, fmt.Errorf("begin HTTP activity query: %w", err)
	}
	defer tx.Rollback()
	var generatedAt time.Time
	if err := tx.QueryRowContext(ctx, "SELECT clock_timestamp()").Scan(&generatedAt); err != nil {
		return HTTPActivityPage{}, fmt.Errorf("read HTTP activity boundary: %w", err)
	}
	generatedAt = generatedAt.UTC()
	anchor := generatedAt
	cursor := recentEventCursor{}
	if query.Cursor != "" {
		cursor, err = decodeRecentEventCursor(query.Cursor)
		if err != nil || cursor.TimeAnchor.IsZero() || cursor.TimeAnchor.After(generatedAt.Add(5*time.Second)) {
			return HTTPActivityPage{}, errors.New("HTTP activity cursor anchor is invalid")
		}
		anchor = cursor.TimeAnchor
	}
	clauses := []string{"source = $1", "kind IN ('http_request','http_response')", "occurred_at >= $2", "occurred_at <= $3"}
	args := []any{SourceMitmproxy, anchor.Add(-time.Duration(query.WindowSeconds) * time.Second), anchor}
	add := func(clause string, value any) {
		args = append(args, value)
		clauses = append(clauses, fmt.Sprintf(clause, len(args)))
	}
	if query.DeviceID != "" {
		add("device_id = $%d", query.DeviceID)
	}
	if query.Host != "" {
		add("lower(rtrim(COALESCE(payload->>'http_host',''), '.')) = $%d", query.Host)
	}
	if query.Method != "" {
		add("upper(COALESCE(payload->>'http_method','')) = $%d", query.Method)
	}
	if query.Cursor != "" {
		args = append(args, cursor.BeforeOccurredAt, cursor.RecordID)
		clauses = append(clauses, fmt.Sprintf("(occurred_at, record_id) < ($%d, $%d)", len(args)-1, len(args)))
	}
	args = append(args, query.Limit+1)
	statement := httpActivitySelect + " WHERE " + strings.Join(clauses, " AND ") + fmt.Sprintf(" ORDER BY occurred_at DESC, record_id DESC LIMIT $%d", len(args))
	events, err := readHTTPActivityEvents(ctx, tx, statement, args)
	if err != nil {
		return HTTPActivityPage{}, err
	}
	page := HTTPActivityPage{Schema: SchemaVersion, GeneratedAt: generatedAt, QueryAnchor: anchor, Events: events}
	if len(page.Events) > query.Limit {
		page.Events = page.Events[:query.Limit]
		last := page.Events[len(page.Events)-1]
		page.NextCursor = encodeRecentEventCursor(last.OccurredAt, last.RecordID, anchor)
	}
	if err := tx.Commit(); err != nil {
		return HTTPActivityPage{}, fmt.Errorf("commit HTTP activity query: %w", err)
	}
	if err := page.Validate(query); err != nil {
		return HTTPActivityPage{}, err
	}
	return page, nil
}

const httpActivitySelect = `SELECT record_id, source, kind, occurred_at, received_at,
COALESCE(flow_id, ''), COALESCE(device_id, ''),
COALESCE(payload->>'http_method',''), COALESCE(payload->>'http_scheme',''),
COALESCE(payload->>'http_host',''), COALESCE(payload->>'http_port',''),
COALESCE(payload->>'http_path',''), COALESCE(payload->>'http_status',''),
COALESCE(payload->>'http_version',''), COALESCE(payload->>'request_bytes',''),
COALESCE(payload->>'response_bytes',''), COALESCE(payload->>'decrypted',''),
COALESCE(payload->>'http_url_truncated',''), COALESCE(payload->>'content_local_only',''),
COALESCE(payload->>'http_path_truncated','')
FROM normalized_events`

func readHTTPActivityEvents(ctx context.Context, queryer eventQueryer, statement string, args []any) ([]HTTPActivityEvent, error) {
	rows, err := queryer.QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, fmt.Errorf("query HTTP activity metadata: %w", err)
	}
	defer rows.Close()
	events := make([]HTTPActivityEvent, 0, min(MaxHTTPActivityLimit, len(args)*8))
	for rows.Next() {
		var event HTTPActivityEvent
		var method, scheme, host, port, path, status, version string
		var requestBytes, responseBytes, decrypted, urlTruncated, contentLocalOnly, pathTruncated string
		if err := rows.Scan(
			&event.RecordID, &event.Source, &event.Kind, &event.OccurredAt, &event.ReceivedAt,
			&event.FlowID, &event.DeviceID, &method, &scheme, &host, &port, &path, &status,
			&version, &requestBytes, &responseBytes, &decrypted, &urlTruncated,
			&contentLocalOnly, &pathTruncated,
		); err != nil {
			return nil, fmt.Errorf("decode HTTP activity metadata: %w", err)
		}
		projection := projectHTTPInput(event.Source, event.Kind, httpProjectionInput{
			Method: method, Scheme: scheme, Host: host, Port: port, Path: path, Status: status,
			HTTPVersion: version, RequestBytes: requestBytes, ResponseBytes: responseBytes,
			Decrypted: decrypted, URLTruncated: urlTruncated, ContentLocalOnly: contentLocalOnly,
			PathTruncated: pathTruncated,
		})
		applyHTTPProjection(&event, projection)
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read HTTP activity metadata: %w", err)
	}
	return events, nil
}

func (page HTTPActivityPage) Validate(query HTTPActivityQuery) error {
	if err := validateHTTPActivityQuery(query); err != nil {
		return err
	}
	if page.Schema != SchemaVersion || page.GeneratedAt.IsZero() || page.QueryAnchor.IsZero() || page.QueryAnchor.After(page.GeneratedAt.Add(5*time.Second)) || len(page.Events) > query.Limit || len(page.Events) > MaxHTTPActivityLimit {
		return errors.New("HTTP activity page boundary is invalid")
	}
	if query.Cursor != "" {
		cursor, err := decodeRecentEventCursor(query.Cursor)
		if err != nil || !cursor.TimeAnchor.Equal(page.QueryAnchor) {
			return errors.New("HTTP activity page anchor does not match its cursor")
		}
	}
	minimum := page.QueryAnchor.Add(-time.Duration(query.WindowSeconds) * time.Second)
	for index, event := range page.Events {
		if !validRecordID(event.RecordID) || event.OccurredAt.Year() < 2000 || event.OccurredAt.Year() > 3000 || event.ReceivedAt.Year() < 2000 || event.ReceivedAt.Year() > 3000 || event.OccurredAt.Before(minimum) || event.OccurredAt.After(page.QueryAnchor) || event.FlowID != "" && !opaqueIDPattern.MatchString(event.FlowID) || event.DeviceID != "" && !deviceIDPattern.MatchString(event.DeviceID) || !validHTTPActivityEvent(event) {
			return errors.New("HTTP activity page contains an invalid event")
		}
		if query.DeviceID != "" && event.DeviceID != query.DeviceID || query.Host != "" && event.Host != query.Host || query.Method != "" && event.Method != query.Method {
			return errors.New("HTTP activity page contains an event outside its filter")
		}
		if index > 0 {
			previous := page.Events[index-1]
			if event.OccurredAt.After(previous.OccurredAt) || event.OccurredAt.Equal(previous.OccurredAt) && event.RecordID >= previous.RecordID {
				return errors.New("HTTP activity events are out of order")
			}
		}
	}
	if page.NextCursor != "" {
		cursor, err := decodeRecentEventCursor(page.NextCursor)
		if err != nil || cursor.TimeAnchor.IsZero() || !cursor.TimeAnchor.Equal(page.QueryAnchor) || len(page.Events) == 0 {
			return errors.New("HTTP activity next cursor is invalid")
		}
		last := page.Events[len(page.Events)-1]
		if !cursor.BeforeOccurredAt.Equal(last.OccurredAt) || cursor.RecordID != last.RecordID {
			return errors.New("HTTP activity next cursor does not match the last event")
		}
	}
	return nil
}
