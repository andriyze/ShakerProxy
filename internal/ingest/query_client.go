package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"shakerproxy.dev/shakerproxy/internal/capture"
	"shakerproxy.dev/shakerproxy/internal/querylang"
)

// maxRecentEventResponseBytes bounds a 100-event page. Each event can carry
// bounded DNS, TLS, HTTP, alert, detection, and summary text (about 3 KiB in
// the worst case), plus facets.
const maxRecentEventResponseBytes = 512 << 10

type QueryClient struct {
	endpoint *url.URL
	token    []byte
	client   *http.Client
}

func NewQueryClient(baseURL string, token []byte, client *http.Client) (*QueryClient, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme != "http" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" && parsed.Path != "/" {
		return nil, errors.New("event query URL must be an HTTP service origin")
	}
	if len(token) < 32 || len(token) > 128 {
		return nil, errors.New("event query token must contain 32 to 128 characters")
	}
	for _, char := range token {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '-' || char == '_') {
			return nil, errors.New("event query token contains an invalid character")
		}
	}
	if client == nil {
		client = &http.Client{Timeout: 4 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	return &QueryClient{endpoint: parsed, token: append([]byte(nil), token...), client: client}, nil
}

func (c *QueryClient) QueryRecent(ctx context.Context, query RecentEventQuery) (RecentEventPage, error) {
	if c == nil || c.endpoint == nil || c.client == nil {
		return RecentEventPage{}, errors.New("event query client is unavailable")
	}
	if err := validateRecentEventQuery(query); err != nil {
		return RecentEventPage{}, err
	}
	publicCanonical := query.Filter.Canonical
	query, err := prepareStorageRecentQuery(query)
	if err != nil {
		return RecentEventPage{}, err
	}
	endpoint := *c.endpoint
	endpoint.Path = "/v1/events"
	values, err := encodeInternalRecentEventQuery(query)
	if err != nil {
		return RecentEventPage{}, err
	}
	endpoint.RawQuery = values.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return RecentEventPage{}, errors.New("create event query request")
	}
	request.Header.Set("Authorization", "Bearer "+string(c.token))
	request.Header.Set("Accept", "application/json")
	response, err := c.client.Do(request)
	if err != nil {
		return RecentEventPage{}, fmt.Errorf("request recent normalized events: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return RecentEventPage{}, fmt.Errorf("event query service returned HTTP %d", response.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return RecentEventPage{}, errors.New("event query service returned an invalid content type")
	}
	limited := &io.LimitedReader{R: response.Body, N: maxRecentEventResponseBytes + 1}
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	var page RecentEventPage
	if err := decoder.Decode(&page); err != nil || decoder.Decode(&struct{}{}) != io.EOF || limited.N <= 0 {
		return RecentEventPage{}, errors.New("event query service returned an invalid or oversized response")
	}
	if (query.BeforeOccurredAt.IsZero() && page.Facets == nil) || (!query.BeforeOccurredAt.IsZero() && page.Facets != nil) {
		return RecentEventPage{}, errors.New("event query service returned facets outside the initial page")
	}
	if err := validateRecentEventPage(page, query); err != nil {
		return RecentEventPage{}, err
	}
	page.CanonicalQuery = publicCanonical
	return page, nil
}

func (c *QueryClient) QueryAfter(ctx context.Context, query LiveEventQuery) (LiveEventBatch, error) {
	if c == nil || c.endpoint == nil || c.client == nil {
		return LiveEventBatch{}, errors.New("event query client is unavailable")
	}
	if querylang.HasRelativeTime(query.Filter) && query.TimeAnchor.IsZero() {
		query.TimeAnchor = query.AfterReceivedAt.UTC()
	}
	if err := validateLiveEventQuery(query); err != nil {
		return LiveEventBatch{}, err
	}
	publicCanonical := query.Filter.Canonical
	storageBase, err := prepareStorageRecentQuery(query.RecentEventQuery)
	if err != nil {
		return LiveEventBatch{}, err
	}
	query.RecentEventQuery = storageBase
	endpoint := *c.endpoint
	endpoint.Path = "/v1/events/live-batch"
	values, err := encodeInternalLiveEventQuery(query)
	if err != nil {
		return LiveEventBatch{}, err
	}
	endpoint.RawQuery = values.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return LiveEventBatch{}, errors.New("create live event query request")
	}
	request.Header.Set("Authorization", "Bearer "+string(c.token))
	request.Header.Set("Accept", "application/json")
	response, err := c.client.Do(request)
	if err != nil {
		return LiveEventBatch{}, fmt.Errorf("request live normalized events: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return LiveEventBatch{}, fmt.Errorf("event query service returned HTTP %d", response.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return LiveEventBatch{}, errors.New("event query service returned an invalid content type")
	}
	limited := &io.LimitedReader{R: response.Body, N: maxRecentEventResponseBytes + 1}
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	var batch LiveEventBatch
	if err := decoder.Decode(&batch); err != nil || decoder.Decode(&struct{}{}) != io.EOF || limited.N <= 0 || validateLiveEventBatch(batch, query) != nil {
		return LiveEventBatch{}, errors.New("event query service returned an invalid live batch")
	}
	batch.CanonicalQuery = publicCanonical
	return batch, nil
}

func prepareStorageRecentQuery(query RecentEventQuery) (RecentEventQuery, error) {
	parsed, err := querylang.Parse(query.Filter.Canonical)
	if err != nil || parsed.Canonical != query.Filter.Canonical {
		return RecentEventQuery{}, errors.New("prepare storage query from invalid canonical filter")
	}
	names := querylang.DeviceNameValues(parsed)
	tags := querylang.DeviceTagValues(parsed)
	if len(names) == 0 && len(tags) == 0 {
		query.Filter = parsed
		return query, nil
	}
	nameReplacements := make(map[string]string, len(names))
	nameResolutions := make(map[string][]string, len(names))
	for index, name := range names {
		reference := fmt.Sprintf("alias-ref-%02d", index+1)
		nameReplacements[name] = reference
		nameResolutions[reference] = append([]string(nil), query.DeviceNameResolutions[name]...)
	}
	rewritten, err := querylang.RewriteDeviceNames(parsed, nameReplacements)
	if err != nil {
		return RecentEventQuery{}, err
	}
	tagReplacements := make(map[string]string, len(tags))
	tagResolutions := make(map[string][]string, len(tags))
	for index, tag := range tags {
		reference := fmt.Sprintf("tag-ref-%02d", index+1)
		tagReplacements[tag] = reference
		tagResolutions[reference] = append([]string(nil), query.DeviceTagResolutions[tag]...)
	}
	rewritten, err = querylang.RewriteDeviceTags(rewritten, tagReplacements)
	if err != nil {
		return RecentEventQuery{}, err
	}
	query.Filter = rewritten
	query.DeviceNameResolutions = nameResolutions
	query.DeviceTagResolutions = tagResolutions
	return query, nil
}

func (c *QueryClient) IngestStatus(ctx context.Context) (Stats, error) {
	if c == nil || c.endpoint == nil || c.client == nil {
		return Stats{}, errors.New("event query client is unavailable")
	}
	endpoint := *c.endpoint
	endpoint.Path = "/v1/query-stats"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return Stats{}, errors.New("create ingestion status request")
	}
	request.Header.Set("Authorization", "Bearer "+string(c.token))
	request.Header.Set("Accept", "application/json")
	response, err := c.client.Do(request)
	if err != nil {
		return Stats{}, fmt.Errorf("request ingestion status: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return Stats{}, fmt.Errorf("event query service returned HTTP %d", response.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return Stats{}, errors.New("event query service returned an invalid content type")
	}
	limited := &io.LimitedReader{R: response.Body, N: (32 << 10) + 1}
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	var stats Stats
	if err := decoder.Decode(&stats); err != nil || decoder.Decode(&struct{}{}) != io.EOF || limited.N <= 0 || validateIngestStatus(stats) != nil {
		return Stats{}, errors.New("event query service returned an invalid ingestion status")
	}
	return stats, nil
}

func validateIngestStatus(stats Stats) error {
	if stats.Schema != SchemaVersion || stats.GeneratedAt.IsZero() || stats.PendingRecords < 0 || stats.PendingRecords > MaxPendingRecords || stats.PendingBytes < 0 || stats.QuarantinedRecords < 0 || stats.QuarantinedBytes < 0 || stats.IngestLagSeconds < 0 {
		return errors.New("invalid ingestion status")
	}
	if stats.PendingRecords == 0 && (!stats.OldestPendingAt.IsZero() || stats.IngestLagSeconds != 0) || stats.PendingRecords > 0 && stats.OldestPendingAt.IsZero() {
		return errors.New("inconsistent ingestion status")
	}
	if stats.DatabaseConnected && !stats.DatabaseConfigured {
		return errors.New("inconsistent database status")
	}
	return nil
}

var recentRecordIDPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

func validateRecentEventPage(page RecentEventPage, query RecentEventQuery) error {
	if page.Schema != SchemaVersion || page.GeneratedAt.IsZero() || len(page.Events) > query.Limit || len(page.Events) > MaxRecentEventLimit || page.CanonicalQuery != query.Filter.Canonical || page.DeviceLabelsAvailable {
		return errors.New("event query service returned an invalid page")
	}
	if querylang.HasRelativeTime(query.Filter) {
		expectedAnchor := query.TimeAnchor
		if expectedAnchor.IsZero() {
			expectedAnchor = page.GeneratedAt
		}
		if page.QueryAnchor.IsZero() || !page.QueryAnchor.Equal(expectedAnchor) {
			return errors.New("event query service returned an invalid query anchor")
		}
	} else if !page.QueryAnchor.IsZero() {
		return errors.New("event query service returned an unexpected query anchor")
	}
	if page.Facets != nil {
		if err := validateEventFacets(*page.Facets, len(page.Events)); err != nil {
			return err
		}
	}
	liveCursor, err := decodeLiveEventCursor(page.LiveCursor)
	if err != nil || !liveCursor.AfterReceivedAt.Equal(page.GeneratedAt) || liveCursor.RecordID != strings.Repeat("0", 64) || querylang.HasRelativeTime(query.Filter) && !liveCursor.TimeAnchor.Equal(page.QueryAnchor) || !querylang.HasRelativeTime(query.Filter) && !liveCursor.TimeAnchor.IsZero() {
		return errors.New("event query service returned an invalid live cursor")
	}
	for index, event := range page.Events {
		if event.DeviceFriendlyName != "" || event.DeviceFriendlyNameAtCapture != "" || event.DeviceFriendlyNameAtCaptureKnown || event.DeviceAliasRevision != 0 || event.DeviceFriendlyNameConflict {
			return errors.New("event query service returned an unauthorized device name projection")
		}
		if !recentRecordIDPattern.MatchString(event.RecordID) || !validText(event.Kind, 1, MaxTextBytes) || !validText(event.SourceVersion, 1, MaxTextBytes) || !validText(event.ParserVersion, 1, MaxTextBytes) || event.OccurredAt.Year() < 2000 || event.OccurredAt.Year() > 3000 || event.ReceivedAt.Year() < 2000 || event.ReceivedAt.Year() > 3000 || event.Confidence < 0 || event.Confidence > 100 {
			return errors.New("event query service returned an invalid event")
		}
		switch event.Source {
		case SourceHost, SourceZeek, SourceSuricata, SourceMitmproxy:
		default:
			return errors.New("event query service returned an invalid event source")
		}
		if event.CaptureSessionID != "" && !capture.ValidSessionID(event.CaptureSessionID) || event.DeviceID != "" && !deviceIDPattern.MatchString(event.DeviceID) || event.FlowID != "" && !opaqueIDPattern.MatchString(event.FlowID) {
			return errors.New("event query service returned an invalid event reference")
		}
		if !validProjectionIP(event.SourceIP) || !validProjectionIP(event.DestinationIP) || event.SourcePort < 0 || event.SourcePort > 65535 || event.DestinationPort < 0 || event.DestinationPort > 65535 || event.Protocol != "" && !projectionTextPattern.MatchString(event.Protocol) || event.Service != "" && !projectionTextPattern.MatchString(event.Service) || event.NetworkBytes < 0 {
			return errors.New("event query service returned an invalid network projection")
		}
		if event.DetectionType != "" && !validDetectionType(event.DetectionType) || event.DetectionSeverity != "" && !validDetectionSeverity(event.DetectionSeverity) || event.DetectionState != "" && !validDetectionState(event.DetectionState) || event.DetectionSummary != "" && !validText(event.DetectionSummary, 1, 256) || event.DetectionScope != "" && !detectionScopePattern.MatchString(event.DetectionScope) {
			return errors.New("event query service returned an invalid detection projection")
		}
		if !validEventDNSAnswers(event.DNSAnswers) {
			return errors.New("event query service returned invalid DNS answers")
		}
		if event.BlockedReason != "" && (!event.Blocked || !validBlockReasons[event.BlockedReason]) {
			return errors.New("event query service returned an invalid block reason")
		}
		if !validTLSProjection(event) {
			return errors.New("event query service returned an invalid TLS projection")
		}
		if !validProtocolProjection(event) || !validEventHTTPColumns(event) || !validEventAlert(event) || !validEventSummary(event.Summary) {
			return errors.New("event query service returned an invalid plain-language projection")
		}
		if event.AttributionEvidence != nil && event.AttributionEvidence.Validate(event) != nil {
			return errors.New("event query service returned invalid attribution evidence")
		}
		if query.Source != "" && event.Source != query.Source || query.Kind != "" && event.Kind != query.Kind || query.CaptureSessionID != "" && event.CaptureSessionID != query.CaptureSessionID || query.DeviceID != "" && event.DeviceID != query.DeviceID {
			return errors.New("event query service returned an event outside the requested filter")
		}
		if index > 0 {
			previous := page.Events[index-1]
			if event.OccurredAt.After(previous.OccurredAt) || event.OccurredAt.Equal(previous.OccurredAt) && event.RecordID >= previous.RecordID {
				return errors.New("event query service returned events in an invalid order")
			}
		}
	}
	if page.NextCursor != "" {
		cursor, err := decodeRecentEventCursor(page.NextCursor)
		if err != nil || len(page.Events) == 0 {
			return errors.New("event query service returned an invalid cursor")
		}
		last := page.Events[len(page.Events)-1]
		if !cursor.BeforeOccurredAt.Equal(last.OccurredAt) || cursor.RecordID != last.RecordID || querylang.HasRelativeTime(query.Filter) && !cursor.TimeAnchor.Equal(page.QueryAnchor) || !querylang.HasRelativeTime(query.Filter) && !cursor.TimeAnchor.IsZero() {
			return errors.New("event query service returned a cursor outside the page")
		}
	}
	return nil
}

func validateEventFacets(facets EventFacets, visibleEvents int) error {
	if facets.MatchedCount < int64(visibleEvents) || facets.MatchedCount < 0 || facets.MatchedCount > MaxEventFacetInput || len(facets.Fields) != 4 {
		return errors.New("event query service returned invalid facet bounds")
	}
	if facets.Exact {
		if facets.CountRelation != "eq" || facets.Basis != "all_matches" {
			return errors.New("event query service returned an invalid exact facet basis")
		}
	} else if facets.MatchedCount != MaxEventFacetInput || facets.CountRelation != "gte" || facets.Basis != "newest_sample" {
		return errors.New("event query service returned an invalid sampled facet basis")
	}
	expectedFields := []string{"source", "kind", "protocol", "service"}
	for index, facet := range facets.Fields {
		if facet.Field != expectedFields[index] || len(facet.Values) > MaxEventFacetValues || facet.OtherCount < 0 {
			return errors.New("event query service returned an invalid facet field")
		}
		total := facet.OtherCount
		for valueIndex, value := range facet.Values {
			if value.Count < 1 || value.Count > facets.MatchedCount || !validFacetValue(facet.Field, value.Value) {
				return errors.New("event query service returned an invalid facet value")
			}
			if valueIndex > 0 {
				previous := facet.Values[valueIndex-1]
				if value.Count > previous.Count || value.Count == previous.Count && value.Value <= previous.Value {
					return errors.New("event query service returned facet values out of order")
				}
			}
			total += value.Count
		}
		if total != facets.MatchedCount {
			return errors.New("event query service returned inconsistent facet counts")
		}
	}
	return validateEventDomains(facets.Domains)
}

func validFacetValue(field, value string) bool {
	switch field {
	case "source":
		switch Source(value) {
		case SourceHost, SourceZeek, SourceSuricata, SourceMitmproxy:
			return true
		}
	case "kind":
		return validText(value, 1, MaxTextBytes)
	case "protocol", "service":
		return value == "" || projectionTextPattern.MatchString(value)
	}
	return false
}

func validateLiveEventBatch(batch LiveEventBatch, query LiveEventQuery) error {
	if batch.Schema != SchemaVersion || batch.GeneratedAt.IsZero() || len(batch.Events) > query.Limit || batch.CanonicalQuery != query.Filter.Canonical || batch.NextCursor == "" || batch.DeviceLabelsAvailable {
		return errors.New("invalid live event batch")
	}
	if querylang.HasRelativeTime(query.Filter) {
		if batch.QueryAnchor.IsZero() || !batch.QueryAnchor.Equal(query.TimeAnchor) {
			return errors.New("invalid live query anchor")
		}
	} else if !batch.QueryAnchor.IsZero() {
		return errors.New("unexpected live query anchor")
	}
	nextCursor, err := decodeLiveEventCursor(batch.NextCursor)
	if err != nil || nextCursor.AfterReceivedAt.Before(query.AfterReceivedAt) || nextCursor.AfterReceivedAt.Equal(query.AfterReceivedAt) && nextCursor.RecordID < query.AfterRecordID || querylang.HasRelativeTime(query.Filter) && !nextCursor.TimeAnchor.Equal(batch.QueryAnchor) || !querylang.HasRelativeTime(query.Filter) && !nextCursor.TimeAnchor.IsZero() {
		return errors.New("invalid live event cursor")
	}
	for index, event := range batch.Events {
		page := RecentEventPage{Schema: SchemaVersion, GeneratedAt: batch.GeneratedAt, LiveCursor: encodeAnchoredLiveEventCursor(batch.GeneratedAt, strings.Repeat("0", 64), batch.QueryAnchor), Events: []RecentEvent{event}, CanonicalQuery: query.Filter.Canonical, QueryAnchor: batch.QueryAnchor}
		if validateRecentEventPage(page, query.RecentEventQuery) != nil || event.ReceivedAt.Before(query.AfterReceivedAt) || event.ReceivedAt.Equal(query.AfterReceivedAt) && event.RecordID <= query.AfterRecordID {
			return errors.New("invalid live event")
		}
		if index > 0 {
			previous := batch.Events[index-1]
			if event.ReceivedAt.Before(previous.ReceivedAt) || event.ReceivedAt.Equal(previous.ReceivedAt) && event.RecordID <= previous.RecordID {
				return errors.New("live events are out of order")
			}
		}
	}
	if len(batch.Events) > 0 {
		last := batch.Events[len(batch.Events)-1]
		if !nextCursor.AfterReceivedAt.Equal(last.ReceivedAt) || nextCursor.RecordID != last.RecordID {
			return errors.New("live cursor does not match the last event")
		}
	}
	return nil
}
