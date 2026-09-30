// Package agentapi provides the deliberately narrow control-plane client used
// by AI-agent integrations. It is not a generic ShakerProxy API client: every
// method is bounded, typed, and selected for safe agent consumption.
package agentapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"shakerproxy.dev/shakerproxy/internal/ingest"
)

const (
	maxTrafficResponseBytes = 512 << 10
	maxDetailResponseBytes  = 256 << 10
	maxAgentTrafficLimit    = 100
	maxEventSummaryBytes    = 512
	maxErrorBodyBytes       = 32 << 10
)

var recordIDPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Client struct {
	base   *url.URL
	token  string
	client *http.Client
}

func NewClient(baseURL, token string, client *http.Client) (*Client, error) {
	baseURL = strings.TrimSpace(baseURL)
	token = strings.TrimSpace(token)
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" && parsed.Path != "/" {
		return nil, errors.New("agent API base URL must be an HTTP(S) service origin")
	}
	if parsed.Scheme != "https" {
		if parsed.Scheme != "http" || !loopbackHost(parsed.Hostname()) {
			return nil, errors.New("agent API cleartext HTTP is permitted only on loopback")
		}
	}
	if len(token) < 40 || len(token) > 128 || !strings.HasPrefix(token, "lgt_") || strings.ContainsAny(token, " \t\r\n,") {
		return nil, errors.New("agent API token is invalid")
	}
	if client == nil {
		client = &http.Client{Timeout: 8 * time.Second}
	} else {
		clone := *client
		client = &clone
		if client.Timeout == 0 || client.Timeout > 30*time.Second {
			client.Timeout = 8 * time.Second
		}
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	parsed.Path = ""
	return &Client{base: parsed, token: token, client: client}, nil
}

func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

type TrafficSearchRequest struct {
	Query  string
	Limit  int
	Cursor string
}

func (request TrafficSearchRequest) validate() error {
	if request.Limit == 0 {
		request.Limit = 50
	}
	if request.Limit < 1 || request.Limit > maxAgentTrafficLimit {
		return fmt.Errorf("agent traffic limit must be between 1 and %d", maxAgentTrafficLimit)
	}
	if len(request.Query) > 2048 || len(request.Cursor) > 4096 || strings.ContainsAny(request.Cursor, "\r\n") {
		return errors.New("agent traffic query or cursor exceeds its bound")
	}
	return nil
}

// Event is one recent event. Summary is the server's plain-language line
// when the control API provides it; it shadows any same-named field of the
// embedded event so decoding stays exact across versions.
type Event struct {
	ingest.RecentEvent
	Summary string `json:"summary,omitempty"`
}

// EventPage is a recent-event page whose events carry Summary.
type EventPage struct {
	ingest.RecentEventPage
	Events []Event `json:"events"`
}

func (c *Client) TrafficSearch(ctx context.Context, request TrafficSearchRequest) (EventPage, error) {
	if c == nil || c.base == nil || c.client == nil {
		return EventPage{}, errors.New("agent API client is unavailable")
	}
	if request.Limit == 0 {
		request.Limit = 50
	}
	if err := request.validate(); err != nil {
		return EventPage{}, err
	}
	values := url.Values{}
	values.Set("limit", strconv.Itoa(request.Limit))
	if request.Query != "" {
		values.Set("q", request.Query)
	}
	if request.Cursor != "" {
		values.Set("cursor", request.Cursor)
	}
	var page EventPage
	if _, err := c.getJSON(ctx, "/api/v1/events", values, maxTrafficResponseBytes, &page); err != nil {
		return EventPage{}, err
	}
	if page.Schema != ingest.SchemaVersion || page.GeneratedAt.IsZero() || len(page.Events) > request.Limit || len(page.Events) > maxAgentTrafficLimit {
		return EventPage{}, errors.New("agent traffic API returned an invalid bounded page")
	}
	for _, event := range page.Events {
		if !recordIDPattern.MatchString(event.RecordID) || len(event.Summary) > maxEventSummaryBytes {
			return EventPage{}, errors.New("agent traffic API returned an invalid event identity")
		}
	}
	return page, nil
}

func (c *Client) EventMetadata(ctx context.Context, recordID string) (ingest.EventDetail, error) {
	if c == nil || c.base == nil || c.client == nil {
		return ingest.EventDetail{}, errors.New("agent API client is unavailable")
	}
	if !recordIDPattern.MatchString(recordID) {
		return ingest.EventDetail{}, errors.New("agent event record ID is invalid")
	}
	var detail ingest.EventDetail
	headers, err := c.getJSON(ctx, "/api/v1/events/"+recordID, nil, maxDetailResponseBytes, &detail)
	if err != nil {
		return ingest.EventDetail{}, err
	}
	if headers.Get("X-ShakerProxy-Event-Detail") != "metadata-only" {
		return ingest.EventDetail{}, errors.New("agent event detail was not explicitly marked metadata-only")
	}
	if detail.Event.RecordID != recordID || detail.Validate() != nil {
		return ingest.EventDetail{}, errors.New("agent event detail response is invalid")
	}
	if err := validateMetadataOnlyPayload(detail.Payload); err != nil {
		return ingest.EventDetail{}, err
	}
	return detail, nil
}

func (c *Client) getJSON(ctx context.Context, path string, values url.Values, maximum int64, dst any) (http.Header, error) {
	return c.getJSONWith(ctx, path, values, maximum, dst, true)
}

// getJSONWith performs one bounded GET. strict rejects unknown fields; it is
// relaxed only for endpoints another component owns and may extend.
func (c *Client) getJSONWith(ctx context.Context, path string, values url.Values, maximum int64, dst any, strict bool) (http.Header, error) {
	if !strings.HasPrefix(path, "/api/v1/") || strings.Contains(path, "..") || maximum < 1024 || maximum > 1<<20 {
		return nil, errors.New("agent API request boundary is invalid")
	}
	endpoint := *c.base
	endpoint.Path = path
	if values != nil {
		endpoint.RawQuery = values.Encode()
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, errors.New("create agent API request")
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	request.Header.Set("Accept", "application/json")
	response, err := c.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("request agent API: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, decodeAPIError(response)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return nil, errors.New("agent API returned an invalid content type")
	}
	limited := &io.LimitedReader{R: response.Body, N: maximum + 1}
	decoder := json.NewDecoder(limited)
	if strict {
		decoder.DisallowUnknownFields()
	}
	if err := decoder.Decode(dst); err != nil || decoder.Decode(&struct{}{}) != io.EOF || limited.N <= 0 {
		return nil, errors.New("agent API returned invalid or oversized JSON")
	}
	return response.Header.Clone(), nil
}
