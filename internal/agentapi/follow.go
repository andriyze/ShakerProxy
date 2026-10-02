package agentapi

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"shakerproxy.dev/shakerproxy/internal/ingest"
)

const (
	// MaxFollowWait bounds how long one follow call waits for new events.
	MaxFollowWait       = 25 * time.Second
	maxFollowFrameBytes = 768 << 10
)

// FollowRequest continues the live event stream after Cursor: a live_cursor
// from a traffic search, or the next_cursor of a previous follow call.
type FollowRequest struct {
	Query  string
	Cursor string
	Limit  int
	Wait   time.Duration
}

// FollowBatch is what arrived after the cursor, in arrival order. NextCursor
// is where the next call continues; it equals the request cursor when
// nothing arrived within the wait.
type FollowBatch struct {
	Events         []Event
	NextCursor     string
	CanonicalQuery string
	TimedOut       bool
}

type liveFrame struct {
	Schema                int       `json:"schema"`
	GeneratedAt           time.Time `json:"generated_at"`
	Events                []Event   `json:"events"`
	NextCursor            string    `json:"next_cursor"`
	CanonicalQuery        string    `json:"canonical_query,omitempty"`
	QueryAnchor           time.Time `json:"query_anchor,omitempty"`
	DeviceLabelsAvailable bool      `json:"device_labels_available"`
}

func (request FollowRequest) validate() error {
	if request.Limit < 1 || request.Limit > maxAgentTrafficLimit {
		return fmt.Errorf("agent follow limit must be between 1 and %d", maxAgentTrafficLimit)
	}
	if request.Cursor == "" || len(request.Query) > 2048 || len(request.Cursor) > 4096 || strings.ContainsAny(request.Cursor, "\r\n") {
		return errors.New("agent follow query or cursor is missing or exceeds its bound")
	}
	if request.Wait < 0 || request.Wait > MaxFollowWait {
		return fmt.Errorf("agent follow wait must be between 0 and %s", MaxFollowWait)
	}
	return nil
}

// FollowTraffic reads the live event stream once: it returns the first batch
// that arrives after the cursor, or an empty batch when the wait ends.
func (c *Client) FollowTraffic(ctx context.Context, request FollowRequest) (FollowBatch, error) {
	if c == nil || c.base == nil || c.client == nil {
		return FollowBatch{}, errors.New("agent API client is unavailable")
	}
	if request.Limit == 0 {
		request.Limit = 50
	}
	if err := request.validate(); err != nil {
		return FollowBatch{}, err
	}
	values := url.Values{}
	values.Set("limit", strconv.Itoa(request.Limit))
	values.Set("cursor", request.Cursor)
	if request.Query != "" {
		values.Set("q", request.Query)
	}
	endpoint := *c.base
	endpoint.Path = "/api/v1/events/live"
	endpoint.RawQuery = values.Encode()
	waitCtx, cancel := context.WithTimeout(ctx, request.Wait+2*time.Second)
	defer cancel()
	httpRequest, err := http.NewRequestWithContext(waitCtx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return FollowBatch{}, errors.New("create agent follow request")
	}
	httpRequest.Header.Set("Authorization", "Bearer "+c.token)
	httpRequest.Header.Set("Accept", "text/event-stream")
	stream := *c.client
	stream.Timeout = 0 // the context bounds the stream
	response, err := stream.Do(httpRequest)
	if err != nil {
		return FollowBatch{}, fmt.Errorf("request agent live events: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return FollowBatch{}, decodeAPIError(response)
	}
	if mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type")); err != nil || mediaType != "text/event-stream" {
		return FollowBatch{}, errors.New("agent live events returned an invalid content type")
	}
	deadline := time.Now().Add(request.Wait)
	scanner := bufio.NewScanner(response.Body)
	scanner.Buffer(make([]byte, 0, 64<<10), maxFollowFrameBytes)
	eventName, data := "", bytes.Buffer{}
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case line == "":
			if eventName == "events" && data.Len() > 0 {
				return decodeLiveFrame(data.Bytes(), request.Limit)
			}
			eventName = ""
			data.Reset()
			if time.Now().After(deadline) {
				return FollowBatch{NextCursor: request.Cursor, TimedOut: true}, nil
			}
		case strings.HasPrefix(line, ":"), strings.HasPrefix(line, "id:"):
		case strings.HasPrefix(line, "event:"):
			eventName = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:"):
			if data.Len()+len(line) > maxFollowFrameBytes {
				return FollowBatch{}, errors.New("agent live events frame exceeds its bound")
			}
			data.WriteString(strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
	}
	if waitCtx.Err() != nil && ctx.Err() == nil {
		return FollowBatch{NextCursor: request.Cursor, TimedOut: true}, nil
	}
	if err := scanner.Err(); err != nil && ctx.Err() == nil {
		return FollowBatch{}, errors.New("agent live events stream failed or exceeded its bound")
	}
	if ctx.Err() != nil {
		return FollowBatch{}, ctx.Err()
	}
	return FollowBatch{NextCursor: request.Cursor, TimedOut: true}, nil
}

func decodeLiveFrame(data []byte, limit int) (FollowBatch, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var frame liveFrame
	if err := decoder.Decode(&frame); err != nil {
		return FollowBatch{}, errors.New("agent live events returned invalid JSON")
	}
	if frame.Schema != ingest.SchemaVersion || frame.GeneratedAt.IsZero() || len(frame.Events) > limit || frame.NextCursor == "" || len(frame.NextCursor) > 4096 || strings.ContainsAny(frame.NextCursor, "\r\n") {
		return FollowBatch{}, errors.New("agent live events returned an invalid bounded batch")
	}
	for _, event := range frame.Events {
		if !recordIDPattern.MatchString(event.RecordID) || len(event.Summary) > maxEventSummaryBytes {
			return FollowBatch{}, errors.New("agent live events returned an invalid event identity")
		}
	}
	return FollowBatch{Events: frame.Events, NextCursor: frame.NextCursor, CanonicalQuery: frame.CanonicalQuery}, nil
}
