package agentapi

import (
	"context"
	"errors"
	"net/url"
	"strconv"
	"strings"

	"shakerproxy.dev/shakerproxy/internal/ingest"
)

const maxAgentHTTPActivityResponseBytes = 256 << 10

var agentHTTPActivityWindows = map[string]int{
	"5m": 5 * 60, "15m": 15 * 60, "1h": 60 * 60, "6h": 6 * 60 * 60, "24h": 24 * 60 * 60,
}

type HTTPActivityRequest struct {
	Window   string
	DeviceID string
	Host     string
	Method   string
	Limit    int
	Cursor   string
}

func (c *Client) HTTPActivity(ctx context.Context, request HTTPActivityRequest) (ingest.HTTPActivityPage, error) {
	if c == nil || c.base == nil || c.client == nil {
		return ingest.HTTPActivityPage{}, errors.New("agent API client is unavailable")
	}
	request.Window = strings.ToLower(strings.TrimSpace(request.Window))
	if request.Window == "" {
		request.Window = "15m"
	}
	windowSeconds, ok := agentHTTPActivityWindows[request.Window]
	if !ok {
		return ingest.HTTPActivityPage{}, errors.New("agent HTTP activity window must be 5m, 15m, 1h, 6h, or 24h")
	}
	if request.Limit == 0 {
		request.Limit = ingest.DefaultHTTPActivityLimit
	}
	if request.Limit < 1 || request.Limit > ingest.MaxHTTPActivityLimit {
		return ingest.HTTPActivityPage{}, errors.New("agent HTTP activity limit must be between 1 and 100")
	}
	request.DeviceID = strings.TrimSpace(request.DeviceID)
	if request.DeviceID != "" && !agentDeviceIDPattern.MatchString(request.DeviceID) {
		return ingest.HTTPActivityPage{}, errors.New("agent HTTP activity device ID is invalid")
	}
	request.Host = strings.TrimSpace(request.Host)
	if request.Host != "" {
		host, err := ingest.CanonicalHTTPHost(request.Host)
		if err != nil {
			return ingest.HTTPActivityPage{}, err
		}
		request.Host = host
	}
	request.Method = strings.TrimSpace(request.Method)
	if request.Method != "" {
		method, err := ingest.CanonicalHTTPMethod(request.Method)
		if err != nil {
			return ingest.HTTPActivityPage{}, err
		}
		request.Method = method
	}
	request.Cursor = strings.TrimSpace(request.Cursor)
	if len(request.Cursor) > 256 || strings.ContainsAny(request.Cursor, "\r\n") {
		return ingest.HTTPActivityPage{}, errors.New("agent HTTP activity cursor is invalid")
	}
	values := make(url.Values)
	values.Set("window", request.Window)
	values.Set("limit", strconv.Itoa(request.Limit))
	if request.DeviceID != "" {
		values.Set("device_id", request.DeviceID)
	}
	if request.Host != "" {
		values.Set("host", request.Host)
	}
	if request.Method != "" {
		values.Set("method", request.Method)
	}
	if request.Cursor != "" {
		values.Set("cursor", request.Cursor)
	}
	var page ingest.HTTPActivityPage
	if _, err := c.getJSON(ctx, "/api/v1/agent/http-activity", values, maxAgentHTTPActivityResponseBytes, &page); err != nil {
		return ingest.HTTPActivityPage{}, err
	}
	query := ingest.HTTPActivityQuery{
		Limit: request.Limit, WindowSeconds: windowSeconds, DeviceID: request.DeviceID,
		Host: request.Host, Method: request.Method, Cursor: request.Cursor,
	}
	if err := page.Validate(query); err != nil {
		return ingest.HTTPActivityPage{}, errors.New("agent HTTP activity API returned an invalid bounded page")
	}
	return page, nil
}
