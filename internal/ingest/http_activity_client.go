package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
)

const maxHTTPActivityResponseBytes = 256 << 10

func (c *QueryClient) QueryHTTPActivity(ctx context.Context, query HTTPActivityQuery) (HTTPActivityPage, error) {
	if c == nil || c.endpoint == nil || c.client == nil {
		return HTTPActivityPage{}, errors.New("event query client is unavailable")
	}
	values, err := encodeHTTPActivityQuery(query)
	if err != nil {
		return HTTPActivityPage{}, err
	}
	endpoint := *c.endpoint
	endpoint.Path = "/v1/http-activity"
	endpoint.RawQuery = values.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return HTTPActivityPage{}, errors.New("create HTTP activity request")
	}
	request.Header.Set("Authorization", "Bearer "+string(c.token))
	request.Header.Set("Accept", "application/json")
	response, err := c.client.Do(request)
	if err != nil {
		return HTTPActivityPage{}, fmt.Errorf("request HTTP activity metadata: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return HTTPActivityPage{}, fmt.Errorf("HTTP activity service returned HTTP %d", response.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return HTTPActivityPage{}, errors.New("HTTP activity service returned an invalid content type")
	}
	limited := &io.LimitedReader{R: response.Body, N: maxHTTPActivityResponseBytes + 1}
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	var page HTTPActivityPage
	if err := decoder.Decode(&page); err != nil || decoder.Decode(&struct{}{}) != io.EOF || limited.N <= 0 {
		return HTTPActivityPage{}, errors.New("HTTP activity service returned an invalid or oversized response")
	}
	if err := page.Validate(query); err != nil {
		return HTTPActivityPage{}, fmt.Errorf("HTTP activity service returned an invalid page: %w", err)
	}
	return page, nil
}
