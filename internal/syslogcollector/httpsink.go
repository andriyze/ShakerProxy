package syslogcollector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"shakerproxy.dev/shakerproxy/internal/ingest"
)

// HTTPSink delivers normalized events to ingestd's POST /v1/events, the same
// endpoint the gateway's own services use, authenticated with the ingest
// token. ingestd deduplicates by event ID, so a retried line is harmless.
type HTTPSink struct {
	origin *url.URL
	token  []byte
	client *http.Client
}

// NewHTTPSink builds a sink posting to origin (ingestd's base URL).
func NewHTTPSink(origin string, token []byte) (*HTTPSink, error) {
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, errors.New("ingest origin is invalid")
	}
	if len(token) == 0 {
		return nil, errors.New("ingest token is required")
	}
	return &HTTPSink{
		origin: parsed,
		token:  append([]byte(nil), token...),
		client: &http.Client{Timeout: 10 * time.Second},
	}, nil
}

// Deliver posts one envelope. A non-2xx that is not a duplicate is an error so
// the receiver counts it; 409/410 (duplicate or tombstoned) are treated as
// delivered, since the event will not be accepted again.
func (s *HTTPSink) Deliver(ctx context.Context, envelope ingest.Envelope) error {
	body, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	endpoint := *s.origin
	endpoint.Path = "/v1/events"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+string(s.token))
	request.Header.Set("Content-Type", "application/json")
	response, err := s.client.Do(request)
	if err != nil {
		return err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		response.Body.Close()
	}()
	switch {
	case response.StatusCode >= 200 && response.StatusCode < 300:
		return nil
	case response.StatusCode == http.StatusConflict, response.StatusCode == http.StatusGone:
		return nil
	default:
		return fmt.Errorf("ingest returned HTTP %d", response.StatusCode)
	}
}
