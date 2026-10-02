package agentapi

import (
	"context"
	"errors"
	"time"

	"shakerproxy.dev/shakerproxy/internal/httpexchange"
)

// maxHTTPExchangeBytes bounds one exchange response: up to 32 request and
// response pairs with bounded headers and body previews.
const maxHTTPExchangeBytes = 1 << 20

// HTTPExchangeCapture says which part of the packet recording an exchange
// was read from.
type HTTPExchangeCapture struct {
	SessionID       string     `json:"session_id"`
	SegmentsRead    int        `json:"segments_read"`
	SegmentsMissing int        `json:"segments_missing"`
	Packets         int        `json:"packets"`
	FirstPacketAt   *time.Time `json:"first_packet_at,omitempty"`
	LastPacketAt    *time.Time `json:"last_packet_at,omitempty"`
	FromStart       bool       `json:"from_start"`
	Closed          bool       `json:"closed"`
	Incomplete      bool       `json:"incomplete"`
}

// HTTPExchange is an HTTP event's requests and responses as an API token
// with the traffic:content scope reads them: credentials are already
// removed by the server.
type HTTPExchange struct {
	Schema    int                     `json:"schema"`
	RecordID  string                  `json:"record_id"`
	Source    string                  `json:"source"`
	State     string                  `json:"state"`
	Reason    string                  `json:"reason,omitempty"`
	Matched   int                     `json:"matched"`
	Exchanges []httpexchange.Exchange `json:"exchanges"`
	Notes     []string                `json:"notes,omitempty"`
	Capture   *HTTPExchangeCapture    `json:"capture,omitempty"`
}

// HTTPExchange reads one HTTP event's request and response. It needs a token
// with traffic:content and refuses a response the server did not mark as
// credential-redacted, so a misconfigured server cannot hand an agent
// cookies or authorization headers.
func (c *Client) HTTPExchange(ctx context.Context, recordID string) (HTTPExchange, error) {
	if c == nil || c.base == nil || c.client == nil {
		return HTTPExchange{}, errors.New("agent API client is unavailable")
	}
	if !recordIDPattern.MatchString(recordID) {
		return HTTPExchange{}, errors.New("agent event record ID is invalid")
	}
	var exchange HTTPExchange
	headers, err := c.getJSON(ctx, "/api/v1/events/"+recordID+"/http-exchange", nil, maxHTTPExchangeBytes, &exchange)
	if err != nil {
		return HTTPExchange{}, err
	}
	if headers.Get("X-ShakerProxy-HTTP-Exchange") != "credentials-redacted" {
		return HTTPExchange{}, errors.New("agent HTTP exchange was not explicitly marked credential-redacted")
	}
	if err := validateHTTPExchange(exchange, recordID); err != nil {
		return HTTPExchange{}, err
	}
	return exchange, nil
}

func validateHTTPExchange(exchange HTTPExchange, recordID string) error {
	if exchange.Schema != 1 || exchange.RecordID != recordID || exchange.Source != "CAPTURE" && exchange.Source != "DECRYPTED" {
		return errors.New("agent HTTP exchange response is invalid")
	}
	switch exchange.State {
	case "AVAILABLE", "UNAVAILABLE", "RETRY":
	default:
		return errors.New("agent HTTP exchange state is invalid")
	}
	if len(exchange.Exchanges) > httpexchange.MaxExchanges || exchange.Matched < -1 || exchange.Matched >= max(len(exchange.Exchanges), 1) || len(exchange.Notes) > 16 || !boundedAgentText(exchange.Reason, 0, 512) {
		return errors.New("agent HTTP exchange response exceeds its bounds")
	}
	for _, note := range exchange.Notes {
		if !boundedAgentText(note, 1, 512) {
			return errors.New("agent HTTP exchange note is invalid")
		}
	}
	for _, pair := range exchange.Exchanges {
		var headers []httpexchange.Headers
		if pair.Request != nil {
			headers = append(headers, pair.Request.Headers)
		}
		if pair.Response != nil {
			headers = append(headers, pair.Response.Headers)
		}
		for _, set := range headers {
			if len(set.Items) > httpexchange.MaxHeaders {
				return errors.New("agent HTTP exchange has too many headers")
			}
			for _, header := range set.Items {
				if (header.Sensitive || httpexchange.IsSensitiveHeader(header.Name)) && header.Value != httpexchange.Redacted {
					return errors.New("agent HTTP exchange contains an unredacted credential header")
				}
			}
		}
	}
	return nil
}
