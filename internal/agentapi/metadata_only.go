package agentapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"strings"
)

const (
	maxMetadataDepth = 16
	maxMetadataNodes = 8192
)

var forbiddenAgentPayloadKeys = map[string]struct{}{
	"authorization":       {},
	"body":                {},
	"body_preview":        {},
	"content":             {},
	"cookie":              {},
	"headers":             {},
	"preview":             {},
	"proxy_authorization": {},
	"raw_content":         {},
	"request_body":        {},
	"request_headers":     {},
	"response_body":       {},
	"response_headers":    {},
	"set_cookie":          {},
	"tls_keylog":          {},
	"x_access_token":      {},
	"x_api_key":           {},
	"x_auth_token":        {},
}

// validateMetadataOnlyPayload provides defense in depth beyond the server's
// X-ShakerProxy-Event-Detail attestation. An accidentally or maliciously mislabeled
// response cannot smuggle decrypted headers, bodies, credentials, or a
// query-bearing URL into an AI-agent process.
func validateMetadataOnlyPayload(raw json.RawMessage) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return errors.New("agent event metadata payload is invalid")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("agent event metadata payload is invalid")
	}
	nodes := 0
	var walk func(any, int) error
	walk = func(current any, depth int) error {
		if depth > maxMetadataDepth {
			return errors.New("agent event metadata nesting exceeds its bound")
		}
		nodes++
		if nodes > maxMetadataNodes {
			return errors.New("agent event metadata node count exceeds its bound")
		}
		switch typed := current.(type) {
		case map[string]any:
			for key, item := range typed {
				normalized := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(key), "-", "_"))
				if _, forbidden := forbiddenAgentPayloadKeys[normalized]; forbidden {
					return errors.New("agent event metadata contains a forbidden plaintext or secret field")
				}
				if normalized == "http_url" {
					text, ok := item.(string)
					if !ok {
						return errors.New("agent event metadata URL is invalid")
					}
					parsed, err := url.Parse(text)
					if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
						return errors.New("agent event metadata URL contains credentials, query parameters, or a fragment")
					}
				}
				if err := walk(item, depth+1); err != nil {
					return err
				}
			}
		case []any:
			for _, item := range typed {
				if err := walk(item, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(value, 0)
}
