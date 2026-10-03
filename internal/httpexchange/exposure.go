package httpexchange

import (
	"net/url"
	"sort"
	"strings"
)

// An Exposure records that a request or response carried a secret in the
// clear, and WHERE it was, never the secret value. It is safe to store,
// serve to an API token, and show in the UI: Where is a location name (a
// header, a form field, a query parameter), not a credential.
type Exposure struct {
	Kind  ExposureKind `json:"kind"`
	Where string       `json:"where"`
}

// ExposureKind is the shape of a cleartext secret exposure.
type ExposureKind string

const (
	// ExposureBasicAuth is an HTTP Basic or Digest Authorization header.
	ExposureBasicAuth ExposureKind = "basic-auth"
	// ExposureFormPassword is a credential field in a form or multipart body.
	ExposureFormPassword ExposureKind = "form-password"
	// ExposureTokenInURL is a credential in the request target's query string.
	ExposureTokenInURL ExposureKind = "token-in-url"
	// ExposureCleartextCookie is a session cookie carried over cleartext.
	ExposureCleartextCookie ExposureKind = "cleartext-cookie"
)

// Exposures reports the secrets an HTTP exchange sent in the clear. It
// returns nothing when the flow was not cleartext on the wire: a
// ShakerProxy-decrypted HTTPS exchange was encrypted when it crossed the
// network, so its credentials were not exposed. The result never contains a
// secret value, only its kind and location.
func Exposures(exchanges []Exchange, cleartext bool) []Exposure {
	if !cleartext {
		return nil
	}
	seen := map[Exposure]bool{}
	var out []Exposure
	add := func(kind ExposureKind, where string) {
		exposure := Exposure{Kind: kind, Where: where}
		if !seen[exposure] {
			seen[exposure] = true
			out = append(out, exposure)
		}
	}
	for _, exchange := range exchanges {
		if request := exchange.Request; request != nil {
			for _, name := range URLCredentialParams(request.Target) {
				add(ExposureTokenInURL, name+" query parameter")
			}
			scanRequestHeaders(request.Headers, add)
			if bodyHasCredential(request.Body) {
				add(ExposureFormPassword, "request body")
			}
		}
		if response := exchange.Response; response != nil {
			for _, header := range response.Headers.Items {
				if strings.EqualFold(strings.TrimSpace(header.Name), "set-cookie") {
					add(ExposureCleartextCookie, "Set-Cookie header")
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Where < out[j].Where
	})
	return out
}

func scanRequestHeaders(headers Headers, add func(ExposureKind, string)) {
	for _, header := range headers.Items {
		name := strings.ToLower(strings.TrimSpace(header.Name))
		switch name {
		case "authorization", "proxy-authorization":
			// A bearer token is also a secret, but "Authorization" already
			// names the exposure; Basic/Digest carry the password itself.
			add(ExposureBasicAuth, "Authorization header")
		case "cookie":
			add(ExposureCleartextCookie, "Cookie header")
		}
	}
}

func bodyHasCredential(body Body) bool {
	if body.Preview == "" || body.PreviewEncoding != "" && body.PreviewEncoding != "text" && body.PreviewEncoding != "utf-8" {
		// A binary body cannot be scanned reliably; do not guess.
		return false
	}
	// Servers mislabel bodies, so every text preview gets every heuristic,
	// the same way redactBody does when removing the values.
	contentType := strings.ToLower(body.ContentType)
	preview := body.Preview
	if strings.Contains(contentType, "x-www-form-urlencoded") || looksLikeForm(preview) {
		if len(URLCredentialParams("?"+preview)) > 0 {
			return true
		}
	}
	return jsonCredential.MatchString(preview) || multipartCredential.MatchString(preview) || xmlCredential.MatchString(preview)
}

// URLCredentialParams returns the names of credential-looking query
// parameters in a request target. The names are not secret; the values are,
// and are never returned.
func URLCredentialParams(target string) []string {
	_, query, found := strings.Cut(target, "?")
	if !found || query == "" {
		return nil
	}
	seen := map[string]bool{}
	var names []string
	for _, part := range strings.Split(query, "&") {
		name, _, hasValue := strings.Cut(part, "=")
		if !hasValue {
			continue
		}
		decoded, err := url.QueryUnescape(name)
		if err != nil {
			decoded = name
		}
		lower := strings.ToLower(decoded)
		if credentialNames[lower] && !seen[lower] {
			seen[lower] = true
			names = append(names, lower)
		}
	}
	return names
}
