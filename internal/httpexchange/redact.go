package httpexchange

import (
	"net/url"
	"regexp"
	"strings"
)

// Redacted replaces every value an API-token reader must not see. The web
// UI masks sensitive headers until an administrator reveals them; a token
// (an AI agent, a script) gets no reveal, so the values are removed on the
// server: credential headers, credential-looking query parameters in the
// request target, and credential-looking fields of form and JSON bodies.
const Redacted = "[redacted]"

// credentialNames are parameter and field names whose values are secrets.
var credentialNames = map[string]bool{
	"password": true, "passwd": true, "pass": true, "pwd": true, "secret": true, "client_secret": true,
	"token": true, "access_token": true, "refresh_token": true, "id_token": true, "auth": true, "authorization": true,
	"api_key": true, "apikey": true, "key": true, "session": true, "sessionid": true, "session_id": true,
	"sig": true, "signature": true, "code": true, "otp": true, "pin": true,
}

const credentialPattern = `password|passwd|pass|pwd|secret|client_secret|token|access_token|refresh_token|id_token|auth|authorization|api_key|apikey|session|sessionid|session_id|signature|otp|pin`

// jsonCredential matches a credential field's string, number or boolean
// value; multipartCredential a form-data part named like one; and
// xmlCredential an element named like one.
var (
	jsonCredential      = regexp.MustCompile(`(?i)("(?:` + credentialPattern + `)"\s*:\s*)(?:"(?:[^"\\]|\\.)*"|-?[0-9][0-9.eE+-]*|true|false)`)
	multipartCredential = regexp.MustCompile(`(?is)(content-disposition:[^\r\n]*\bname="(?:` + credentialPattern + `)"[^\r\n]*\r?\n(?:[^\r\n]+\r?\n)*\r?\n)([^\r\n]*)`)
	xmlCredential       = regexp.MustCompile(`(?i)(<(` + credentialPattern + `)\b[^>]*>)[^<]*(</)`)
)

// IsSensitiveHeader reports whether a header carries credentials.
func IsSensitiveHeader(name string) bool {
	return sensitiveHeaders[strings.ToLower(strings.TrimSpace(name))]
}

// RedactExchanges returns a copy of exchanges with credentials removed.
func RedactExchanges(exchanges []Exchange) []Exchange {
	redacted := make([]Exchange, 0, len(exchanges))
	for _, exchange := range exchanges {
		var copied Exchange
		if exchange.Request != nil {
			request := *exchange.Request
			request.Target = redactTarget(request.Target)
			request.Headers = redactHeaders(request.Headers)
			request.Body = redactBody(request.Body)
			copied.Request = &request
		}
		if exchange.Response != nil {
			response := *exchange.Response
			response.Headers = redactHeaders(response.Headers)
			response.Body = redactBody(response.Body)
			copied.Response = &response
		}
		redacted = append(redacted, copied)
	}
	return redacted
}

func redactHeaders(headers Headers) Headers {
	items := make([]Header, 0, len(headers.Items))
	for _, header := range headers.Items {
		if header.Sensitive || IsSensitiveHeader(header.Name) {
			header.Value, header.Sensitive, header.Truncated = Redacted, true, false
		}
		items = append(items, header)
	}
	headers.Items = items
	return headers
}

// redactTarget removes credential values from the query string, keeping the
// parameter names so the request stays recognizable.
func redactTarget(target string) string {
	path, query, found := strings.Cut(target, "?")
	if !found || query == "" {
		return target
	}
	return path + "?" + redactPairs(query)
}

func redactPairs(encoded string) string {
	parts := strings.Split(encoded, "&")
	for index, part := range parts {
		name, _, hasValue := strings.Cut(part, "=")
		decoded, err := url.QueryUnescape(name)
		if err != nil {
			decoded = name
		}
		if hasValue && credentialNames[strings.ToLower(decoded)] {
			parts[index] = name + "=" + url.QueryEscape(Redacted)
		}
	}
	return strings.Join(parts, "&")
}

// redactBody removes credentials from a text preview. A token reader gets
// no binary (hex or base64) preview at all: it could hold anything, and its
// fields cannot be found reliably. Text previews get every heuristic,
// whatever the declared content type, since servers mislabel bodies.
func redactBody(body Body) Body {
	if body.Preview == "" {
		return body
	}
	if body.PreviewEncoding != "" && body.PreviewEncoding != "text" && body.PreviewEncoding != "utf-8" {
		body.Preview, body.PreviewBytes, body.PreviewEncoding = "", 0, ""
		body.Note = "The body is binary; its preview is not shown to API tokens."
		return body
	}
	contentType := strings.ToLower(body.ContentType)
	preview := body.Preview
	if strings.Contains(contentType, "x-www-form-urlencoded") || looksLikeForm(preview) {
		preview = redactPairs(preview)
	}
	preview = jsonCredential.ReplaceAllString(preview, `${1}"`+Redacted+`"`)
	preview = multipartCredential.ReplaceAllString(preview, `${1}`+Redacted)
	preview = xmlCredential.ReplaceAllString(preview, `${1}`+Redacted+`${3}`)
	body.Preview = preview
	return body
}

// looksLikeForm reports whether a preview is a single line of
// name=value pairs, as a form body sent with a wrong content type is.
func looksLikeForm(preview string) bool {
	return strings.Contains(preview, "=") && !strings.ContainsAny(preview, " \t\r\n{<")
}
