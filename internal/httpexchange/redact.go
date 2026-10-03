package httpexchange

import (
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// Redacted replaces every value an API-token reader must not see. The web
// UI masks sensitive headers until an administrator reveals them; a token
// (an AI agent, a script) gets no reveal, so the values are removed on the
// server: credential headers, credential-looking query parameters in the
// request target, and credential-looking fields of form and JSON bodies.
const Redacted = "[redacted]"

// credentialFields are parameter and field names whose values are secrets,
// in snake_case. Every matcher (query and form pairs, JSON, XML, multipart)
// and the exposure detector are built from this one list, so redaction and
// detection cannot drift apart. A name matches with or without its
// separators and in any case: access_token, access-token and accessToken.
var credentialFields = []string{
	"password", "passwd", "pass", "pwd", "passcode", "secret", "client_secret", "private_key",
	"token", "access_token", "refresh_token", "id_token", "auth_token", "jwt", "auth", "authorization",
	"api_key", "key", "session", "session_id", "sig", "signature", "code", "otp", "pin",
}

// markupNames are credential names that are also everyday element names
// (<code> in HTML, <key> in Apple property lists) whose text is not a
// secret; the XML matcher skips them. plistCredential covers a property
// list's <key>password</key><string>…</string> pair instead.
var markupNames = map[string]bool{"code": true, "key": true}

// credentialNames holds each credential field in canonical form (see
// canonicalName).
var credentialNames = func() map[string]bool {
	names := make(map[string]bool, len(credentialFields))
	for _, field := range credentialFields {
		names[canonicalName(field)] = true
	}
	return names
}()

// credentialAlternation returns a regular-expression alternation of the
// credential fields, longest first, each separator optional.
func credentialAlternation(skip map[string]bool) string {
	fields := make([]string, 0, len(credentialFields))
	for _, field := range credentialFields {
		if !skip[field] {
			fields = append(fields, field)
		}
	}
	sort.Slice(fields, func(i, j int) bool {
		if len(fields[i]) != len(fields[j]) {
			return len(fields[i]) > len(fields[j])
		}
		return fields[i] < fields[j]
	})
	for index, field := range fields {
		fields[index] = strings.ReplaceAll(regexp.QuoteMeta(field), "_", "[_-]?")
	}
	return strings.Join(fields, "|")
}

// jsonCredential matches a credential field's string, number or boolean
// value, and jsonCredentialContainer the start of one whose value is an
// object or array; multipartCredential a form-data part named like one;
// xmlCredential an element named like one; and plistCredential a property
// list value under a key named like one.
var (
	credentialPattern       = credentialAlternation(nil)
	markupPattern           = credentialAlternation(markupNames)
	jsonCredential          = regexp.MustCompile(`(?i)("(?:` + credentialPattern + `)"\s*:\s*)(?:"(?:[^"\\]|\\.)*"|-?[0-9][0-9.eE+-]*|true|false)`)
	jsonCredentialContainer = regexp.MustCompile(`(?i)"(?:` + credentialPattern + `)"\s*:\s*[\[{]`)
	multipartCredential     = regexp.MustCompile(`(?is)(content-disposition:[^\r\n]*\bname="(?:` + credentialPattern + `)"[^\r\n]*\r?\n(?:[^\r\n]+\r?\n)*\r?\n)([^\r\n]*)`)
	xmlCredential           = regexp.MustCompile(`(?i)(<(` + markupPattern + `)\b[^>]*>)[^<]*(</)`)
	plistCredential         = regexp.MustCompile(`(?i)(<key>\s*(?:` + credentialPattern + `)\s*</key>\s*<(?:string|data|integer|real)>)[^<]*(</)`)
)

// strictPair is a name=value pair of a query string or a form body, which
// separate pairs with & or ;. loosePair is one anywhere in a text preview,
// such as a form sent with the wrong content type, a form spread over
// lines, or a URL inside another body.
var (
	strictPair = regexp.MustCompile(`(^|[&;])([^&;=]*)=([^&;]*)`)
	loosePair  = regexp.MustCompile(`(^|[?&;\s"'(,])([A-Za-z0-9_.%\[\]-]+)=([^&;\s"'<>]*)`)
	pairEnd    = regexp.MustCompile(`[&;\r\n"'<>]`)
)

// canonicalName lowercases a field name and drops its separators.
func canonicalName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	return strings.NewReplacer("_", "", "-", "").Replace(name)
}

// isCredentialName reports whether a (possibly percent-encoded) parameter
// name names a secret. A nested form name counts when any part of it does:
// user[password], password[] and user.password all do.
func isCredentialName(name string) bool {
	if decoded, err := url.QueryUnescape(name); err == nil {
		name = decoded
	}
	for _, part := range strings.FieldsFunc(name, func(r rune) bool { return r == '[' || r == ']' || r == '.' }) {
		if credentialNames[canonicalName(part)] {
			return true
		}
	}
	return false
}

// credentialPairs returns the [nameStart, nameEnd, valueStart, valueEnd]
// offsets of each credential pair with a non-empty value. With loose
// matching a credential value runs past spaces to the next pair separator,
// quote or line end, so a mislabeled form's "password=hunter 2" is covered
// whole.
func credentialPairs(text string, pattern *regexp.Regexp, loose bool) [][4]int {
	var pairs [][4]int
	covered := 0
	for _, match := range pattern.FindAllStringSubmatchIndex(text, -1) {
		nameStart, nameEnd, valueStart, valueEnd := match[4], match[5], match[6], match[7]
		if nameStart < covered || valueStart == valueEnd || !isCredentialName(text[nameStart:nameEnd]) {
			continue
		}
		if loose {
			if end := pairEnd.FindStringIndex(text[valueStart:]); end != nil {
				valueEnd = valueStart + end[0]
			} else {
				valueEnd = len(text)
			}
		}
		pairs = append(pairs, [4]int{nameStart, nameEnd, valueStart, valueEnd})
		covered = valueEnd
	}
	return pairs
}

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
	return path + "?" + redactPairs(query, strictPair, false)
}

// redactPairs replaces the value of each credential pair, keeping its name.
func redactPairs(text string, pattern *regexp.Regexp, loose bool) string {
	pairs := credentialPairs(text, pattern, loose)
	if len(pairs) == 0 {
		return text
	}
	var out strings.Builder
	last := 0
	for _, pair := range pairs {
		out.WriteString(text[last:pair[2]])
		out.WriteString(url.QueryEscape(Redacted))
		last = pair[3]
	}
	out.WriteString(text[last:])
	return out.String()
}

// redactJSONContainers replaces the whole object or array under a
// credential field, such as {"token":{"jwt":"…"}}, with the redaction
// marker. A container cut off by the preview's end is redacted to the end.
func redactJSONContainers(preview string) string {
	var out strings.Builder
	rest := preview
	for {
		match := jsonCredentialContainer.FindStringIndex(rest)
		if match == nil {
			if out.Len() == 0 {
				return preview
			}
			out.WriteString(rest)
			return out.String()
		}
		open := match[1] - 1
		out.WriteString(rest[:open])
		out.WriteString(`"` + Redacted + `"`)
		rest = rest[closingBracket(rest, open):]
	}
}

// closingBracket returns the index just past the bracket that closes the
// one at open, skipping brackets inside strings, or len(text) if none does.
func closingBracket(text string, open int) int {
	depth, inString, escaped := 0, false, false
	for index := open; index < len(text); index++ {
		switch char := text[index]; {
		case inString:
			if escaped {
				escaped = false
			} else if char == '\\' {
				escaped = true
			} else if char == '"' {
				inString = false
			}
		case char == '"':
			inString = true
		case char == '{' || char == '[':
			depth++
		case char == '}' || char == ']':
			if depth--; depth == 0 {
				return index + 1
			}
		}
	}
	return len(text)
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
		preview = redactPairs(preview, strictPair, false)
	}
	preview = redactPairs(preview, loosePair, true)
	preview = redactJSONContainers(preview)
	preview = jsonCredential.ReplaceAllString(preview, `${1}"`+Redacted+`"`)
	preview = multipartCredential.ReplaceAllString(preview, `${1}`+Redacted)
	preview = xmlCredential.ReplaceAllString(preview, `${1}`+Redacted+`${3}`)
	preview = plistCredential.ReplaceAllString(preview, `${1}`+Redacted+`${2}`)
	body.Preview = preview
	return body
}

// looksLikeForm reports whether a preview is a single line of
// name=value pairs, as a form body sent with a wrong content type is.
func looksLikeForm(preview string) bool {
	preview = strings.TrimSpace(preview)
	return strings.Contains(preview, "=") && !strings.ContainsAny(preview, " \t\r\n{<")
}
