// Package httpexchange turns the two byte streams of a cleartext HTTP/1.x
// connection into its request and response exchanges, the way Wireshark's
// "Follow HTTP stream" shows them. Everything is bounded: headers, bodies
// and decompression, so a hostile stream cannot make the control API spend
// unbounded memory.
package httpexchange

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	MaxExchanges          = 32
	MaxBodyPreviewBytes   = 64 << 10
	MaxHexPreviewBytes    = 256
	MaxHeaders            = 128
	MaxHeaderBytes        = 32 << 10
	MaxHeaderValueBytes   = 4096
	maxHeaderNameBytes    = 256
	maxStreamBytes        = 4 << 20
	maxRequestTargetBytes = 8192
)

var sensitiveHeaders = map[string]bool{
	"authorization": true, "proxy-authorization": true, "cookie": true, "set-cookie": true,
	"x-api-key": true, "x-auth-token": true, "x-access-token": true,
	"x-csrf-token": true, "x-xsrf-token": true, "x-amz-security-token": true, "x-goog-api-key": true,
	"x-session-token": true, "x-refresh-token": true, "x-id-token": true,
}

var textualMarkers = []string{"text/", "json", "xml", "javascript", "x-www-form-urlencoded", "graphql", "yaml", "csv"}

// A recording that starts mid-connection begins inside a message, and the
// next message follows the previous body directly, not at a line start.
var requestLine = regexp.MustCompile(`(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE) [^\s]+ HTTP/1\.[01]\r?\n`)
var statusLine = regexp.MustCompile(`HTTP/1\.[01] [1-5][0-9][0-9][ \r]`)

// Header is one header line, in the order it was sent. Sensitive values
// (credentials, cookies) are marked so the UI can mask them until revealed.
type Header struct {
	Name      string `json:"name"`
	Value     string `json:"value"`
	Sensitive bool   `json:"sensitive,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
}

type Headers struct {
	Items     []Header `json:"items"`
	Bytes     int      `json:"bytes"`
	Truncated bool     `json:"truncated,omitempty"`
}

// Body is a bounded preview of a message body after transfer decoding
// (chunked) and, for gzip and deflate, content decoding.
type Body struct {
	ContentType     string `json:"content_type"`
	ContentEncoding string `json:"content_encoding,omitempty"`
	// BodyBytes is the size after transfer decoding, before decompression.
	BodyBytes       int64  `json:"body_bytes"`
	DecodedPreview  bool   `json:"decoded_preview"`
	PreviewBytes    int    `json:"preview_bytes"`
	PreviewEncoding string `json:"preview_encoding"`
	Preview         string `json:"preview"`
	Truncated       bool   `json:"truncated"`
	// Complete is false when the recording ends before the body does.
	Complete bool   `json:"complete"`
	Note     string `json:"note,omitempty"`
}

type Request struct {
	Method  string  `json:"method"`
	Target  string  `json:"target"`
	Proto   string  `json:"proto"`
	Headers Headers `json:"headers"`
	Body    Body    `json:"body"`
}

type Response struct {
	Proto      string  `json:"proto"`
	StatusCode int     `json:"status_code"`
	Status     string  `json:"status"`
	Headers    Headers `json:"headers"`
	Body       Body    `json:"body"`
}

type Exchange struct {
	Request  *Request  `json:"request,omitempty"`
	Response *Response `json:"response,omitempty"`
}

type Result struct {
	Exchanges []Exchange `json:"exchanges"`
	// SkippedClientBytes and SkippedServerBytes count bytes before the first
	// message, from a connection whose start was not recorded.
	SkippedClientBytes int      `json:"skipped_client_bytes,omitempty"`
	SkippedServerBytes int      `json:"skipped_server_bytes,omitempty"`
	Notes              []string `json:"notes,omitempty"`
}

// Parse reads up to MaxExchanges request/response pairs. Requests and
// responses pair in order, as HTTP/1.x pipelining requires.
func Parse(client, server []byte) Result {
	result := Result{Exchanges: []Exchange{}}
	if len(client) > maxStreamBytes {
		client = client[:maxStreamBytes]
	}
	if len(server) > maxStreamBytes {
		server = server[:maxStreamBytes]
	}
	client, result.SkippedClientBytes = skipToMessage(client, requestLine)
	server, result.SkippedServerBytes = skipToMessage(server, statusLine)
	requests, methods, clientNote := parseRequests(client)
	responses, serverNote := parseResponses(server, methods)
	for _, note := range []string{clientNote, serverNote} {
		if note != "" {
			result.Notes = append(result.Notes, note)
		}
	}
	if result.SkippedClientBytes > 0 || result.SkippedServerBytes > 0 {
		result.Notes = append(result.Notes, "The recording starts in the middle of this connection; earlier exchanges are not shown.")
	}
	count := max(len(requests), len(responses))
	for index := 0; index < count && index < MaxExchanges; index++ {
		var exchange Exchange
		if index < len(requests) {
			exchange.Request = requests[index]
		}
		if index < len(responses) {
			exchange.Response = responses[index]
		}
		result.Exchanges = append(result.Exchanges, exchange)
	}
	return result
}

func skipToMessage(stream []byte, start *regexp.Regexp) ([]byte, int) {
	if len(stream) == 0 {
		return stream, 0
	}
	location := start.FindIndex(stream)
	if location == nil {
		return nil, len(stream)
	}
	return stream[location[0]:], location[0]
}

// countingReader tracks how much of the stream net/http consumed.
type countingReader struct {
	reader io.Reader
	read   int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.reader.Read(p)
	c.read += n
	return n, err
}

func parseRequests(stream []byte) ([]*Request, []string, string) {
	requests := []*Request{}
	methods := []string{}
	offset := 0
	for offset < len(stream) && len(requests) < MaxExchanges {
		remaining := stream[offset:]
		headEnd := headerEnd(remaining)
		if headEnd < 0 {
			// Show what was recorded: the request line and complete headers.
			if partial := partialRequest(remaining); partial != nil {
				requests = append(requests, partial)
				methods = append(methods, partial.Method)
			}
			return requests, methods, "The recording ends inside a request's headers."
		}
		counter := &countingReader{reader: bytes.NewReader(remaining)}
		reader := bufio.NewReader(counter)
		message, err := http.ReadRequest(reader)
		if err != nil {
			return requests, methods, fmt.Sprintf("A request could not be read as HTTP/1.x: %s.", plainError(err))
		}
		request := &Request{Method: message.Method, Target: bounded(message.RequestURI, maxRequestTargetBytes), Proto: message.Proto, Headers: orderedHeaders(remaining[:headEnd])}
		request.Body = readBody(message.Body, message.Header)
		_ = message.Body.Close()
		requests = append(requests, request)
		methods = append(methods, message.Method)
		consumed := counter.read - reader.Buffered()
		if consumed <= 0 || !request.Body.Complete {
			break
		}
		offset += consumed
	}
	return requests, methods, ""
}

func parseResponses(stream []byte, methods []string) ([]*Response, string) {
	responses := []*Response{}
	offset := 0
	for offset < len(stream) && len(responses) < MaxExchanges {
		remaining := stream[offset:]
		headEnd := headerEnd(remaining)
		if headEnd < 0 {
			if partial := partialResponse(remaining); partial != nil {
				responses = append(responses, partial)
			}
			return responses, "The recording ends inside a response's headers."
		}
		method := http.MethodGet
		if len(responses) < len(methods) {
			method = methods[len(responses)]
		}
		counter := &countingReader{reader: bytes.NewReader(remaining)}
		reader := bufio.NewReader(counter)
		message, err := http.ReadResponse(reader, &http.Request{Method: method})
		if err != nil {
			return responses, fmt.Sprintf("A response could not be read as HTTP/1.x: %s.", plainError(err))
		}
		response := &Response{Proto: message.Proto, StatusCode: message.StatusCode, Status: strings.TrimSpace(strings.TrimPrefix(message.Status, fmt.Sprint(message.StatusCode))), Headers: orderedHeaders(remaining[:headEnd])}
		response.Body = readBody(message.Body, message.Header)
		_ = message.Body.Close()
		consumed := counter.read - reader.Buffered()
		informational := message.StatusCode >= 100 && message.StatusCode < 200
		if informational && message.StatusCode != http.StatusSwitchingProtocols {
			// 100 Continue and friends precede the real response.
			offset += consumed
			if consumed <= 0 {
				break
			}
			continue
		}
		responses = append(responses, response)
		if message.StatusCode == http.StatusSwitchingProtocols {
			return responses, "The connection switched to another protocol (for example a WebSocket); later data is not HTTP."
		}
		if consumed <= 0 || !response.Body.Complete {
			break
		}
		offset += consumed
	}
	return responses, ""
}

var partialBody = Body{PreviewEncoding: "utf-8", Complete: false, Note: "The recording ends inside the headers; the rest of this message was not recorded."}

// completeHeadLines returns the start line and the header lines a cut-off
// message head contains in full (the last, unterminated line is dropped).
func completeHeadLines(head []byte) (string, []byte, bool) {
	if len(head) > MaxHeaderBytes+maxRequestTargetBytes {
		head = head[:MaxHeaderBytes+maxRequestTargetBytes]
	}
	end := bytes.LastIndexByte(head, '\n')
	if end < 0 {
		return "", nil, false
	}
	complete := head[:end+1]
	first := bytes.IndexByte(complete, '\n')
	return strings.TrimRight(string(complete[:first]), "\r"), complete, true
}

func partialRequest(head []byte) *Request {
	line, complete, ok := completeHeadLines(head)
	if !ok {
		return nil
	}
	parts := strings.SplitN(line, " ", 3)
	if len(parts) != 3 || !strings.HasPrefix(parts[2], "HTTP/1.") {
		return nil
	}
	return &Request{Method: bounded(parts[0], 16), Target: bounded(parts[1], maxRequestTargetBytes), Proto: bounded(parts[2], 16), Headers: orderedHeaders(complete), Body: partialBody}
}

func partialResponse(head []byte) *Response {
	line, complete, ok := completeHeadLines(head)
	if !ok {
		return nil
	}
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "HTTP/1.") {
		return nil
	}
	code := 0
	if _, err := fmt.Sscanf(parts[1], "%d", &code); err != nil || code < 100 || code > 599 {
		return nil
	}
	status := ""
	if len(parts) == 3 {
		status = bounded(parts[2], 128)
	}
	return &Response{Proto: bounded(parts[0], 16), StatusCode: code, Status: status, Headers: orderedHeaders(complete), Body: partialBody}
}

func plainError(err error) string {
	message := err.Error()
	if len(message) > 160 {
		message = message[:160]
	}
	return strings.TrimSuffix(message, ".")
}

func headerEnd(stream []byte) int {
	limit := min(len(stream), MaxHeaderBytes+maxRequestTargetBytes)
	if index := bytes.Index(stream[:limit], []byte("\r\n\r\n")); index >= 0 {
		return index + 4
	}
	if index := bytes.Index(stream[:limit], []byte("\n\n")); index >= 0 {
		return index + 2
	}
	return -1
}

// orderedHeaders keeps header lines as sent (net/http's map loses order
// and the original spelling).
func orderedHeaders(head []byte) Headers {
	result := Headers{Items: []Header{}}
	lines := strings.Split(strings.ReplaceAll(string(head), "\r\n", "\n"), "\n")
	for _, line := range lines[1:] {
		if line == "" {
			continue
		}
		name, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		if len(result.Items) >= MaxHeaders || result.Bytes+len(name)+len(value) > MaxHeaderBytes {
			result.Truncated = true
			break
		}
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)
		header := Header{Name: bounded(name, maxHeaderNameBytes), Value: bounded(value, MaxHeaderValueBytes), Sensitive: sensitiveHeaders[strings.ToLower(name)]}
		header.Truncated = header.Name != name || header.Value != value
		result.Bytes += len(header.Name) + len(header.Value)
		result.Items = append(result.Items, header)
	}
	return result
}

func bounded(value string, limit int) string {
	if len(value) <= limit {
		return toValidUTF8(value)
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(value[cut]) {
		cut--
	}
	return toValidUTF8(value[:cut])
}

func toValidUTF8(value string) string {
	if utf8.ValidString(value) {
		return value
	}
	return strings.ToValidUTF8(value, "�")
}

// readBody reads a transfer-decoded body (net/http undoes chunking) and
// builds a bounded preview, decompressing gzip and deflate up to the bound.
func readBody(body io.Reader, header http.Header) Body {
	result := Body{ContentType: bounded(header.Get("Content-Type"), 256), ContentEncoding: strings.ToLower(strings.TrimSpace(header.Get("Content-Encoding"))), Complete: true}
	var wire bytes.Buffer
	_, err := io.Copy(&wire, io.LimitReader(body, maxStreamBytes))
	if err != nil {
		// The recording ended before the body did.
		result.Complete = false
		result.Note = "The recording ends before this body does."
	}
	result.BodyBytes = int64(wire.Len())
	if wire.Len() == 0 {
		result.PreviewEncoding = "utf-8"
		return result
	}
	decoded, decodedPreview, decodeNote := decodeContent(wire.Bytes(), result.ContentEncoding)
	result.DecodedPreview = decodedPreview
	if decodeNote != "" && result.Note == "" {
		result.Note = decodeNote
	}
	encoded := result.ContentEncoding != "" && result.ContentEncoding != "identity"
	result.Truncated = len(decoded) > MaxBodyPreviewBytes || (encoded && !decodedPreview && wire.Len() > MaxBodyPreviewBytes)
	preview := decoded
	if len(preview) > MaxBodyPreviewBytes {
		preview = preview[:MaxBodyPreviewBytes]
	}
	if (!encoded || decodedPreview) && textual(result.ContentType, preview) {
		result.PreviewEncoding = "utf-8"
		result.Preview = toValidUTF8(string(preview))
		result.PreviewBytes = len(preview)
		return result
	}
	return HexPreview(result, preview)
}

// HexPreview shows a binary body as a hex dump of its first bytes.
func HexPreview(body Body, data []byte) Body {
	if len(data) > MaxHexPreviewBytes {
		data = data[:MaxHexPreviewBytes]
		body.Truncated = true
	}
	body.PreviewEncoding = "hex"
	body.Preview = hexDump(data)
	body.PreviewBytes = len(data)
	return body
}

// decodeContent undoes gzip or deflate content encoding, producing at most
// one byte more than the preview bound so truncation is detectable without
// inflating a whole (possibly hostile) body.
func decodeContent(wire []byte, encoding string) ([]byte, bool, string) {
	limit := int64(MaxBodyPreviewBytes + 1)
	readLimited := func(reader io.Reader) ([]byte, error) {
		decoded, err := io.ReadAll(io.LimitReader(reader, limit))
		if errors.Is(err, io.ErrUnexpectedEOF) && len(decoded) > 0 {
			// A body the recording cut short still previews what it has.
			return decoded, nil
		}
		return decoded, err
	}
	switch encoding {
	case "", "identity":
		return wire, false, ""
	case "gzip", "x-gzip":
		reader, err := gzip.NewReader(bytes.NewReader(wire))
		if err != nil {
			return wire, false, "The gzip body could not be decoded; showing the bytes as sent."
		}
		decoded, err := readLimited(reader)
		if err != nil {
			return wire, false, "The gzip body could not be decoded; showing the bytes as sent."
		}
		return decoded, true, ""
	case "deflate":
		// "deflate" is zlib-wrapped by the standard but raw in practice too.
		if reader, err := zlib.NewReader(bytes.NewReader(wire)); err == nil {
			if decoded, err := readLimited(reader); err == nil {
				return decoded, true, ""
			}
		}
		if decoded, err := readLimited(flate.NewReader(bytes.NewReader(wire))); err == nil {
			return decoded, true, ""
		}
		return wire, false, "The deflate body could not be decoded; showing the bytes as sent."
	default:
		return wire, false, fmt.Sprintf("The body is %s-encoded, which ShakerProxy does not decode; showing the bytes as sent.", bounded(encoding, 32))
	}
}

func textual(contentType string, preview []byte) bool {
	lower := strings.ToLower(contentType)
	for _, marker := range textualMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	if lower != "" || !utf8.Valid(preview) {
		return false
	}
	// No Content-Type: treat mostly printable UTF-8 as text.
	printable, total := 0, 0
	for _, r := range string(preview) {
		total++
		if r == '\n' || r == '\r' || r == '\t' || (r >= 0x20 && r != 0x7f) {
			printable++
		}
	}
	return total > 0 && printable*10 >= total*9
}

// hexDump formats bytes like `hexdump -C`: offset, hex and printable ASCII.
func hexDump(data []byte) string {
	var builder strings.Builder
	for offset := 0; offset < len(data); offset += 16 {
		line := data[offset:min(offset+16, len(data))]
		fmt.Fprintf(&builder, "%08x  ", offset)
		for index := 0; index < 16; index++ {
			if index < len(line) {
				fmt.Fprintf(&builder, "%02x ", line[index])
			} else {
				builder.WriteString("   ")
			}
			if index == 7 {
				builder.WriteByte(' ')
			}
		}
		builder.WriteString(" |")
		for _, value := range line {
			if value >= 0x20 && value < 0x7f {
				builder.WriteByte(value)
			} else {
				builder.WriteByte('.')
			}
		}
		builder.WriteString("|\n")
	}
	return builder.String()
}
