package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"reflect"
	"strings"
	"time"
)

const maxOpenAPIBytes = 4 << 20

var (
	errEmptyRequestBody     = errors.New("the request body is empty; send a JSON object")
	errMultipleJSONValues   = errors.New("the request body must contain exactly one JSON value")
	errUnsupportedMediaType = errors.New("set Content-Type: application/json")
)

type requestTooLargeError struct{ limit int64 }

func (e requestTooLargeError) Error() string {
	return fmt.Sprintf("the request body exceeds %d bytes", e.limit)
}

// checkJSONContentType accepts application/json with an optional UTF-8
// charset parameter (for example "application/json; charset=utf-8").
func checkJSONContentType(r *http.Request) error {
	mediaType, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return errUnsupportedMediaType
	}
	for name, value := range params {
		if name != "charset" || !strings.EqualFold(value, "utf-8") {
			return errUnsupportedMediaType
		}
	}
	return nil
}

func readBoundedBody(r *http.Request, maxBytes int64) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxBytes {
		return nil, requestTooLargeError{limit: maxBytes}
	}
	return body, nil
}

func decodeStrictJSONBytes(body []byte, dst any) error {
	if len(bytes.TrimSpace(body)) == 0 {
		return errEmptyRequestBody
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	if !errors.Is(decoder.Decode(&struct{}{}), io.EOF) {
		return errMultipleJSONValues
	}
	return nil
}

// decodeOptionalJSON decodes a JSON object when one is present and treats an
// empty body (no bytes or only whitespace) as "{}". Action endpoints whose
// fields are all optional use it so clients may POST without a body.
func decodeOptionalJSON(r *http.Request, dst any, maxBytes int64) error {
	body, err := readBoundedBody(r, maxBytes)
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	if err := checkJSONContentType(r); err != nil {
		return err
	}
	return decodeStrictJSONBytes(body, dst)
}

// describeDecodeError turns a request decoding failure into plain language that
// names the offending field without leaking Go type names.
func describeDecodeError(err error) string {
	var syntaxError *json.SyntaxError
	var typeError *json.UnmarshalTypeError
	var tooLarge requestTooLargeError
	var timeError *time.ParseError
	switch {
	case err == nil:
		return ""
	case errors.Is(err, errEmptyRequestBody), errors.Is(err, errMultipleJSONValues), errors.Is(err, errUnsupportedMediaType):
		return err.Error()
	case errors.As(err, &tooLarge):
		return tooLarge.Error()
	case errors.As(err, &syntaxError):
		return fmt.Sprintf("the request body is not valid JSON (problem near byte %d)", syntaxError.Offset)
	case errors.Is(err, io.ErrUnexpectedEOF):
		return "the JSON request body is incomplete"
	case errors.As(err, &typeError):
		if typeError.Field == "" {
			return "the request body must be " + jsonKind(typeError.Type)
		}
		return fmt.Sprintf("field %q must be %s", typeError.Field, jsonKind(typeError.Type))
	case errors.As(err, &timeError):
		return "timestamps must use RFC 3339, for example 2026-09-29T10:00:00Z"
	case strings.HasPrefix(err.Error(), "json: unknown field "):
		return "field " + strings.TrimPrefix(err.Error(), "json: unknown field ") + " is not supported"
	default:
		return strings.TrimPrefix(err.Error(), "json: ")
	}
}

func jsonKind(kind reflect.Type) string {
	if kind == nil {
		return "a different JSON type"
	}
	for kind.Kind() == reflect.Pointer {
		kind = kind.Elem()
	}
	if kind == reflect.TypeOf(time.Time{}) {
		return "an RFC 3339 timestamp string"
	}
	switch kind.Kind() {
	case reflect.String:
		return "a string"
	case reflect.Bool:
		return "true or false"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return "an integer"
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return "a non-negative integer"
	case reflect.Float32, reflect.Float64:
		return "a number"
	case reflect.Slice, reflect.Array:
		return "an array"
	case reflect.Map, reflect.Struct:
		return "an object"
	default:
		return "a different JSON type"
	}
}

// writeDecodeError reports a request body that could not be decoded. The
// message names the schema and the concrete problem so integrators can fix the
// request without reading server logs.
func writeDecodeError(w http.ResponseWriter, err error, schema string) {
	status, code := http.StatusBadRequest, "invalid_request"
	var tooLarge requestTooLargeError
	switch {
	case errors.Is(err, errUnsupportedMediaType):
		status, code = http.StatusUnsupportedMediaType, "unsupported_media_type"
	case errors.As(err, &tooLarge):
		status, code = http.StatusRequestEntityTooLarge, "request_too_large"
	}
	writeError(w, status, code, fmt.Sprintf("Request does not match the %s schema: %s.", schema, describeDecodeError(err)))
}

// requestOperationID returns the client's Idempotency-Key or, when the header
// is absent, a fresh server-generated key. A present but malformed header is
// rejected so clients learn about the typo instead of losing replay safety.
func requestOperationID(r *http.Request, valid func(string) bool) (string, bool) {
	if values, present := r.Header["Idempotency-Key"]; present {
		if len(values) != 1 || !valid(strings.TrimSpace(values[0])) {
			return "", false
		}
		return strings.TrimSpace(values[0]), true
	}
	return newOperationID()
}

// newOperationID returns a random operation ID for a mutation the server
// makes on its own behalf.
func newOperationID() (string, bool) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", false
	}
	return "op-" + hex.EncodeToString(random), true
}

func writeInvalidIdempotencyKey(w http.ResponseWriter) {
	writeError(w, http.StatusBadRequest, "invalid_idempotency_key", "Idempotency-Key must be 16-128 characters of letters, digits, '-' or '_'; omit the header to let the server generate one.")
}

func writeInvalidDeviceID(w http.ResponseWriter) {
	writeError(w, http.StatusBadRequest, "invalid_device_id", "The device ID is invalid; device IDs look like device-<32 hex characters>. List devices with GET /api/v1/devices.")
}

// durableOperationTimeout bounds work that must reach a persisted state once
// it started, even if the client disconnects (deletions, retention runs).
const durableOperationTimeout = 10 * time.Minute

// durableOperationContext keeps the request's values but not its
// cancellation. A job interrupted by the timeout stays RUNNING in its ledger
// and the recovery loops resume it.
func durableOperationContext(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(r.Context()), durableOperationTimeout)
}

// wrapMux applies the shared API boundary: security headers, Host/Origin
// validation, and JSON errors for unknown routes and methods.
func (s *Server) wrapMux(mux *http.ServeMux) http.Handler {
	return s.securityHeaders(s.validateHost(jsonFallback(mux)))
}

var fallbackProbeMethods = []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}

// jsonFallback serves registered routes unchanged and replaces the mux's
// text/plain 404 and 405 responses with the API's JSON error shape.
func jsonFallback(mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, pattern := mux.Handler(r); pattern != "" {
			mux.ServeHTTP(w, r)
			return
		}
		allowed := make([]string, 0, len(fallbackProbeMethods))
		for _, method := range fallbackProbeMethods {
			if method == r.Method {
				continue
			}
			probe := r.Clone(r.Context())
			probe.Method = method
			if _, pattern := mux.Handler(probe); pattern != "" {
				allowed = append(allowed, method)
			}
		}
		if len(allowed) > 0 {
			if containsString(allowed, http.MethodGet) {
				allowed = append(allowed, http.MethodHead)
			}
			w.Header().Set("Allow", strings.Join(allowed, ", "))
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", fmt.Sprintf("%s is not supported for %s. Use %s.", r.Method, r.URL.Path, strings.Join(allowed, " or ")))
			return
		}
		writeError(w, http.StatusNotFound, "not_found", fmt.Sprintf("No API endpoint matches %s %s. See GET /api/v1 for the list of resources.", r.Method, r.URL.Path))
	})
}

type apiIndexResource struct {
	Path        string   `json:"path"`
	Methods     []string `json:"methods"`
	Description string   `json:"description"`
}

type apiIndex struct {
	Schema         int                `json:"schema"`
	Name           string             `json:"name"`
	Version        string             `json:"version"`
	OpenAPI        string             `json:"openapi"`
	Authentication map[string]string  `json:"authentication"`
	Resources      []apiIndexResource `json:"resources"`
}

var apiIndexResources = []apiIndexResource{
	{"/api/v1/setup/status", []string{"GET"}, "Whether the appliance administrator has been created."},
	{"/api/v1/auth/login", []string{"POST"}, "Sign in with the administrator password; returns a bearer session token and its expiry."},
	{"/api/v1/auth/logout", []string{"POST"}, "End the current session."},
	{"/api/v1/auth/recover", []string{"POST"}, "Set a new administrator password with a one-time recovery code."},
	{"/api/v1/auth/tokens", []string{"GET", "POST"}, "Scoped API tokens for scripts, CI and integrations."},
	{"/api/v1/system/status", []string{"GET"}, "Appliance, network and service health."},
	{"/api/v1/capabilities", []string{"GET"}, "Which features this appliance build and profile support."},
	{"/api/v1/devices", []string{"GET"}, "Devices seen on the lab network with vendor, name, addresses and tags."},
	{"/api/v1/devices/resolve", []string{"GET"}, "Find a device by friendly name, IP, MAC or ID."},
	{"/api/v1/devices/{device}", []string{"GET"}, "One device with identities, addresses and alias history."},
	{"/api/v1/devices/{device}/report", []string{"GET"}, "Plain-language security report and findings for one device."},
	{"/api/v1/devices/{device}/compare", []string{"GET"}, "Compare two test runs of one device."},
	{"/api/v1/devices/{device}/controls", []string{"GET", "PUT"}, "Decrypt HTTPS, block internet or block domains for one device."},
	{"/api/v1/test-sessions", []string{"GET", "POST"}, "Named, time-bounded test runs against one device."},
	{"/api/v1/events", []string{"GET"}, "Recent traffic events with plain-language summaries; supports the query language."},
	{"/api/v1/events/live", []string{"GET"}, "Live traffic after a cursor, for streaming views."},
	{"/api/v1/events/summary", []string{"GET"}, "Traffic over time by type, top devices and destinations, and byte totals for a query."},
	{"/api/v1/protocols", []string{"GET"}, "Application protocols observed in a time window, including unusual ones."},
	{"/api/v1/captures", []string{"GET", "POST"}, "Packet captures: start, stop, list and export."},
	{"/api/v1/cases", []string{"GET", "POST"}, "Cases that group evidence (captures, exports, query snapshots) with an audit timeline."},
	{"/api/v1/saved-views", []string{"GET", "POST"}, "Saved traffic queries."},
	{"/api/v1/traffic-policy", []string{"GET", "PUT"}, "DNS enforcement and HTTPS decryption policy."},
	{"/api/v1/interception-ca/onboarding", []string{"GET"}, "How to install the ShakerProxy certificate on test devices."},
	{"/api/v1/preflight", []string{"GET"}, "Network interfaces available for the lab network plan."},
	{"/api/v1/integrations/forwarders", []string{"GET", "POST"}, "Forward alerts and events to SIEM, webhook or syslog."},
	{"/api/v1/address-aliases", []string{"GET", "POST"}, "Names for addresses and subnets that are not DHCP devices."},
	{"/api/v1/device-audit", []string{"GET"}, "Audit log of device renames, tags, merges and splits."},
	{"/api/v1/metrics", []string{"GET"}, "OpenMetrics counters (requires a metrics:read API token)."},
	{"/api/v1/openapi.yaml", []string{"GET"}, "The full OpenAPI description of this API."},
}

func (s *Server) apiIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, apiIndex{
		Schema: 1, Name: "ShakerProxy Control API", Version: "v1", OpenAPI: "/api/v1/openapi.yaml",
		Authentication: map[string]string{
			"session":   "POST /api/v1/auth/login, then send Authorization: Bearer <session_token>. Sessions stay valid while used (1 hour idle, 12 hours maximum).",
			"api_token": "Create a scoped token with POST /api/v1/auth/tokens and send Authorization: Bearer <secret>.",
		},
		Resources: apiIndexResources,
	})
}

func (s *Server) serveOpenAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-cache")
	path := s.openAPIPath
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxOpenAPIBytes {
		writeError(w, http.StatusServiceUnavailable, "openapi_unavailable", "The OpenAPI document is not installed on this appliance; see schemas/api/openapi.yaml in the ShakerProxy source.")
		return
	}
	document, err := os.ReadFile(path)
	if err != nil || len(document) > maxOpenAPIBytes {
		writeError(w, http.StatusServiceUnavailable, "openapi_unavailable", "The OpenAPI document could not be read; check the appliance installation.")
		return
	}
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Content-Disposition", `inline; filename="shakerproxy-openapi.yaml"`)
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(document)
	}
}
