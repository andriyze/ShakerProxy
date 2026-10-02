package server

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/capture"
	"shakerproxy.dev/shakerproxy/internal/gatewayclient"
	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
)

func decodeErrorBody(t *testing.T, recorder *httptest.ResponseRecorder) (string, string) {
	t.Helper()
	if !strings.HasPrefix(recorder.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("error response is not JSON: %q %s", recorder.Header().Get("Content-Type"), recorder.Body.String())
	}
	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("error response is not the JSON error shape: %v %s", err, recorder.Body.String())
	}
	return body.Error.Code, body.Error.Message
}

func TestUnknownRoutesAndMethodsReturnJSONErrors(t *testing.T) {
	server, session := configuredAPIServer(t, filepath.Join(t.TempDir(), "absent.sock"))
	handlers := map[string]http.Handler{
		"core":     server.Handler(),
		"testlab":  server.TestLabHandler(),
		"agent":    server.AgentConnectionHandler(),
		"devices":  server.AgentDeviceHandler(),
		"overview": server.AgentSystemOverviewHandler(),
	}
	for name, handler := range handlers {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, authenticatedJSONRequest(http.MethodGet, "/api/v1/does-not-exist", "", session, ""))
		if code, message := decodeErrorBody(t, recorder); recorder.Code != http.StatusNotFound || code != "not_found" || !strings.Contains(message, "GET /api/v1") {
			t.Fatalf("%s unknown route returned %d %s %q", name, recorder.Code, code, message)
		}
	}
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, authenticatedJSONRequest(http.MethodDelete, "/api/v1/devices", "", session, ""))
	code, message := decodeErrorBody(t, recorder)
	if recorder.Code != http.StatusMethodNotAllowed || code != "method_not_allowed" || !strings.Contains(recorder.Header().Get("Allow"), "GET") || !strings.Contains(message, "GET") {
		t.Fatalf("wrong method returned %d %s %q allow=%q", recorder.Code, code, message, recorder.Header().Get("Allow"))
	}
	testlab := httptest.NewRecorder()
	server.TestLabHandler().ServeHTTP(testlab, authenticatedJSONRequest(http.MethodGet, "/api/v1/self-test/run", "", session, ""))
	if code, _ := decodeErrorBody(t, testlab); testlab.Code != http.StatusMethodNotAllowed || code != "method_not_allowed" || testlab.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("self-test wrong method returned %d %s headers=%v", testlab.Code, code, testlab.Header())
	}
	badHost := authenticatedJSONRequest(http.MethodPost, "/api/v1/self-test/cleanup", `{}`, session, "")
	badHost.Host = "evil.example"
	hostRecorder := httptest.NewRecorder()
	server.TestLabHandler().ServeHTTP(hostRecorder, badHost)
	if hostRecorder.Code != http.StatusBadRequest {
		t.Fatalf("self-test handler skipped host validation: %d", hostRecorder.Code)
	}
}

func TestAPIIndexAndOpenAPIAreServed(t *testing.T) {
	openAPIPath, err := filepath.Abs(filepath.Join("..", "..", "..", "..", "schemas", "api", "openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	server, _ := configuredAPIServerWithConfig(t, filepath.Join(t.TempDir(), "absent.sock"), func(config *Config) { config.OpenAPIPath = openAPIPath })
	for _, target := range []string{"/api/v1", "/api/v1/"} {
		request := httptest.NewRequest(http.MethodGet, target, nil)
		request.Host = "shakerproxy.test"
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, request)
		var index apiIndex
		if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &index) != nil || index.Schema != 1 || index.OpenAPI != "/api/v1/openapi.yaml" || len(index.Resources) < 10 {
			t.Fatalf("index %s returned %d: %s", target, recorder.Code, recorder.Body.String())
		}
		for _, resource := range index.Resources {
			if resource.Path == "" || len(resource.Methods) == 0 || resource.Description == "" {
				t.Fatalf("index resource is incomplete: %#v", resource)
			}
		}
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/openapi.yaml", nil)
	request.Host = "shakerproxy.test"
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.HasPrefix(recorder.Header().Get("Content-Type"), "application/yaml") || !strings.HasPrefix(recorder.Body.String(), "openapi: 3.1.0") {
		t.Fatalf("openapi returned %d %q", recorder.Code, recorder.Header().Get("Content-Type"))
	}
	missing, _ := configuredAPIServerWithConfig(t, filepath.Join(t.TempDir(), "absent.sock"), func(config *Config) { config.OpenAPIPath = filepath.Join(t.TempDir(), "missing.yaml") })
	recorder = httptest.NewRecorder()
	missing.Handler().ServeHTTP(recorder, request)
	if code, _ := decodeErrorBody(t, recorder); recorder.Code != http.StatusServiceUnavailable || code != "openapi_unavailable" {
		t.Fatalf("missing openapi returned %d %s", recorder.Code, code)
	}
}

// openAPIPendingRoutes lists core routes that are intentionally not yet in
// schemas/api/openapi.yaml. Keep it empty; add an entry only with a follow-up.
var openAPIPendingRoutes = map[string]bool{}

func TestOpenAPIDescribesEveryCoreRoute(t *testing.T) {
	// Routes are registered across the package (agent, self-test and policy
	// handlers have their own muxes), so every source file is read.
	sources, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	routePattern := regexp.MustCompile(`mux\.Handle(?:Func)?\("(GET|POST|PUT|PATCH|DELETE) /api/v1([^"]*)"`)
	routes := map[string]bool{}
	for _, name := range sources {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		source, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, match := range routePattern.FindAllStringSubmatch(string(source), -1) {
			path := strings.TrimSuffix(match[2], "{$}")
			if path == "" || path == "/" || path == "/openapi.yaml" {
				continue
			}
			routes[strings.ToLower(match[1])+" "+path] = true
		}
	}
	if len(routes) < 140 {
		t.Fatalf("found only %d routes; the route scan is broken", len(routes))
	}
	document, err := os.Open(filepath.Join("..", "..", "..", "..", "schemas", "api", "openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	defer document.Close()
	described := map[string]bool{}
	current := ""
	pathLine := regexp.MustCompile(`^  (/[^:]*):\s*$`)
	methodLine := regexp.MustCompile(`^    (get|post|put|patch|delete):`)
	scanner := bufio.NewScanner(document)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		if match := pathLine.FindStringSubmatch(line); match != nil {
			current = match[1]
			continue
		}
		if strings.HasPrefix(line, "components:") {
			break
		}
		if match := methodLine.FindStringSubmatch(line); match != nil && current != "" {
			described[match[1]+" "+current] = true
		}
	}
	missing := make([]string, 0)
	for route := range routes {
		if !described[route] && !openAPIPendingRoutes[route] {
			missing = append(missing, route)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("schemas/api/openapi.yaml is missing %d core routes:\n%s", len(missing), strings.Join(missing, "\n"))
	}
}

func TestJSONBodiesAcceptCharsetAndExplainDecodeFailures(t *testing.T) {
	server, session := configuredAPIServer(t, filepath.Join(t.TempDir(), "absent.sock"))
	charset := authenticatedJSONRequest(http.MethodPost, "/api/v1/auth/login", `{"username":"admin","password":"`+activationTestPassword+`"}`, "", "")
	charset.Header.Set("Content-Type", "application/json; charset=UTF-8")
	charset.Header.Del("Authorization")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, charset)
	if recorder.Code != http.StatusOK {
		t.Fatalf("charset content type was rejected: %d %s", recorder.Code, recorder.Body.String())
	}
	cases := []struct {
		name, contentType, body string
		status                  int
		code, contains          string
	}{
		{"media type", "text/plain", `{}`, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type: application/json"},
		{"latin1", "application/json; charset=latin1", `{}`, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type"},
		{"unknown field", "application/json", `{"username":"admin","pasword":"x"}`, http.StatusBadRequest, "invalid_request", `field "pasword" is not supported`},
		{"type", "application/json", `{"username":1}`, http.StatusBadRequest, "invalid_request", `field "username" must be a string`},
		{"syntax", "application/json", `{"username":`, http.StatusBadRequest, "invalid_request", "incomplete"},
		{"empty", "application/json", ``, http.StatusBadRequest, "invalid_request", "body is empty"},
		{"trailing", "application/json", `{} {}`, http.StatusBadRequest, "invalid_request", "exactly one JSON value"},
	}
	for _, tc := range cases {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(tc.body))
		request.Host = "shakerproxy.test"
		request.Header.Set("Content-Type", tc.contentType)
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, request)
		code, message := decodeErrorBody(t, recorder)
		if recorder.Code != tc.status || code != tc.code || !strings.Contains(message, tc.contains) || !strings.Contains(message, "login schema") {
			t.Fatalf("%s: got %d %s %q", tc.name, recorder.Code, code, message)
		}
	}
	_ = session
}

func TestActionPostsAcceptEmptyBodiesAndStopNeedsNoIdempotencyKey(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "gateway.sock")
	result := capture.View{Session: capture.Session{ID: captureTestID, StartedAt: time.Now()}, State: capture.StateRunning}
	requests := startGatewayStub(t, socketPath, result)
	server, session := configuredAPIServer(t, socketPath)
	request := authenticatedJSONRequest(http.MethodPost, "/api/v1/captures/"+captureTestID+"/stop", "", session, "")
	request.Header.Del("Content-Type")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("empty stop returned %d: %s", recorder.Code, recorder.Body.String())
	}
	if rpc := <-requests; rpc.Method != "StopCapture" {
		t.Fatalf("unexpected RPC %s", rpc.Method)
	}
	bad := authenticatedJSONRequest(http.MethodPost, "/api/v1/captures/"+captureTestID+"/stop", `{"now":true}`, session, "")
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, bad)
	if code, _ := decodeErrorBody(t, recorder); recorder.Code != http.StatusBadRequest || code != "invalid_request" {
		t.Fatalf("non-empty unknown stop body returned %d %s", recorder.Code, code)
	}
}

// startGatewayErrorStub answers one request with a JSON-RPC error.
func startGatewayErrorStub(t *testing.T, socketPath string, code int, message string) {
	t.Helper()
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		defer listener.Close()
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		var request gatewayprotocol.Request
		if json.NewDecoder(connection).Decode(&request) != nil {
			return
		}
		_ = json.NewEncoder(connection).Encode(gatewayprotocol.Response{JSONRPC: gatewayprotocol.JSONRPCVersion, ID: request.ID, Error: &gatewayprotocol.RPCError{Code: code, Message: message}})
	}()
}

func TestCaptureStatsMapsGatewayErrors(t *testing.T) {
	cases := []struct {
		code    int
		message string
		status  int
		errCode string
	}{
		{gatewayclient.CodeCaptureStatus, "lstat /var/lib/shakerproxy/captures/x/session.json: no such file or directory", http.StatusNotFound, "capture_not_found"},
		{gatewayclient.CodeCaptureUnavailable, "capture is unavailable in this daemon profile", http.StatusServiceUnavailable, "capture_unavailable"},
		{gatewayclient.CodeCaptureStatus, "capture metadata is not a bounded regular file", http.StatusServiceUnavailable, "capture_unavailable"},
	}
	for _, tc := range cases {
		socketPath := filepath.Join(t.TempDir(), "gateway.sock")
		startGatewayErrorStub(t, socketPath, tc.code, tc.message)
		server, session := configuredAPIServer(t, socketPath)
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, authenticatedJSONRequest(http.MethodGet, "/api/v1/captures/"+captureTestID, "", session, ""))
		if code, _ := decodeErrorBody(t, recorder); recorder.Code != tc.status || code != tc.errCode {
			t.Fatalf("%q mapped to %d %s", tc.message, recorder.Code, code)
		}
	}
	server, session := configuredAPIServer(t, filepath.Join(t.TempDir(), "absent.sock"))
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, authenticatedJSONRequest(http.MethodGet, "/api/v1/captures/"+captureTestID, "", session, ""))
	if code, _ := decodeErrorBody(t, recorder); recorder.Code != http.StatusServiceUnavailable || code != "gateway_unavailable" {
		t.Fatalf("unreachable gateway mapped to %d %s", recorder.Code, code)
	}
}

func TestCaptureRetentionSchedulerLogsProfileUnavailabilityOnce(t *testing.T) {
	var logs strings.Builder
	server, _ := configuredAPIServer(t, filepath.Join(t.TempDir(), "absent.sock"))
	server.logger = newTestLogger(&logs)
	unavailable := &gatewayclient.RemoteError{Code: gatewayclient.CodeCaptureUnavailable, Message: "capture is unavailable in this daemon profile"}
	for range 5 {
		server.reportCaptureRetentionSchedulerResult(errors.Join(errors.New("resume capture retention runs"), unavailable))
	}
	if strings.Count(logs.String(), "capture retention scheduler idle") != 1 || strings.Contains(logs.String(), "level=ERROR") {
		t.Fatalf("profile unavailability was not logged once at info level:\n%s", logs.String())
	}
	other := errors.New("gateway daemon: host inspection failed")
	for range 3 {
		server.reportCaptureRetentionSchedulerResult(other)
	}
	server.reportCaptureRetentionSchedulerResult(nil)
	if strings.Count(logs.String(), "level=ERROR") != 1 || strings.Count(logs.String(), "scheduler recovered") != 1 {
		t.Fatalf("repeated failures were not deduplicated:\n%s", logs.String())
	}
}

func TestCaptureDeletionCompletesWhenTheClientDisconnects(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "gateway.sock")
	preview := coordinatorDeletionPreview(t, 0)
	completedAt := time.Now().UTC().Truncate(time.Microsecond)
	hostJob := capture.DeletionJob{Schema: 1, ID: "capture-delete-0123456789abcdef0123456789abcdef", SessionID: captureTestID, State: capture.DeletionCompleted, Phase: "VERIFIED", ProgressPercent: 100, Administrator: "admin", PreviewSHA256: preview.HostArtifacts.PreviewSHA256, Footprint: preview.HostArtifacts.Footprint, RetainedDataClasses: []string{"normalized_event_metadata"}, CreatedAt: completedAt, UpdatedAt: completedAt, CompletedAt: &completedAt}
	startGatewayStub(t, socketPath, hostJob)
	events := &captureDeletionEventStub{preview: preview.NormalizedEvents}
	server, session := configuredAPIServerWithConfig(t, socketPath, func(config *Config) {
		config.CaptureEventDeletions = events
		configureAnalyzerDeletionPreviews(config, preview)
	})
	body, err := json.Marshal(deleteCaptureRequest{Password: activationTestPassword, Preview: preview, Confirmation: captureTestID})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request := authenticatedJSONRequest(http.MethodPost, "/api/v1/captures/"+captureTestID+"/deletion-jobs", string(body), session, "capture-delete-disconnect-0001").WithContext(ctx)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	var job coordinatedCaptureDeletionJob
	if recorder.Code != http.StatusAccepted || json.Unmarshal(recorder.Body.Bytes(), &job) != nil || job.State != coordinatedDeletionCompleted {
		t.Fatalf("deletion did not survive the client disconnect: %d %s", recorder.Code, recorder.Body.String())
	}
}
