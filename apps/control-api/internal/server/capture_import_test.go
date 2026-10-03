package server

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/apitoken"
	"shakerproxy.dev/shakerproxy/internal/capture"
	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/pcapng/pcapngtest"
)

func smallImportPCAPNG() []byte {
	frame := make([]byte, 60)
	frame[12], frame[13] = 0x08, 0x00
	base := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	return pcapngtest.File(1, []pcapngtest.RawPacket{
		{At: base, Data: frame}, {At: base.Add(time.Second), Data: frame}, {At: base.Add(2 * time.Second), Data: frame},
	})
}

func multipartCapture(t *testing.T, name string, file []byte) (*bytes.Buffer, string) {
	t.Helper()
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	if name != "" {
		if err := writer.WriteField("name", name); err != nil {
			t.Fatal(err)
		}
	}
	part, err := writer.CreateFormFile("file", "unifi-gateway.pcapng")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(file); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return body, writer.FormDataContentType()
}

func TestImportCaptureStreamsToTheGateway(t *testing.T) {
	fixture := newIntelFixture(t)
	socket := filepath.Join(t.TempDir(), "gw.sock")
	fixture.server.gateway.SocketPath = socket
	sessionID := "capture-00112233445566778899aabbccddeeff"

	begin := func(req gatewayprotocol.Request) any {
		if req.Method != "BeginCaptureImport" {
			t.Errorf("first call = %s, want BeginCaptureImport", req.Method)
		}
		return gatewayprotocol.BeginCaptureImportResult{SessionID: sessionID}
	}
	appendEOF := func(req gatewayprotocol.Request) any {
		if req.Method != "AppendCaptureImport" {
			t.Errorf("second call = %s, want AppendCaptureImport", req.Method)
		}
		var params gatewayprotocol.AppendCaptureImportParams
		_ = gatewayprotocol.DecodeParams(req.Params, &params)
		if !params.EOF {
			t.Errorf("a one-chunk upload did not carry EOF: %#v", params)
		}
		result := capture.ImportResult{SessionID: sessionID, Packets: 3, SizeBytes: int64(len(params.Data))}
		return gatewayprotocol.AppendCaptureImportResult{Done: true, Result: &result}
	}
	requests := startGatewaySequenceStub(t, socket, begin, appendEOF)

	body, contentType := multipartCapture(t, "UniFi capture", smallImportPCAPNG())
	request := httptest.NewRequest(http.MethodPost, "/api/v1/captures/import", body)
	request.Host = "shakerproxy.test"
	request.Header.Set("Content-Type", contentType)
	request.Header.Set("Authorization", "Bearer "+fixture.session)
	recorder := httptest.NewRecorder()
	fixture.server.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusCreated {
		t.Fatalf("import returned %d: %s", recorder.Code, recorder.Body.String())
	}
	var response captureImportResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.SessionID != sessionID || response.ViewPath != "/#/traffic?capture_session_id="+sessionID {
		t.Fatalf("unexpected response: %#v", response)
	}
	<-requests // Begin
	<-requests // Append
}

func TestImportCaptureRejectsBadRequests(t *testing.T) {
	fixture := newIntelFixture(t)

	// Not multipart.
	request := authenticatedJSONRequest(http.MethodPost, "/api/v1/captures/import", "{}", fixture.session, "")
	recorder := httptest.NewRecorder()
	fixture.server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("non-multipart import returned %d", recorder.Code)
	}

	// A read-only token may not import.
	body, contentType := multipartCapture(t, "x", smallImportPCAPNG())
	forbidden := httptest.NewRequest(http.MethodPost, "/api/v1/captures/import", body)
	forbidden.Host = "shakerproxy.test"
	forbidden.Header.Set("Content-Type", contentType)
	forbidden.Header.Set("Authorization", "Bearer "+fixture.token(t, apitoken.ScopeTrafficRead))
	recorder = httptest.NewRecorder()
	fixture.server.Handler().ServeHTTP(recorder, forbidden)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("read-only import returned %d", recorder.Code)
	}
}
