package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"shakerproxy.dev/shakerproxy/internal/capture"
	"shakerproxy.dev/shakerproxy/internal/casework"
	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
)

const caseAPICaptureID = "capture-0123456789abcdef0123456789abcdef"

func TestCaseAPIProtectsCaptureAndMakesOperationReplayIdempotent(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "gateway.sock")
	requests := startGatewaySequenceStub(t, socketPath,
		capture.View{Session: capture.Session{ID: caseAPICaptureID}},
		capture.View{Session: capture.Session{ID: caseAPICaptureID}},
		func(request gatewayprotocol.Request) any {
			var params gatewayprotocol.SetCaptureEvidenceHoldParams
			if err := gatewayprotocol.DecodeParams(request.Params, &params); err != nil {
				t.Error(err)
			}
			return capture.EvidenceHold{SessionID: params.Request.SessionID, Revision: 1, Active: true, CaseID: params.Request.CaseID}
		},
		func(gatewayprotocol.Request) any {
			return capture.View{Session: capture.Session{ID: caseAPICaptureID}, EvidenceHold: &capture.EvidenceHold{SessionID: caseAPICaptureID, Revision: 1, Active: true}}
		},
		func(request gatewayprotocol.Request) any {
			var params gatewayprotocol.SetCaptureEvidenceHoldParams
			if err := gatewayprotocol.DecodeParams(request.Params, &params); err != nil {
				t.Error(err)
			}
			return capture.EvidenceHold{SessionID: params.Request.SessionID, Revision: 2, Active: false}
		},
	)
	caseStore := &casework.Store{Path: filepath.Join(t.TempDir(), "cases.json")}
	server, session := configuredAPIServerWithConfig(t, socketPath, func(config *Config) { config.Cases = caseStore })

	created := serveCaseRequest(t, server, session, http.MethodPost, "/api/v1/cases", `{"name":"Camera incident","description":"Bench investigation","reason":"authorized investigation"}`, "")
	if created.Code != http.StatusCreated {
		t.Fatalf("create returned %d: %s", created.Code, created.Body.String())
	}
	var item casework.Case
	if err := json.Unmarshal(created.Body.Bytes(), &item); err != nil {
		t.Fatal(err)
	}

	evidenceBody := `{"expected_revision":1,"kind":"CAPTURE","artifact_id":"` + caseAPICaptureID + `","label":"Incident packets","reason":"attach final capture"}`
	attached := serveCaseRequest(t, server, session, http.MethodPost, "/api/v1/cases/"+item.ID+"/evidence", evidenceBody, "")
	if attached.Code != http.StatusCreated {
		t.Fatalf("attach returned %d: %s", attached.Code, attached.Body.String())
	}
	if err := json.Unmarshal(attached.Body.Bytes(), &item); err != nil {
		t.Fatal(err)
	}

	holdOperation := "case-hold-api-operation-0001"
	holdBody := `{"expected_revision":2,"active":true,"reason":"preserve incident evidence","password":"` + activationTestPassword + `"}`
	held := serveCaseRequest(t, server, session, http.MethodPost, "/api/v1/cases/"+item.ID+"/hold", holdBody, holdOperation)
	if held.Code != http.StatusOK || !strings.Contains(held.Body.String(), `"state":"ACTIVE"`) || !strings.Contains(held.Body.String(), `"operation_id":"`+holdOperation+`"`) {
		t.Fatalf("hold returned %d: %s", held.Code, held.Body.String())
	}
	if err := json.Unmarshal(held.Body.Bytes(), &item); err != nil {
		t.Fatal(err)
	}

	replay := serveCaseRequest(t, server, session, http.MethodPost, "/api/v1/cases/"+item.ID+"/hold", holdBody, holdOperation)
	if replay.Code != http.StatusOK || replay.Body.String() != held.Body.String() {
		t.Fatalf("hold replay changed result: %d %s", replay.Code, replay.Body.String())
	}

	releaseOperation := "case-hold-api-operation-0002"
	releaseBody := `{"expected_revision":3,"active":false,"reason":"custodian approved release","password":"` + activationTestPassword + `"}`
	released := serveCaseRequest(t, server, session, http.MethodPost, "/api/v1/cases/"+item.ID+"/hold", releaseBody, releaseOperation)
	if released.Code != http.StatusOK || !strings.Contains(released.Body.String(), `"state":"INACTIVE"`) {
		t.Fatalf("release returned %d: %s", released.Code, released.Body.String())
	}

	methods := make([]string, 0, 5)
	for request := range requests {
		methods = append(methods, request.Method)
		if request.Method == "SetCaptureEvidenceHold" {
			var params gatewayprotocol.SetCaptureEvidenceHoldParams
			if err := gatewayprotocol.DecodeParams(request.Params, &params); err != nil {
				t.Fatal(err)
			}
			expectedOperation := releaseOperation
			if params.Request.Active {
				expectedOperation = holdOperation
			}
			if params.Request.IdempotencyKey != caseHoldArtifactKey(expectedOperation, item.Evidence[0].ID) {
				t.Fatalf("unexpected derived hold identity: %q", params.Request.IdempotencyKey)
			}
			if params.Request.CaseID != item.ID || params.Request.Actor != "admin" || strings.Contains(string(request.Params), activationTestPassword) {
				t.Fatalf("unsafe hold RPC: %s", request.Params)
			}
		}
	}
	expected := []string{"GetCaptureStats", "GetCaptureStats", "SetCaptureEvidenceHold", "GetCaptureStats", "SetCaptureEvidenceHold"}
	if strings.Join(methods, ",") != strings.Join(expected, ",") {
		t.Fatalf("unexpected RPC sequence: %v", methods)
	}
}

func TestCaseHoldRejectsUnsafeOperationKeyBeforeHostRPC(t *testing.T) {
	caseStore := &casework.Store{Path: filepath.Join(t.TempDir(), "cases.json")}
	server, session := configuredAPIServerWithConfig(t, filepath.Join(t.TempDir(), "absent.sock"), func(config *Config) { config.Cases = caseStore })
	response := serveCaseRequest(t, server, session, http.MethodPost, "/api/v1/cases/case-0123456789abcdef0123456789abcdef/hold", `{"expected_revision":1,"active":true,"reason":"preserve","password":"`+activationTestPassword+`"}`, "unsafe key with spaces")
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "invalid_idempotency_key") {
		t.Fatalf("unsafe operation identity returned %d: %s", response.Code, response.Body.String())
	}
}

func serveCaseRequest(t *testing.T, server *Server, session, method, target, body, operationID string) *httptest.ResponseRecorder {
	t.Helper()
	request := authenticatedJSONRequest(method, target, body, session, operationID)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	return recorder
}
