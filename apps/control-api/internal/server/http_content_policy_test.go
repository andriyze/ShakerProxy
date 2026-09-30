package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"shakerproxy.dev/shakerproxy/internal/contentpolicy"
)

func TestHTTPContentPolicyIsSessionOnlyReauthenticatedAndRevisioned(t *testing.T) {
	server, session := configuredAPIServer(t, filepath.Join(t.TempDir(), "absent.sock"))
	policyPath := filepath.Join(t.TempDir(), "content-policy", "policy.json")
	handler := server.HTTPContentPolicyHandler(policyPath)

	unauthenticated := httptest.NewRequest(http.MethodGet, "/api/v1/http-content-policy", nil)
	unauthenticated.Host = "shakerproxy.test"
	unauthenticatedRecorder := httptest.NewRecorder()
	handler.ServeHTTP(unauthenticatedRecorder, unauthenticated)
	if unauthenticatedRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated content policy returned %d", unauthenticatedRecorder.Code)
	}

	get := authenticatedJSONRequest(http.MethodGet, "/api/v1/http-content-policy", "", session, "")
	getRecorder := httptest.NewRecorder()
	handler.ServeHTTP(getRecorder, get)
	if getRecorder.Code != http.StatusOK || getRecorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("content policy GET returned %d headers=%v body=%s", getRecorder.Code, getRecorder.Header(), getRecorder.Body.String())
	}
	var initial httpContentPolicyView
	if err := json.Unmarshal(getRecorder.Body.Bytes(), &initial); err != nil {
		t.Fatal(err)
	}
	if initial.Schema != 1 || initial.Policy.Revision != 1 || !initial.Policy.CaptureHTTPContent || !initial.TLSInterceptionIndependent || !initial.AppliesWithoutRestart || initial.StorageBoundary != "local_sensor_only" {
		t.Fatalf("unexpected initial content policy: %#v", initial)
	}

	wrongPassword := authenticatedJSONRequest(http.MethodPut, "/api/v1/http-content-policy", `{"expected_revision":1,"capture_http_content":false,"password":"wrong"}`, session, "")
	wrongRecorder := httptest.NewRecorder()
	handler.ServeHTTP(wrongRecorder, wrongPassword)
	if wrongRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("wrong-password mutation returned %d: %s", wrongRecorder.Code, wrongRecorder.Body.String())
	}

	apply := authenticatedJSONRequest(http.MethodPut, "/api/v1/http-content-policy", `{"expected_revision":1,"capture_http_content":false,"password":"`+activationTestPassword+`"}`, session, "")
	applyRecorder := httptest.NewRecorder()
	handler.ServeHTTP(applyRecorder, apply)
	if applyRecorder.Code != http.StatusOK {
		t.Fatalf("content policy mutation returned %d: %s", applyRecorder.Code, applyRecorder.Body.String())
	}
	var disabled httpContentPolicyView
	if err := json.Unmarshal(applyRecorder.Body.Bytes(), &disabled); err != nil {
		t.Fatal(err)
	}
	if disabled.Policy.Revision != 2 || disabled.Policy.CaptureHTTPContent || disabled.Policy.UpdatedBy != "admin" {
		t.Fatalf("unexpected disabled policy: %#v", disabled)
	}
	persisted, err := (&contentpolicy.Store{Path: policyPath}).Load()
	if err != nil || persisted != disabled.Policy {
		t.Fatalf("persisted policy mismatch: %#v err=%v", persisted, err)
	}

	stale := authenticatedJSONRequest(http.MethodPut, "/api/v1/http-content-policy", `{"expected_revision":1,"capture_http_content":true,"password":"`+activationTestPassword+`"}`, session, "")
	staleRecorder := httptest.NewRecorder()
	handler.ServeHTTP(staleRecorder, stale)
	if staleRecorder.Code != http.StatusConflict {
		t.Fatalf("stale mutation returned %d: %s", staleRecorder.Code, staleRecorder.Body.String())
	}
}

func TestHTTPContentPolicyRejectsQueriesAndUnknownFields(t *testing.T) {
	server, session := configuredAPIServer(t, filepath.Join(t.TempDir(), "absent.sock"))
	handler := server.HTTPContentPolicyHandler(filepath.Join(t.TempDir(), "policy.json"))

	request := authenticatedJSONRequest(http.MethodGet, "/api/v1/http-content-policy?revision=1", "", session, "")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("query-bearing GET returned %d: %s", recorder.Code, recorder.Body.String())
	}

	request = authenticatedJSONRequest(http.MethodPut, "/api/v1/http-content-policy", `{"expected_revision":1,"capture_http_content":false,"password":"`+activationTestPassword+`","unexpected":true}`, session, "")
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("unknown-field mutation returned %d: %s", recorder.Code, recorder.Body.String())
	}
}
