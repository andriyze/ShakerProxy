package server

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestNotificationsConfigAndInApp(t *testing.T) {
	dir := t.TempDir()
	server, session := configuredAPIServerWithConfig(t, filepath.Join(t.TempDir(), "absent.sock"), func(config *Config) {
		config.NotifyConfigPath = filepath.Join(dir, "notifications.json")
		config.NotifyLogPath = filepath.Join(dir, "notification-log.json")
	})
	serve := func(request *http.Request) *httptest.ResponseRecorder {
		request.Host = "shakerproxy.test"
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, request)
		return recorder
	}

	// Starts inert: the in-app channel, no rules, revision 0.
	get := serve(tokenRequest(http.MethodGet, "/api/v1/integrations/notifications", session))
	if get.Code != http.StatusOK || !strings.Contains(get.Body.String(), `"enabled":false`) || !strings.Contains(get.Body.String(), `"revision":0`) {
		t.Fatalf("initial GET returned %d: %s", get.Code, get.Body.String())
	}

	// A wrong password is rejected.
	body := `{"channels":[{"id":"in-app","kind":"IN_APP","name":"In-app notifications","enabled":true},{"id":"ops","kind":"SLACK","name":"Ops","enabled":true,"url":"https://hooks.example.com/x"}],"rules":[{"id":"r1","trigger":"CLEARTEXT_EXPOSURE","channels":["in-app","ops"],"enabled":true}],"expected_revision":0,"password":"wrong"}`
	bad := serve(authenticatedJSONRequest(http.MethodPut, "/api/v1/integrations/notifications", body, session, ""))
	if bad.Code == http.StatusOK {
		t.Fatalf("wrong password accepted: %d", bad.Code)
	}

	// With the password it is saved: revision 1, enabled.
	ok := serve(authenticatedJSONRequest(http.MethodPut, "/api/v1/integrations/notifications", strings.Replace(body, `"password":"wrong"`, `"password":"`+activationTestPassword+`"`, 1), session, ""))
	if ok.Code != http.StatusOK || !strings.Contains(ok.Body.String(), `"enabled":true`) || !strings.Contains(ok.Body.String(), `"revision":1`) {
		t.Fatalf("PUT returned %d: %s", ok.Code, ok.Body.String())
	}

	// A stale revision conflicts.
	stale := serve(authenticatedJSONRequest(http.MethodPut, "/api/v1/integrations/notifications", strings.Replace(body, `"password":"wrong"`, `"password":"`+activationTestPassword+`"`, 1), session, ""))
	if stale.Code != http.StatusConflict {
		t.Fatalf("stale revision returned %d: %s", stale.Code, stale.Body.String())
	}

	// A test notification to the in-app channel is stored.
	test := serve(authenticatedJSONRequest(http.MethodPost, "/api/v1/integrations/notifications/test", `{"channel":"in-app"}`, session, ""))
	if test.Code != http.StatusOK || !strings.Contains(test.Body.String(), `"delivered":true`) {
		t.Fatalf("test notification returned %d: %s", test.Code, test.Body.String())
	}
	list := serve(tokenRequest(http.MethodGet, "/api/v1/notifications", session))
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), "Test notification") || !strings.Contains(list.Body.String(), `"unread":1`) {
		t.Fatalf("notifications list returned %d: %s", list.Code, list.Body.String())
	}

	// Marking read clears the unread count.
	read := serve(authenticatedJSONRequest(http.MethodPost, "/api/v1/notifications/read", `{}`, session, ""))
	if read.Code != http.StatusOK || !strings.Contains(read.Body.String(), `"changed":1`) {
		t.Fatalf("mark read returned %d: %s", read.Code, read.Body.String())
	}
	after := serve(tokenRequest(http.MethodGet, "/api/v1/notifications", session))
	if !strings.Contains(after.Body.String(), `"unread":0`) {
		t.Fatalf("still unread after mark: %s", after.Body.String())
	}
}
