package server

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/notify"
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

	// The Slack URL is a credential: no reader gets it back, and sending the
	// masked view back (as the UI does on its next change) keeps it.
	view := serve(tokenRequest(http.MethodGet, "/api/v1/integrations/notifications", session))
	if strings.Contains(view.Body.String(), "hooks.example.com/x") || !strings.Contains(view.Body.String(), `"url":"https://hooks.example.com/[redacted]"`) {
		t.Fatalf("GET exposes the webhook URL: %s", view.Body.String())
	}
	roundTrip := strings.NewReplacer(`"url":"https://hooks.example.com/x"`, `"url":"https://hooks.example.com/[redacted]"`, `"expected_revision":0`, `"expected_revision":1`, `"password":"wrong"`, `"password":"`+activationTestPassword+`"`).Replace(body)
	if kept := serve(authenticatedJSONRequest(http.MethodPut, "/api/v1/integrations/notifications", roundTrip, session, "")); kept.Code != http.StatusOK {
		t.Fatalf("round-trip PUT returned %d: %s", kept.Code, kept.Body.String())
	}
	stored, err := notify.LoadConfig(filepath.Join(dir, "notifications.json"))
	if err != nil || len(stored.Channels) != 2 || stored.Channels[1].URL != "https://hooks.example.com/x" {
		t.Fatalf("stored channels after a round-trip = %#v (%v)", stored.Channels, err)
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

// A fresh install has no rules and no notifications. The dashboard reads both
// lists' lengths, so they must be [] and never null (beta.33 sent null and
// the whole Integrations page failed to render).
func TestNotificationsFreshInstallSendsEmptyListsNotNull(t *testing.T) {
	dir := t.TempDir()
	server, session := configuredAPIServerWithConfig(t, filepath.Join(t.TempDir(), "absent.sock"), func(config *Config) {
		config.NotifyConfigPath = filepath.Join(dir, "notifications.json")
		config.NotifyLogPath = filepath.Join(dir, "notification-log.json")
	})
	for _, check := range []struct{ path, want string }{
		{"/api/v1/integrations/notifications", `"rules":[]`},
		{"/api/v1/notifications", `"notifications":[]`},
	} {
		request := tokenRequest(http.MethodGet, check.path, session)
		request.Host = "shakerproxy.test"
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), check.want) || strings.Contains(recorder.Body.String(), "null") {
			t.Fatalf("GET %s = %d %s; want %s and no null", check.path, recorder.Code, recorder.Body.String(), check.want)
		}
	}
}

func TestNotificationSeedingWaitsForAnAvailableReport(t *testing.T) {
	const present = "device-00000000000000000000000000000001"
	server := &Server{notifyEvalState: &notifyState{lastFired: map[string]time.Time{}, known: map[string]bool{}}}
	// The report is down while the rule is off: nothing is learned.
	server.seedKnownDevicesFrom(labRoutingReport{Available: false})
	if server.notifyEvalState.seeded {
		t.Fatal("an unavailable report marked the device list seeded")
	}
	// Once it is back the present device is learned quietly, not announced.
	server.seedKnownDevicesFrom(labRoutingReport{Available: true, Devices: []labRoutingDevice{{DeviceID: present}}})
	if !server.notifyEvalState.seeded || server.noteNewDevice(present) {
		t.Fatal("a device present at seeding was announced as new")
	}
	if !server.noteNewDevice("device-00000000000000000000000000000002") {
		t.Fatal("a device that joined later was not announced")
	}
}

func TestNotificationStateSurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	newServer := func() *Server {
		server := &Server{notifyConfigPath: filepath.Join(dir, "notifications.json"), notifyLogPath: filepath.Join(dir, "notification-log.json"), logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
		server.notifyEvalState = server.loadNotifyState()
		return server
	}
	first := newServer()
	first.seedKnownDevicesFrom(labRoutingReport{Available: true, Devices: []labRoutingDevice{{DeviceID: "device-00000000000000000000000000000001"}}})
	first.notifyEvalState.lastFired["r1\x00BYPASSING"] = time.Now().UTC()
	first.saveNotifyState()

	second := newServer()
	if !second.notifyEvalState.seeded || second.noteNewDevice("device-00000000000000000000000000000001") || len(second.notifyEvalState.lastFired) != 1 {
		t.Fatalf("restored state = %#v", second.notifyEvalState)
	}
}
