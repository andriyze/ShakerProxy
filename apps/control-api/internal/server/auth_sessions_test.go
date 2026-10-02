package server

import (
	"crypto/sha256"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/apitoken"
	deviceinventory "shakerproxy.dev/shakerproxy/internal/inventory"
)

type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func newTestLogger(w io.Writer) *slog.Logger {
	return slog.New(slog.NewTextHandler(&lockedWriter{w: w}, nil))
}

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func loginForTest(t *testing.T, server *Server, password string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"username":"admin","password":"`+password+`"}`))
	request.Host = "shakerproxy.test"
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	var body map[string]any
	_ = json.Unmarshal(recorder.Body.Bytes(), &body)
	return recorder, body
}

func TestSessionsSlideAndExpireAndLogoutRevokes(t *testing.T) {
	server, _ := configuredAPIServer(t, filepath.Join(t.TempDir(), "absent.sock"))
	clock := &testClock{now: time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)}
	server.clock = clock.Now
	recorder, body := loginForTest(t, server, activationTestPassword)
	token, _ := body["session_token"].(string)
	if recorder.Code != http.StatusOK || token == "" || body["expires_at"] != "2026-09-29T11:00:00Z" || body["absolute_expires_at"] != "2026-09-29T22:00:00Z" || body["expires_in_seconds"] != float64(3600) {
		t.Fatalf("login returned %d %v", recorder.Code, body)
	}
	use := func() *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, authenticatedJSONRequest(http.MethodGet, "/api/v1/auth/tokens", "", token, ""))
		return recorder
	}
	// Each use within the idle timeout slides the expiry forward, up to the
	// absolute lifetime (10:00 + 12h).
	succeeded := 0
	for range 20 {
		clock.Advance(50 * time.Minute)
		if response := use(); response.Code == http.StatusUnauthorized {
			break
		}
		succeeded++
	}
	if succeeded != 14 {
		t.Fatalf("session was usable for %d sliding intervals, want 14", succeeded)
	}
	recorder, body = loginForTest(t, server, activationTestPassword)
	token, _ = body["session_token"].(string)
	clock.Advance(30 * time.Minute)
	if response := use(); response.Code != http.StatusServiceUnavailable || response.Header().Get("X-ShakerProxy-Session-Expires-At") != clock.Now().Add(time.Hour).Format(time.RFC3339) {
		t.Fatalf("session did not slide: %d %q", response.Code, response.Header().Get("X-ShakerProxy-Session-Expires-At"))
	}
	clock.Advance(61 * time.Minute)
	if response := use(); response.Code != http.StatusUnauthorized {
		t.Fatalf("idle session was not expired: %d", response.Code)
	}
	_, body = loginForTest(t, server, activationTestPassword)
	token, _ = body["session_token"].(string)
	logout := httptest.NewRecorder()
	server.Handler().ServeHTTP(logout, authenticatedJSONRequest(http.MethodPost, "/api/v1/auth/logout", "", token, ""))
	if logout.Code != http.StatusOK || !strings.Contains(logout.Body.String(), `"logged_out":true`) {
		t.Fatalf("logout returned %d %s", logout.Code, logout.Body.String())
	}
	if response := use(); response.Code != http.StatusUnauthorized {
		t.Fatalf("logged-out session still works: %d", response.Code)
	}
	again := httptest.NewRecorder()
	server.Handler().ServeHTTP(again, authenticatedJSONRequest(http.MethodPost, "/api/v1/auth/logout", "", token, ""))
	if again.Code != http.StatusOK || !strings.Contains(again.Body.String(), `"logged_out":false`) {
		t.Fatalf("repeated logout returned %d %s", again.Code, again.Body.String())
	}
}

func TestRecentPasswordConfirmationWindow(t *testing.T) {
	server, _ := configuredAPIServer(t, filepath.Join(t.TempDir(), "absent.sock"))
	clock := &testClock{now: time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)}
	server.clock = clock.Now
	unverified, err := server.newSession("admin")
	if err != nil {
		t.Fatal(err)
	}
	server.inventory = &deviceinventory.Store{Path: filepath.Join(t.TempDir(), "inventory.json"), Now: clock.Now}
	server.apiTokens = &apitoken.Store{Path: filepath.Join(t.TempDir(), "tokens.json")}
	seedInventoryDevice(t, server)
	deviceID := firstDeviceID(t, server)
	rename := func(session, body string) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, authenticatedJSONRequest(http.MethodPut, "/api/v1/devices/"+deviceID+"/metadata", body, session, ""))
		return recorder
	}
	// A session that never confirmed the password must provide it.
	response := rename(unverified, `{"notes":"one"}`)
	if code, _ := decodeErrorBody(t, response); response.Code != http.StatusUnauthorized || code != "reauthentication_required" {
		t.Fatalf("unconfirmed session edit returned %d %s", response.Code, code)
	}
	if response := rename(unverified, `{"notes":"one","password":"wrong-password"}`); response.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password was accepted: %d", response.Code)
	}
	// Confirming once opens the 10 minute window for the same session.
	if response := rename(unverified, `{"notes":"one","password":"`+activationTestPassword+`"}`); response.Code != http.StatusOK {
		t.Fatalf("confirmed edit returned %d %s", response.Code, response.Body.String())
	}
	if response := rename(unverified, `{"notes":"two"}`); response.Code != http.StatusOK {
		t.Fatalf("edit inside the window returned %d %s", response.Code, response.Body.String())
	}
	// Signing in counts as a password confirmation.
	_, body := loginForTest(t, server, activationTestPassword)
	fresh, _ := body["session_token"].(string)
	if response := rename(fresh, `{"notes":"three"}`); response.Code != http.StatusOK {
		t.Fatalf("edit right after sign-in returned %d %s", response.Code, response.Body.String())
	}
	// Dangerous actions still need the password every time.
	createToken := httptest.NewRecorder()
	server.Handler().ServeHTTP(createToken, authenticatedJSONRequest(http.MethodPost, "/api/v1/auth/tokens", `{"name":"ci","scopes":["lab:write"],"expires_in_seconds":3600}`, fresh, ""))
	if code, _ := decodeErrorBody(t, createToken); createToken.Code != http.StatusUnauthorized || code != "password_required" {
		t.Fatalf("token creation without password returned %d %s", createToken.Code, code)
	}
	createToken = httptest.NewRecorder()
	server.Handler().ServeHTTP(createToken, authenticatedJSONRequest(http.MethodPost, "/api/v1/auth/tokens", `{"name":"ci","scopes":["lab:write"],"expires_in_seconds":3600,"password":"`+activationTestPassword+`"}`, fresh, ""))
	if createToken.Code != http.StatusCreated || !strings.Contains(createToken.Body.String(), `"lab:write"`) {
		t.Fatalf("lab:write token creation returned %d %s", createToken.Code, createToken.Body.String())
	}
	// Other sessions do not share the window, and it expires.
	clock.Advance(recentAuthenticationWindow + time.Second)
	response = rename(fresh, `{"notes":"four"}`)
	if code, _ := decodeErrorBody(t, response); response.Code != http.StatusUnauthorized || code != "reauthentication_required" {
		t.Fatalf("edit after the window returned %d %s", response.Code, code)
	}
}

func TestFailedPasswordAttemptsAreRateLimited(t *testing.T) {
	server, _ := configuredAPIServer(t, filepath.Join(t.TempDir(), "absent.sock"))
	clock := &testClock{now: time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)}
	server.clock = clock.Now
	for attempt := 0; attempt < authFailureLimit; attempt++ {
		if response, _ := loginForTest(t, server, "Wrong-password-123!"); response.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d returned %d", attempt, response.Code)
		}
	}
	response, _ := loginForTest(t, server, activationTestPassword)
	if code, _ := decodeErrorBody(t, response); response.Code != http.StatusTooManyRequests || code != "too_many_attempts" || response.Header().Get("Retry-After") == "" {
		t.Fatalf("rate limited login returned %d %s retry=%q", response.Code, code, response.Header().Get("Retry-After"))
	}
	clock.Advance(authFailureWindow)
	if response, _ := loginForTest(t, server, activationTestPassword); response.Code != http.StatusOK {
		t.Fatalf("login after the window returned %d", response.Code)
	}
}

func setupAdministratorForTest(t *testing.T) (*Server, []string, string) {
	t.Helper()
	dataDirectory := filepath.Join(t.TempDir(), "data")
	tokenPath := filepath.Join(t.TempDir(), "setup-token.sha256")
	digest := sha256.Sum256([]byte("install-setup-token"))
	if err := os.WriteFile(tokenPath, digest[:], 0o400); err != nil {
		t.Fatal(err)
	}
	uid := os.Getuid()
	server := New(Config{Store: NewStore(dataDirectory, tokenPath), AllowedHosts: []string{"shakerproxy.test"}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), AdminResetRequestPath: filepath.Join(dataDirectory, adminResetRequestName), AdminResetOwnerUID: &uid})
	codes, err := server.store.CreateAdmin("install-setup-token", "admin", activationTestPassword)
	if err != nil {
		t.Fatal(err)
	}
	return server, codes, dataDirectory
}

func recoverForTest(server *Server, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/recover", strings.NewReader(body))
	request.Host = "shakerproxy.test"
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	return recorder
}

func TestRecoveryCodesAreSingleUseAndEnforcePasswordPolicy(t *testing.T) {
	server, codes, _ := setupAdministratorForTest(t)
	oldSession, err := server.newSession("admin")
	if err != nil {
		t.Fatal(err)
	}
	const newPassword = "Recovered-Password-42!"
	weak := recoverForTest(server, `{"username":"admin","recovery_code":"`+codes[0]+`","new_password":"short"}`)
	if code, _ := decodeErrorBody(t, weak); weak.Code != http.StatusBadRequest || code != "weak_password" {
		t.Fatalf("weak password returned %d %s", weak.Code, code)
	}
	// Lower case and missing dashes are accepted; the weak attempt did not burn the code.
	typed := strings.ToLower(strings.ReplaceAll(codes[0], "-", ""))
	recovered := recoverForTest(server, `{"username":"admin","recovery_code":"`+typed+`","new_password":"`+newPassword+`"}`)
	var body map[string]any
	if recovered.Code != http.StatusOK || json.Unmarshal(recovered.Body.Bytes(), &body) != nil || body["remaining_recovery_codes"] != float64(len(codes)-1) || body["session_token"] == "" || body["expires_at"] == nil {
		t.Fatalf("recovery returned %d %s", recovered.Code, recovered.Body.String())
	}
	if _, ok := server.authenticateSession(oldSession); ok {
		t.Fatal("recovery did not revoke existing sessions")
	}
	if ok, err := server.store.Authenticate("admin", newPassword); err != nil || !ok {
		t.Fatalf("new password does not authenticate: %v", err)
	}
	if ok, _ := server.store.Authenticate("admin", activationTestPassword); ok {
		t.Fatal("old password still authenticates")
	}
	reused := recoverForTest(server, `{"username":"admin","recovery_code":"`+codes[0]+`","new_password":"Another-Password-43!"}`)
	if code, _ := decodeErrorBody(t, reused); reused.Code != http.StatusUnauthorized || code != "invalid_recovery_code" {
		t.Fatalf("reused code returned %d %s", reused.Code, code)
	}
	wrongUser := recoverForTest(server, `{"username":"root","recovery_code":"`+codes[1]+`","new_password":"Another-Password-43!"}`)
	if wrongUser.Code != http.StatusUnauthorized {
		t.Fatalf("wrong username returned %d", wrongUser.Code)
	}
	if recovered := recoverForTest(server, `{"username":"admin","recovery_code":"`+codes[1]+`","new_password":"Another-Password-43!"}`); recovered.Code != http.StatusOK || !strings.Contains(recovered.Body.String(), `"remaining_recovery_codes":6`) {
		t.Fatalf("second code returned %d %s", recovered.Code, recovered.Body.String())
	}
}

func writeResetRequest(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(`{"requested_at":"2026-09-29T10:00:00Z","requested_by":"root via shakerproxy admin reset"}`), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func TestAdminResetRequestRotatesSetupTokenAndClearsCredentials(t *testing.T) {
	server, _, dataDirectory := setupAdministratorForTest(t)
	session, _ := server.newSession("admin")
	requestPath := filepath.Join(dataDirectory, adminResetRequestName)

	// Unsafe requests are rejected, removed, and change nothing.
	writeResetRequest(t, requestPath, 0o644)
	if server.handleAdminResetRequest() {
		t.Fatal("a group/world-readable request was honoured")
	}
	target := filepath.Join(t.TempDir(), "target")
	writeResetRequest(t, target, 0o600)
	if err := os.Symlink(target, requestPath); err != nil {
		t.Fatal(err)
	}
	if server.handleAdminResetRequest() {
		t.Fatal("a symlinked request was honoured")
	}
	if _, err := os.Lstat(requestPath); !os.IsNotExist(err) {
		t.Fatalf("rejected request was not removed: %v", err)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("symlink target was touched: %v", err)
	}
	otherOwner := os.Getuid() + 1
	server.adminResetOwnerUID = otherOwner
	writeResetRequest(t, requestPath, 0o600)
	if server.handleAdminResetRequest() {
		t.Fatal("a request with the wrong owner was honoured")
	}
	server.adminResetOwnerUID = os.Getuid()
	if configured, _ := server.store.IsConfigured(); !configured {
		t.Fatal("rejected requests cleared the administrator")
	}

	writeResetRequest(t, requestPath, 0o600)
	if !server.handleAdminResetRequest() {
		t.Fatal("valid reset request was not honoured")
	}
	if _, err := os.Lstat(requestPath); !os.IsNotExist(err) {
		t.Fatalf("handled request was not removed: %v", err)
	}
	if configured, _ := server.store.IsConfigured(); configured {
		t.Fatal("administrator credential was not cleared")
	}
	if _, err := os.Stat(filepath.Join(dataDirectory, "recovery-codes.json")); !os.IsNotExist(err) {
		t.Fatalf("recovery codes were not cleared: %v", err)
	}
	if _, ok := server.authenticateSession(session); ok {
		t.Fatal("sessions survived the reset")
	}
	tokenPath := filepath.Join(dataDirectory, "setup-token")
	info, err := os.Stat(tokenPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("rotated setup token receipt is missing or not 0600: %v %v", info, err)
	}
	token, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.store.CreateAdmin("install-setup-token", "admin", activationTestPassword); err == nil {
		t.Fatal("the original installation setup token still works after a reset")
	}
	if _, err := server.store.CreateAdmin(strings.TrimSpace(string(token)), "admin", "Brand-New-Password-7!"); err != nil {
		t.Fatalf("rotated setup token did not complete setup: %v", err)
	}
	if _, err := os.Stat(tokenPath); !os.IsNotExist(err) {
		t.Fatalf("consumed setup token receipt was not removed: %v", err)
	}
}

func seedInventoryDevice(t *testing.T, server *Server) {
	t.Helper()
	now := server.now()
	lease := deviceinventory.DHCP4Lease{Address: netip.MustParseAddr("10.77.0.20"), HardwareAddr: "52:54:00:00:00:20", Hostname: "camera", ValidLifetime: time.Hour, ExpiresAt: now.Add(time.Hour)}
	if _, err := server.inventory.ReconcileDHCP4([]deviceinventory.DHCP4Lease{lease}); err != nil {
		t.Fatal(err)
	}
}

func firstDeviceID(t *testing.T, server *Server) string {
	t.Helper()
	snapshot, err := server.inventory.Snapshot()
	if err != nil || len(snapshot.Devices) == 0 {
		t.Fatalf("inventory has no devices: %v", err)
	}
	return snapshot.Devices[0].ID
}

// Every upgrade restarts control-api; the administrator stayed signed in only
// until then and had to sign in again after each release.
func TestSessionsSurviveARestartWithoutStoringTokens(t *testing.T) {
	directory := t.TempDir()
	now := time.Date(2026, 10, 2, 4, 0, 0, 0, time.UTC)
	first := &Server{store: NewStore(directory, ""), sessions: make(map[string]sessionRecord), clock: func() time.Time { return now }}
	first.sessionsPath = first.store.SessionsPath()
	token, _, err := first.newVerifiedSession("admin")
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := first.newVerifiedSession("admin")
	if err != nil {
		t.Fatal(err)
	}
	first.revokeSession(other)
	raw, err := os.ReadFile(first.sessionsPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), token) || strings.Contains(string(raw), other) {
		t.Fatal("a session token was written to disk")
	}
	if info, err := os.Stat(first.sessionsPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("sessions file mode = %v err=%v", info.Mode().Perm(), err)
	}
	restarted := &Server{store: NewStore(directory, ""), sessions: make(map[string]sessionRecord), clock: func() time.Time { return now.Add(10 * time.Minute) }}
	restarted.sessionsPath = restarted.store.SessionsPath()
	restarted.loadSessions()
	if session, ok := restarted.authenticateSession(token); !ok || session.Username != "admin" {
		t.Fatal("the session did not survive the restart")
	}
	if _, ok := restarted.authenticateSession(other); ok {
		t.Fatal("a revoked session came back after the restart")
	}
	expired := &Server{store: NewStore(directory, ""), sessions: make(map[string]sessionRecord), clock: func() time.Time { return now.Add(13 * time.Hour) }}
	expired.sessionsPath = expired.store.SessionsPath()
	expired.loadSessions()
	if _, ok := expired.authenticateSession(token); ok {
		t.Fatal("an expired session was restored")
	}
	restarted.revokeAllSessions()
	again := &Server{store: NewStore(directory, ""), sessions: make(map[string]sessionRecord), clock: func() time.Time { return now.Add(11 * time.Minute) }}
	again.sessionsPath = again.store.SessionsPath()
	again.loadSessions()
	if _, ok := again.authenticateSession(token); ok {
		t.Fatal("signing everyone out did not survive the restart")
	}
}
