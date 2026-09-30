package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/trafficpolicy"
)

const (
	// Sessions slide: every authenticated request extends the idle deadline,
	// bounded by an absolute lifetime measured from sign-in.
	sessionIdleTimeout      = time.Hour
	sessionAbsoluteLifetime = 12 * time.Hour
	// After a successful password check the same session may perform
	// recent-confirmation actions without re-entering the password.
	recentAuthenticationWindow = 10 * time.Minute
	maxSessions                = 256

	authFailureWindow = 5 * time.Minute
	authFailureLimit  = 10

	authBucketPassword = "password"
	authBucketRecovery = "recovery"
)

type sessionTokenContextKey struct{}

type sessionRecord struct {
	Username           string
	CreatedAt          time.Time
	LastUsedAt         time.Time
	ExpiresAt          time.Time
	AbsoluteExpiresAt  time.Time
	PasswordVerifiedAt time.Time
}

type authFailureCounter struct {
	StartedAt time.Time
	Failures  int
}

// passwordPolicy says whether an action accepts a recent password
// confirmation from the same session or needs the password every time.
type passwordPolicy int

const (
	passwordRecent passwordPolicy = iota
	passwordAlways
)

func (s *Server) now() time.Time {
	if s.clock != nil {
		return s.clock().UTC()
	}
	return time.Now().UTC()
}

// newSession creates a session without a recent password confirmation. It is
// used by tests and internal callers; sign-in paths use newVerifiedSession.
func (s *Server) newSession(username string) (string, error) {
	token, _, err := s.createSession(username, false)
	return token, err
}

func (s *Server) newVerifiedSession(username string) (string, sessionRecord, error) {
	return s.createSession(username, true)
}

func (s *Server) createSession(username string, passwordVerified bool) (string, sessionRecord, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", sessionRecord{}, err
	}
	token := base64.RawURLEncoding.EncodeToString(b)
	now := s.now()
	record := sessionRecord{Username: username, CreatedAt: now, LastUsedAt: now, AbsoluteExpiresAt: now.Add(sessionAbsoluteLifetime)}
	record.ExpiresAt = earliest(now.Add(sessionIdleTimeout), record.AbsoluteExpiresAt)
	if passwordVerified {
		record.PasswordVerifiedAt = now
	}
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	if len(s.sessions) >= maxSessions {
		s.evictSessionsLocked(now)
	}
	s.sessions[token] = record
	return token, record, nil
}

func (s *Server) evictSessionsLocked(now time.Time) {
	for token, record := range s.sessions {
		if !now.Before(record.ExpiresAt) {
			delete(s.sessions, token)
		}
	}
	for len(s.sessions) >= maxSessions {
		oldestToken, oldest := "", time.Time{}
		for token, record := range s.sessions {
			if oldestToken == "" || record.LastUsedAt.Before(oldest) {
				oldestToken, oldest = token, record.LastUsedAt
			}
		}
		delete(s.sessions, oldestToken)
	}
}

// authenticateSession validates a session token and slides its expiry.
func (s *Server) authenticateSession(token string) (sessionRecord, bool) {
	now := s.now()
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	session, ok := s.sessions[token]
	if !ok {
		return sessionRecord{}, false
	}
	if !now.Before(session.ExpiresAt) {
		delete(s.sessions, token)
		return sessionRecord{}, false
	}
	session.LastUsedAt = now
	session.ExpiresAt = earliest(now.Add(sessionIdleTimeout), session.AbsoluteExpiresAt)
	s.sessions[token] = session
	return session, true
}

func (s *Server) revokeSession(token string) bool {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	_, existed := s.sessions[token]
	delete(s.sessions, token)
	return existed
}

func (s *Server) revokeAllSessions() int {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	count := len(s.sessions)
	s.sessions = make(map[string]sessionRecord)
	return count
}

func (s *Server) markPasswordVerified(token string) {
	now := s.now()
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	if session, ok := s.sessions[token]; ok {
		session.PasswordVerifiedAt = now
		s.sessions[token] = session
	}
}

func (s *Server) recentlyAuthenticated(token string) bool {
	now := s.now()
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	session, ok := s.sessions[token]
	return ok && !session.PasswordVerifiedAt.IsZero() && now.Sub(session.PasswordVerifiedAt) < recentAuthenticationWindow && now.Before(session.ExpiresAt)
}

func withSession(ctx context.Context, token string, session sessionRecord) context.Context {
	ctx = context.WithValue(ctx, sessionContextKey{}, session.Username)
	return context.WithValue(ctx, sessionTokenContextKey{}, token)
}

func sessionToken(ctx context.Context) string {
	token, _ := ctx.Value(sessionTokenContextKey{}).(string)
	return token
}

func setSessionExpiryHeader(w http.ResponseWriter, session sessionRecord) {
	w.Header().Set("X-ShakerProxy-Session-Expires-At", session.ExpiresAt.UTC().Format(time.RFC3339))
}

func sessionResponse(token string, session sessionRecord, now time.Time) map[string]any {
	return map[string]any{
		"session_token":        token,
		"expires_at":           session.ExpiresAt.UTC().Format(time.RFC3339),
		"expires_in_seconds":   int64(session.ExpiresAt.Sub(now).Round(time.Second) / time.Second),
		"absolute_expires_at":  session.AbsoluteExpiresAt.UTC().Format(time.RFC3339),
		"idle_timeout_seconds": int64(sessionIdleTimeout / time.Second),
	}
}

// confirmAdministrator enforces the password policy of a sensitive action and
// writes the error response itself. A successful password check starts (or
// renews) the session's recent-confirmation window.
func (s *Server) confirmAdministrator(w http.ResponseWriter, r *http.Request, password string, policy passwordPolicy) bool {
	username, token := sessionUsername(r.Context()), sessionToken(r.Context())
	if username == "" || token == "" {
		writeError(w, http.StatusUnauthorized, "reauthentication_failed", "Only a signed-in administrator session can confirm this action.")
		return false
	}
	if password == "" {
		if policy == passwordRecent && s.recentlyAuthenticated(token) {
			return true
		}
		if policy == passwordAlways {
			writeError(w, http.StatusUnauthorized, "password_required", "This action always requires the administrator password; include \"password\" in the request.")
			return false
		}
		writeError(w, http.StatusUnauthorized, "reauthentication_required", "Confirm the administrator password to continue; include \"password\" in the request (it is remembered for 10 minutes).")
		return false
	}
	if !s.allowAuthAttempt(w, authBucketPassword) {
		return false
	}
	ok, err := s.store.Authenticate(username, password)
	if err != nil || !ok {
		s.recordAuthFailure(authBucketPassword)
		writeError(w, http.StatusUnauthorized, "reauthentication_failed", "The administrator password is incorrect.")
		return false
	}
	s.markPasswordVerified(token)
	return true
}

func (s *Server) allowAuthAttempt(w http.ResponseWriter, bucket string) bool {
	now := s.now()
	s.authFailuresMu.Lock()
	counter := s.authFailures[bucket]
	s.authFailuresMu.Unlock()
	if counter.Failures < authFailureLimit || now.Sub(counter.StartedAt) >= authFailureWindow {
		return true
	}
	retry := counter.StartedAt.Add(authFailureWindow).Sub(now).Round(time.Second)
	if retry < time.Second {
		retry = time.Second
	}
	seconds := int(retry / time.Second)
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
	writeError(w, http.StatusTooManyRequests, "too_many_attempts", "Too many failed attempts; wait "+strconv.Itoa(seconds)+" seconds and try again.")
	return false
}

func (s *Server) recordAuthFailure(bucket string) {
	now := s.now()
	s.authFailuresMu.Lock()
	defer s.authFailuresMu.Unlock()
	counter := s.authFailures[bucket]
	if counter.StartedAt.IsZero() || now.Sub(counter.StartedAt) >= authFailureWindow {
		counter = authFailureCounter{StartedAt: now}
	}
	counter.Failures++
	s.authFailures[bucket] = counter
}

func (s *Server) resetAuthFailures(bucket string) {
	s.authFailuresMu.Lock()
	defer s.authFailuresMu.Unlock()
	delete(s.authFailures, bucket)
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var request loginRequest
	if err := decodeJSON(r, &request); err != nil {
		writeDecodeError(w, err, "login")
		return
	}
	if !s.allowAuthAttempt(w, authBucketPassword) {
		return
	}
	ok, err := s.store.Authenticate(request.Username, request.Password)
	if err != nil || !ok {
		s.recordAuthFailure(authBucketPassword)
		s.logger.Warn("login failed", "username", request.Username)
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "The username or password is incorrect.")
		return
	}
	s.resetAuthFailures(authBucketPassword)
	token, session, err := s.newVerifiedSession(request.Username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "session_failed", "Could not create a session; try again.")
		return
	}
	writeJSON(w, http.StatusOK, sessionResponse(token, session, s.now()))
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	token, ok := bearerToken(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication_required", "Send the session token as Authorization: Bearer <session_token>.")
		return
	}
	loggedOut := s.revokeSession(token)
	if loggedOut {
		s.logger.Info("session signed out")
	}
	writeJSON(w, http.StatusOK, map[string]any{"schema": 1, "logged_out": loggedOut})
}

type recoverRequest struct {
	Username     string `json:"username"`
	RecoveryCode string `json:"recovery_code"`
	NewPassword  string `json:"new_password"`
}

func (s *Server) recoverAdministrator(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var request recoverRequest
	if err := decodeJSON(r, &request); err != nil {
		writeDecodeError(w, err, "account recovery")
		return
	}
	if !s.allowAuthAttempt(w, authBucketRecovery) {
		return
	}
	remaining, err := s.store.RecoverAdmin(strings.TrimSpace(request.Username), request.RecoveryCode, request.NewPassword)
	switch {
	case err == nil:
	case errors.Is(err, errSetupRequired):
		writeError(w, http.StatusConflict, "setup_required", "No administrator exists yet; complete setup with the one-time setup token.")
		return
	case errors.Is(err, errWeakPassword):
		writeError(w, http.StatusBadRequest, "weak_password", strings.TrimPrefix(err.Error(), errWeakPassword.Error()+": ")+".")
		return
	case errors.Is(err, errRecoveryRejected):
		s.recordAuthFailure(authBucketRecovery)
		s.logger.Warn("account recovery rejected", "username", request.Username)
		writeError(w, http.StatusUnauthorized, "invalid_recovery_code", "The username or recovery code is not valid. Each recovery code works once; use an unused code from the list saved at setup, or ask the appliance owner to run `sudo shakerproxy admin reset`.")
		return
	default:
		s.logger.Error("account recovery failed", "error", err)
		writeError(w, http.StatusServiceUnavailable, "recovery_unavailable", "Account recovery could not be saved; check appliance storage and try again.")
		return
	}
	s.resetAuthFailures(authBucketRecovery)
	s.resetAuthFailures(authBucketPassword)
	revoked := s.revokeAllSessions()
	token, session, err := s.newVerifiedSession(strings.TrimSpace(request.Username))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "session_failed", "The password was changed but a session could not be created; sign in with the new password.")
		return
	}
	s.logger.Info("administrator password recovered with a recovery code", "username", request.Username, "remaining_recovery_codes", remaining, "revoked_sessions", revoked)
	response := sessionResponse(token, session, s.now())
	response["schema"] = 1
	response["remaining_recovery_codes"] = remaining
	writeJSON(w, http.StatusOK, response)
}

func earliest(first, second time.Time) time.Time {
	if second.Before(first) {
		return second
	}
	return first
}

// trafficPolicyPasswordPolicy requires the password every time a policy turns
// on HTTPS decryption for every lab client (global TLS interception). Other
// traffic-policy changes accept a recent confirmation. If the current policy
// cannot be read the check fails closed to "password every time".
func (s *Server) trafficPolicyPasswordPolicy(r *http.Request, requested trafficpolicy.Policy) passwordPolicy {
	if !requested.TLS.Enabled || len(requested.TLS.SelectedDeviceIDs) > 0 {
		return passwordRecent
	}
	var current trafficpolicy.Document
	if err := s.gateway.Call(r.Context(), "GetTrafficPolicy", gatewayprotocol.EmptyParams{}, &current); err != nil {
		return passwordAlways
	}
	if current.Policy.TLS.Enabled && len(current.Policy.TLS.SelectedDeviceIDs) == 0 {
		return passwordRecent
	}
	return passwordAlways
}

// httpContentPasswordPolicy requires the password to start retaining
// decrypted HTTP bodies; turning retention off accepts a recent confirmation.
func httpContentPasswordPolicy(enable bool) passwordPolicy {
	if enable {
		return passwordAlways
	}
	return passwordRecent
}
