package server

import (
	"net/http"
	"path/filepath"
	"sync"

	"shakerproxy.dev/shakerproxy/internal/apitoken"
	"shakerproxy.dev/shakerproxy/internal/testsession"
)

// registerDeviceIntelRoutes adds device references, reports, comparisons,
// CA trust, and test sessions. Every route that takes a device accepts a
// friendly name, IP address, MAC address, or device ID.
func (s *Server) registerDeviceIntelRoutes(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/devices/resolve", s.requireAuthOrScope(apitoken.ScopeDevicesRead, http.HandlerFunc(s.resolveDevice)))
	mux.Handle("GET /api/v1/devices/{deviceID}/report", s.requireAuthOrScope(apitoken.ScopeDevicesRead, s.requireAlsoScope(apitoken.ScopeTrafficRead, http.HandlerFunc(s.getDeviceReport))))
	mux.Handle("GET /api/v1/devices/{deviceID}/compare", s.requireAuthOrScope(apitoken.ScopeDevicesRead, s.requireAlsoScope(apitoken.ScopeTrafficRead, http.HandlerFunc(s.compareDeviceRuns))))
	mux.Handle("PUT /api/v1/devices/{deviceID}/ca-trust", s.requireLabWrite(http.HandlerFunc(s.setDeviceCATrust)))
	mux.Handle("GET /api/v1/test-sessions", s.requireAuthOrScope(apitoken.ScopeDevicesRead, http.HandlerFunc(s.listTestSessions)))
	mux.Handle("POST /api/v1/test-sessions", s.requireLabWrite(http.HandlerFunc(s.startTestSession)))
	mux.Handle("GET /api/v1/test-sessions/{sessionID}", s.requireAuthOrScope(apitoken.ScopeDevicesRead, http.HandlerFunc(s.getTestSession)))
	mux.Handle("PATCH /api/v1/test-sessions/{sessionID}", s.requireLabWrite(http.HandlerFunc(s.updateTestSession)))
	mux.Handle("POST /api/v1/test-sessions/{sessionID}/stop", s.requireLabWrite(http.HandlerFunc(s.stopTestSession)))
	mux.Handle("DELETE /api/v1/test-sessions/{sessionID}", s.requireLabWrite(http.HandlerFunc(s.deleteTestSession)))
}

// requireLabWrite guards lab changes (test sessions, CA trust): an
// administrator session or an API token with lab:write. No password prompt.
func (s *Server) requireLabWrite(next http.Handler) http.Handler {
	return s.requireAuthOrScope(apitoken.ScopeLabWrite, next)
}

// requireAlsoScope adds a second scope requirement after requireAuthOrScope.
// Administrator sessions carry no principal and always pass.
func (s *Server) requireAlsoScope(required apitoken.Scope, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if principal, ok := r.Context().Value(apiPrincipalContextKey{}).(apitoken.Principal); ok {
			granted := false
			for _, scope := range principal.Scopes {
				if scope == required {
					granted = true
					break
				}
			}
			if !granted {
				writeError(w, http.StatusForbidden, "insufficient_scope", "This API token also needs the "+string(required)+" scope. Create a token with devices:read and traffic:read.")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

var (
	testSessionStoresMu sync.Mutex
	testSessionStores   = map[string]*testsession.Store{}
)

// testSessions returns the process-wide store for this server's data
// directory so concurrent handlers never race on the same file.
func (s *Server) testSessions() *testsession.Store {
	if s.store == nil || s.store.dataDir == "" {
		return nil
	}
	path, err := filepath.Abs(filepath.Join(s.store.dataDir, "test-sessions.json"))
	if err != nil {
		return nil
	}
	testSessionStoresMu.Lock()
	defer testSessionStoresMu.Unlock()
	store, ok := testSessionStores[path]
	if !ok {
		store = &testsession.Store{Path: path}
		testSessionStores[path] = store
	}
	return store
}
