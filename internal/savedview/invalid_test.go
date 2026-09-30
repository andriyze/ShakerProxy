package savedview

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClientReportsBackendRejectionsAsInvalidWithReason(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"code":"invalid_saved_view","message":"saved view canonical query is invalid"}}`))
	}))
	defer backend.Close()
	client, err := NewClient(backend.URL, []byte(strings.Repeat("s", 32)), backend.Client())
	if err != nil {
		t.Fatal(err)
	}
	configuration, err := Normalize(Configuration{Scope: ScopePersonal, Name: "Camera", Page: "live-traffic", CanonicalQuery: "source:zeek", TimeBehavior: TimeBehavior{Mode: "query"}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Create(t.Context(), "admin", configuration)
	var invalid *InvalidError
	if !errors.Is(err, ErrInvalid) || !errors.As(err, &invalid) || invalid.Message != "saved view canonical query is invalid" {
		t.Fatalf("backend 400 was not reported as invalid: %v", err)
	}
}
