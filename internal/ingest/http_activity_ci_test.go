package ingest

import (
	"os"
	"strings"
	"testing"
)

func TestHTTPActivityPostgresProofIsConfiguredInCI(t *testing.T) {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("CI")), "true") && strings.TrimSpace(os.Getenv("SHAKERPROXY_TEST_DATABASE_URL")) == "" {
		t.Fatal("CI must configure SHAKERPROXY_TEST_DATABASE_URL so the HTTP activity PostgreSQL proof cannot silently skip")
	}
}
