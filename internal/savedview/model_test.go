package savedview

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestNormalizeCanonicalizesAndBoundsSavedView(t *testing.T) {
	configuration, err := Normalize(Configuration{
		Scope: ScopePersonal, Name: "  My traffic  ", Description: "  useful  ", Page: "live-traffic",
		CanonicalQuery: "source:zeek protocol:tcp", TimeBehavior: TimeBehavior{Mode: "query"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if configuration.Name != "My traffic" || configuration.Description != "useful" || configuration.CanonicalQuery != "source:ZEEK AND protocol:tcp" || configuration.Density != "comfortable" || len(configuration.Sort) != 1 || len(configuration.Columns) != 4 {
		t.Fatalf("saved view was not normalized: %#v", configuration)
	}
	encoded, err := json.Marshal(configuration)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "0001-01-01") || strings.Contains(string(encoded), `"start"`) || strings.Contains(string(encoded), `"end"`) {
		t.Fatalf("inactive time bounds leaked into saved view JSON: %s", encoded)
	}
	invalid := configuration
	invalid.Columns = []string{"payload"}
	if _, err := Normalize(invalid); err == nil {
		t.Fatal("sensitive/unknown saved view column was accepted")
	}
	invalid = configuration
	start, end := time.Now(), time.Now().Add(31*24*time.Hour)
	invalid.TimeBehavior = TimeBehavior{Mode: "absolute", Start: &start, End: &end}
	if _, err := Normalize(invalid); err == nil {
		t.Fatal("unbounded absolute saved view window was accepted")
	}
}

func TestSavedViewIdentifiersAndActorsAreStrict(t *testing.T) {
	if !ValidID("view-0123456789abcdef0123456789abcdef") || ValidID("view-../../admin") {
		t.Fatal("saved view ID validation is unsafe")
	}
	if !ValidActor("admin@example.test") || ValidActor("admin\nforged") {
		t.Fatal("saved view actor validation is unsafe")
	}
}
