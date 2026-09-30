package server

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestOpenAPIDescribesLabControlRoutes extends the core route check to the
// routes registered from lab_controls.go.
func TestOpenAPIDescribesLabControlRoutes(t *testing.T) {
	source, err := os.ReadFile("lab_controls.go")
	if err != nil {
		t.Fatal(err)
	}
	routePattern := regexp.MustCompile(`mux\.Handle(?:Func)?\("(GET|POST|PUT|PATCH|DELETE) /api/v1([^"]*)"`)
	routes := map[string]bool{}
	for _, match := range routePattern.FindAllStringSubmatch(string(source), -1) {
		routes[strings.ToLower(match[1])+" "+match[2]] = true
	}
	if len(routes) != 5 {
		t.Fatalf("expected 5 lab control routes, found %d", len(routes))
	}
	document, err := os.Open(filepath.Join("..", "..", "..", "..", "schemas", "api", "openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	defer document.Close()
	described := map[string]bool{}
	current := ""
	pathLine := regexp.MustCompile(`^  (/[^:]*):\s*$`)
	methodLine := regexp.MustCompile(`^    (get|post|put|patch|delete):`)
	scanner := bufio.NewScanner(document)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		if match := pathLine.FindStringSubmatch(line); match != nil {
			current = match[1]
			continue
		}
		if strings.HasPrefix(line, "components:") {
			break
		}
		if match := methodLine.FindStringSubmatch(line); match != nil && current != "" {
			described[match[1]+" "+current] = true
		}
	}
	missing := []string{}
	for route := range routes {
		if !described[route] {
			missing = append(missing, route)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("schemas/api/openapi.yaml does not describe: %s", strings.Join(missing, ", "))
	}
}
