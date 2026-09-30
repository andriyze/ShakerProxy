package capabilityregistry

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRepositoryRegistryIsValid(t *testing.T) {
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate registry test")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(current), "..", ".."))
	bundle, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Schema != 1 || len(bundle.Features) < 10 || len(bundle.Glossary) < 20 || len(bundle.SupportMatrix.Environments) < 3 {
		t.Fatalf("registry is unexpectedly incomplete: %#v", bundle)
	}
}

func TestRuntimeRegistryDoesNotRequireSourceEvidenceInImage(t *testing.T) {
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate repository")
	}
	sourceRoot := filepath.Clean(filepath.Join(filepath.Dir(current), "..", ".."))
	runtimeRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(runtimeRoot, "schemas"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"feature-flags.yaml", "glossary.yaml", "support-matrix.yaml"} {
		contents, err := os.ReadFile(filepath.Join(sourceRoot, "schemas", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(runtimeRoot, "schemas", name), contents, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := LoadRuntime(runtimeRoot); err != nil {
		t.Fatalf("immutable runtime registry rejected without source tree: %v", err)
	}
	if _, err := Load(runtimeRoot); err == nil {
		t.Fatal("repository validation accepted absent evidence")
	}
}

func TestLoadRejectsUnknownAndMissingEvidence(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "schemas"), 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"feature-flags.yaml":  `{"schema":1,"revision":"r1","status_vocabulary":["experimental"],"features":[{"id":"proof","name":"Proof","status":"experimental","badge":"EXPERIMENTAL","summary":"Bounded proof","owning_document":"docs/missing.md","evidence":["tests/missing.sh"],"promotion_gate":"Pass","enabled_by_default":false}]}`,
		"glossary.yaml":       `{"schema":1,"revision":"r1","terms":[{"id":"experimental","label":"Experimental","definition":"Incomplete evidence."}]}`,
		"support-matrix.yaml": `{"schema":1,"revision":"r1","certification_levels":["not-certified"],"environments":[]}`,
	}
	for name, contents := range files {
		if err := os.WriteFile(filepath.Join(root, "schemas", name), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Load(root); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("missing evidence was accepted: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "schemas", "glossary.yaml"), []byte(`{"schema":1,"revision":"r1","unknown":true,"terms":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(root); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown registry field was accepted: %v", err)
	}
}
