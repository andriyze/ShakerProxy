package recoveryobjectives

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestRepositoryRecoveryObjectivesAreHonestAndBounded(t *testing.T) {
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate repository")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(current), "..", ".."))
	registry, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	statuses := map[string]int{}
	for _, objective := range registry.Objectives {
		statuses[objective.Status]++
	}
	if registry.Schema != 1 || len(registry.Objectives) != 4 || statuses["verified"] != 1 || statuses["target"] != 1 || statuses["not-offered"] != 2 {
		t.Fatalf("recovery claims drifted: %#v", registry)
	}
}

func TestRuntimeRegistryLoadsPackagedSchemaWithoutSourceEvidence(t *testing.T) {
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate repository")
	}
	sourceRoot := filepath.Clean(filepath.Join(filepath.Dir(current), "..", ".."))
	runtimeRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(runtimeRoot, "schemas"), 0o755); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(filepath.Join(sourceRoot, "schemas", "recovery-objectives.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runtimeRoot, "schemas", "recovery-objectives.yaml"), contents, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRuntime(runtimeRoot); err != nil {
		t.Fatalf("runtime recovery registry rejected: %v", err)
	}
}
