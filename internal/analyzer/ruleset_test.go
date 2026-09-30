package analyzer

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRepositorySuricataRulesetMatchesProvenanceManifest(t *testing.T) {
	rules, err := filepath.Abs(filepath.Join("..", "..", "apps", "analyzer-worker", "suricata.rules"))
	if err != nil {
		t.Fatal(err)
	}
	manifestPath, err := filepath.Abs(filepath.Join("..", "..", "apps", "analyzer-worker", "suricata-ruleset.json"))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := LoadRulesetManifest(rules, manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.RulesetID != "shakerproxy-cleartext-policy" || manifest.Version != "2026.09.29.1" || manifest.EngineVersion != "8.0.6" || manifest.RuleCount != 10 {
		t.Fatalf("unexpected repository ruleset provenance: %#v", manifest)
	}
}

func TestRulesetManifestRejectsDriftDuplicateSIDsAndSymlinks(t *testing.T) {
	directory := t.TempDir()
	rulesPath := filepath.Join(directory, "rules.rules")
	manifestPath := filepath.Join(directory, "manifest.json")
	rules := []byte("alert tcp any any -> any 23 (msg:\"one\"; sid:9900001; rev:1;)\nalert tcp any any -> any 21 (msg:\"two\"; sid:9900002; rev:1;)\n")
	manifest := testRulesetManifest(rules, 2, 9900001, 9900002)
	writeRulesetFixture(t, rulesPath, manifestPath, rules, manifest)
	if _, err := LoadRulesetManifest(rulesPath, manifestPath); err != nil {
		t.Fatalf("valid ruleset was rejected: %v", err)
	}
	if err := os.WriteFile(rulesPath, append(append([]byte(nil), rules...), '#'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRulesetManifest(rulesPath, manifestPath); err == nil || !strings.Contains(err.Error(), "hash") {
		t.Fatalf("ruleset drift was accepted: %v", err)
	}
	duplicate := []byte("alert tcp any any -> any 23 (msg:\"one\"; sid:9900001; rev:1;)\nalert tcp any any -> any 21 (msg:\"two\"; sid:9900001; rev:1;)\n")
	manifest = testRulesetManifest(duplicate, 2, 9900001, 9900001)
	writeRulesetFixture(t, rulesPath, manifestPath, duplicate, manifest)
	if _, err := LoadRulesetManifest(rulesPath, manifestPath); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate rule SID was accepted: %v", err)
	}
	target := filepath.Join(directory, "target.rules")
	if err := os.WriteFile(target, rules, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(rulesPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, rulesPath); err != nil {
		t.Fatal(err)
	}
	manifest = testRulesetManifest(rules, 2, 9900001, 9900002)
	writeRulesetManifestFixture(t, manifestPath, manifest)
	if _, err := LoadRulesetManifest(rulesPath, manifestPath); err == nil {
		t.Fatal("symlinked ruleset was accepted")
	}
}

func TestAnalyzerStatusBindsOptionalSuricataRulesetIdentity(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	status := Status{Schema: SchemaVersion, Engine: EngineSuricata, SourceVersion: "8.0.6", RulesetID: "shakerproxy-cleartext-policy", RulesetVersion: "2026.09.01.1", RulesetSHA256: strings.Repeat("a", 64), StartedAt: now, UpdatedAt: now}
	if !validStatus(status) {
		t.Fatal("valid Suricata ruleset status was rejected")
	}
	status.Engine = EngineZeek
	if validStatus(status) {
		t.Fatal("Zeek status accepted Suricata ruleset identity")
	}
	status.Engine = EngineSuricata
	status.RulesetSHA256 = "drift"
	if validStatus(status) {
		t.Fatal("invalid Suricata ruleset digest was accepted")
	}
}

func testRulesetManifest(rules []byte, count int, minimum, maximum uint64) RulesetManifest {
	digest := sha256.Sum256(rules)
	return RulesetManifest{Schema: SchemaVersion, RulesetID: "shakerproxy-test-policy", Version: "2026.09.01.1", Source: "test fixture", License: "Apache-2.0", Engine: EngineSuricata, EngineVersion: "8.0.6", SHA256: hex.EncodeToString(digest[:]), RuleCount: count, SIDMin: minimum, SIDMax: maximum, UpdatedAt: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)}
}

func writeRulesetFixture(t *testing.T, rulesPath, manifestPath string, rules []byte, manifest RulesetManifest) {
	t.Helper()
	if err := os.WriteFile(rulesPath, rules, 0o600); err != nil {
		t.Fatal(err)
	}
	writeRulesetManifestFixture(t, manifestPath, manifest)
}

func writeRulesetManifestFixture(t *testing.T, path string, manifest RulesetManifest) {
	t.Helper()
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(encoded, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}
