package applifecycle

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type runnerCall struct {
	executable string
	arguments  []string
}

type recordingRunner struct {
	calls []runnerCall
}

type fixtureTrust struct {
	keySHA256 string
}

func (runner *recordingRunner) Run(_ context.Context, executable string, arguments ...string) ([]byte, error) {
	runner.calls = append(runner.calls, runnerCall{executable: executable, arguments: append([]string(nil), arguments...)})
	return []byte("ok\n"), nil
}

func TestControllerStartsOnlyValidatedPinnedRelease(t *testing.T) {
	root, config, trust := releaseFixture(t)
	runner := &recordingRunner{}
	controller := Controller{InstallRoot: root, ConfigRoot: config, DockerPath: "/fixed/docker", TrustedPublicKeySHA256: trust.keySHA256, Runner: runner}
	if _, err := controller.Execute(context.Background(), "start"); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 2 || runner.calls[0].executable != "/fixed/docker" || runner.calls[1].executable != "/fixed/docker" {
		t.Fatalf("unexpected lifecycle command calls: %#v", runner.calls)
	}
	first := strings.Join(runner.calls[0].arguments, " ")
	second := strings.Join(runner.calls[1].arguments, " ")
	if !strings.Contains(first, "--profile core --profile observe config --quiet") || !strings.Contains(second, "up --detach --remove-orphans --pull never --wait --wait-timeout 120") {
		t.Fatalf("unexpected fixed Compose arguments: first=%q second=%q", first, second)
	}
	for _, call := range runner.calls {
		if strings.Contains(strings.Join(call.arguments, " "), "sh -c") {
			t.Fatal("lifecycle command crossed a shell boundary")
		}
		if !strings.Contains(strings.Join(call.arguments, " "), "--project-directory "+filepath.Join(root, "releases", "1.2.3", "deploy")+" ") {
			t.Fatalf("Compose must resolve relative paths from the release's deploy directory: %q", call.arguments)
		}
	}
}

// The release bundle ships deploy/compose.yaml next to deploy/caddy, and the
// controller runs Compose from deploy/, so every relative bind-mount source
// must exist under deploy/ (Docker would otherwise create an empty directory).
func TestComposeRelativeBindSourcesExistUnderDeploy(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "deploy", "compose.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, line := range strings.Split(string(data), "\n") {
		entry := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "- "))
		if !strings.HasPrefix(entry, "./") && !strings.HasPrefix(entry, "../") {
			continue
		}
		source := strings.SplitN(entry, ":", 2)[0]
		found++
		if _, err := os.Stat(filepath.Join("..", "..", "deploy", source)); err != nil {
			t.Errorf("compose.yaml bind source %s does not exist under deploy/: %v", source, err)
		}
	}
	if found == 0 {
		t.Fatal("expected at least one relative bind source (the edge Caddyfile)")
	}
}

func TestControllerRejectsEscapingReleaseSymlink(t *testing.T) {
	root, config, trust := releaseFixture(t)
	if err := os.Remove(filepath.Join(root, "current")); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "current")); err != nil {
		t.Fatal(err)
	}
	runner := &recordingRunner{}
	_, err := (Controller{InstallRoot: root, ConfigRoot: config, TrustedPublicKeySHA256: trust.keySHA256, Runner: runner}).Execute(context.Background(), "validate")
	if err == nil || !strings.Contains(err.Error(), "escapes") || len(runner.calls) != 0 {
		t.Fatalf("escaping release reached Docker: err=%v calls=%#v", err, runner.calls)
	}
}

func TestControllerRejectsUnpinnedOrUnknownReleaseData(t *testing.T) {
	root, config, trust := releaseFixture(t)
	releaseDirectory := filepath.Join(root, "releases", "1.2.3")
	if err := os.WriteFile(filepath.Join(releaseDirectory, "release.env"), []byte("SHAKERPROXY_CONTROL_API_IMAGE=registry.invalid/control-api:latest\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (Controller{InstallRoot: root, ConfigRoot: config, TrustedPublicKeySHA256: trust.keySHA256, Runner: &recordingRunner{}}).Execute(context.Background(), "validate"); err == nil || !strings.Contains(err.Error(), "unpinned") {
		t.Fatalf("mutable image environment was accepted: %v", err)
	}
	release := validRelease()
	encoded, err := json.Marshal(release)
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded[:len(encoded)-1], []byte(`,"unexpected":true}`)...)
	if err := os.WriteFile(filepath.Join(releaseDirectory, "release.json"), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (Controller{InstallRoot: root, ConfigRoot: config, TrustedPublicKeySHA256: trust.keySHA256, Runner: &recordingRunner{}}).Execute(context.Background(), "validate"); err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("unknown release metadata was accepted: %v", err)
	}
}

func TestControllerRejectsTamperedSignedReleaseFiles(t *testing.T) {
	root, config, trust := releaseFixture(t)
	releaseDirectory := filepath.Join(root, "releases", "1.2.3")
	if err := os.WriteFile(filepath.Join(releaseDirectory, "deploy", "compose.yaml"), []byte("tampered\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	controller := Controller{InstallRoot: root, ConfigRoot: config, TrustedPublicKeySHA256: trust.keySHA256, Runner: &recordingRunner{}}
	if _, err := controller.Execute(context.Background(), "validate"); err == nil || !strings.Contains(err.Error(), "integrity") {
		t.Fatalf("tampered release file was accepted: %v", err)
	}
}

func releaseFixture(t *testing.T) (string, string, fixtureTrust) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "opt", "shakerproxy")
	config := filepath.Join(t.TempDir(), "etc", "shakerproxy")
	releaseDirectory := filepath.Join(root, "releases", "1.2.3")
	if err := os.MkdirAll(filepath.Join(releaseDirectory, "deploy"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(config, 0o750); err != nil {
		t.Fatal(err)
	}
	imageValues := map[string]string{
		"SHAKERPROXY_POSTGRES_IMAGE":    "registry.invalid/postgres@sha256:" + strings.Repeat("1", 64),
		"SHAKERPROXY_CONTROL_API_IMAGE": "registry.invalid/control-api@sha256:" + strings.Repeat("2", 64),
		"SHAKERPROXY_WEB_UI_IMAGE":      "registry.invalid/web-ui@sha256:" + strings.Repeat("3", 64),
		"SHAKERPROXY_EDGE_IMAGE":        "registry.invalid/edge@sha256:" + strings.Repeat("4", 64),
		"SHAKERPROXY_INGESTD_IMAGE":     "registry.invalid/ingestd@sha256:" + strings.Repeat("5", 64),
		"SHAKERPROXY_ZEEK_IMAGE":        "registry.invalid/zeek@sha256:" + strings.Repeat("6", 64),
		"SHAKERPROXY_SURICATA_IMAGE":    "registry.invalid/suricata@sha256:" + strings.Repeat("7", 64),
		"SHAKERPROXY_MITMPROXY_IMAGE":   "registry.invalid/mitmproxy@sha256:" + strings.Repeat("8", 64),
	}
	manifestObject := map[string]any{
		"schema": 1, "version": "1.2.3", "channel": "stable", "release_public_key_sha256": "placeholder",
		"images": imageValues, "compose_bundle": map[string]string{"sha256": strings.Repeat("b", 64)}, "config_schema": 1, "database_schema": 10,
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDigest := sha256.Sum256(publicDER)
	trust := fixtureTrust{keySHA256: hex.EncodeToString(keyDigest[:])}
	manifestObject["release_public_key_sha256"] = trust.keySHA256
	manifest, err := json.Marshal(manifestObject)
	if err != nil {
		t.Fatal(err)
	}
	manifestDigest := sha256.Sum256(manifest)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, manifestDigest[:])
	if err != nil {
		t.Fatal(err)
	}
	release := validRelease()
	release.ManifestSHA256 = hex.EncodeToString(manifestDigest[:])
	encoded, err := json.Marshal(release)
	if err != nil {
		t.Fatal(err)
	}
	compose := "name: shakerproxy\nservices: {}\n"
	composeDigest := sha256.Sum256([]byte(compose))
	files := map[string]string{
		filepath.Join(releaseDirectory, "release.json"):           string(encoded),
		filepath.Join(releaseDirectory, "manifest.json"):          string(manifest),
		filepath.Join(releaseDirectory, "release-public.pem"):     string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})),
		filepath.Join(releaseDirectory, "bundle-files.sha256"):    hex.EncodeToString(composeDigest[:]) + "  deploy/compose.yaml\n",
		filepath.Join(releaseDirectory, "deploy", "compose.yaml"): compose,
		filepath.Join(config, "compose.env"):                      "SHAKERPROXY_CAPTURE_GID=2000\nSHAKERPROXY_EDGE_GID=2001\nSHAKERPROXY_CLOUD_GID=2002\n",
		filepath.Join(releaseDirectory, "release.env"): strings.Join([]string{
			"SHAKERPROXY_CONTROL_API_IMAGE=" + imageValues["SHAKERPROXY_CONTROL_API_IMAGE"],
			"SHAKERPROXY_EDGE_IMAGE=" + imageValues["SHAKERPROXY_EDGE_IMAGE"],
			"SHAKERPROXY_INGESTD_IMAGE=" + imageValues["SHAKERPROXY_INGESTD_IMAGE"],
			"SHAKERPROXY_MITMPROXY_IMAGE=" + imageValues["SHAKERPROXY_MITMPROXY_IMAGE"],
			"SHAKERPROXY_POSTGRES_IMAGE=" + imageValues["SHAKERPROXY_POSTGRES_IMAGE"],
			"SHAKERPROXY_SURICATA_IMAGE=" + imageValues["SHAKERPROXY_SURICATA_IMAGE"],
			"SHAKERPROXY_WEB_UI_IMAGE=" + imageValues["SHAKERPROXY_WEB_UI_IMAGE"],
			"SHAKERPROXY_ZEEK_IMAGE=" + imageValues["SHAKERPROXY_ZEEK_IMAGE"],
		}, "\n") + "\n",
	}
	for path, contents := range files {
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(releaseDirectory, "manifest.json.sig"), signature, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(releaseDirectory, filepath.Join(root, "current")); err != nil {
		t.Fatal(err)
	}
	return root, config, trust
}

func validRelease() Release {
	return Release{Schema: 1, Version: "1.2.3", Channel: "stable", Profiles: []string{"core", "observe"}, ManifestSHA256: strings.Repeat("a", 64), ComposeBundleSHA256: strings.Repeat("b", 64), ConfigSchema: 1, DatabaseSchema: 10, InstalledAt: time.Date(2026, 9, 1, 23, 0, 0, 0, time.UTC)}
}

func TestExecRunnerKeepsDockerConfigOutOfRootHome(t *testing.T) {
	if _, err := os.Stat("/usr/bin/env"); err != nil {
		t.Skip("/usr/bin/env is unavailable")
	}
	output, err := ExecRunner{}.Run(context.Background(), "/usr/bin/env")
	if err != nil {
		t.Fatal(err)
	}
	environment := string(output)
	if !strings.Contains(environment, "DOCKER_CONFIG=/etc/shakerproxy/docker\n") || strings.Contains(environment, "HOME=") {
		t.Fatalf("lifecycle commands must use DOCKER_CONFIG outside /root and no HOME, got:\n%s", environment)
	}
}
