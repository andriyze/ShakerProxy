package applifecycle

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const maxReleaseMetadataBytes = 32 << 10

const trustedReleaseKeySHA256 = "e8c3c965ed4859f55e69af55ccb03d20d297843104b611f0a754072694dafdcb"

var (
	versionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:[-.][0-9A-Za-z.-]+)?$`)
	digestPattern  = regexp.MustCompile(`^[A-Za-z0-9./_-]+@sha256:[a-f0-9]{64}$`)
	envNamePattern = regexp.MustCompile(`^SHAKERPROXY_[A-Z0-9_]+_IMAGE$`)
)

type Release struct {
	Schema              int       `json:"schema"`
	Version             string    `json:"version"`
	Channel             string    `json:"channel"`
	Profiles            []string  `json:"profiles"`
	ManifestSHA256      string    `json:"manifest_sha256"`
	ComposeBundleSHA256 string    `json:"compose_bundle_sha256"`
	ConfigSchema        int       `json:"config_schema"`
	DatabaseSchema      int       `json:"database_schema"`
	InstalledAt         time.Time `json:"installed_at"`
}

type Runner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

type ExecRunner struct{}

// commandEnvironment is the whole environment of lifecycle commands.
// DOCKER_CONFIG keeps the Docker CLI out of /root: shakerproxy-app.service runs
// with ProtectHome=true and no capabilities, where /root/.docker is
// unreadable, and Docker then drops its plugins, including compose.
var commandEnvironment = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "DOCKER_CONFIG=/etc/shakerproxy/docker"}

func (ExecRunner) Run(ctx context.Context, executable string, arguments ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, executable, arguments...)
	command.Env = append([]string(nil), commandEnvironment...)
	output, err := command.CombinedOutput()
	if len(output) > 64<<10 {
		output = output[:64<<10]
	}
	if err != nil {
		return output, fmt.Errorf("fixed application lifecycle command failed: %w", err)
	}
	return output, nil
}

type Controller struct {
	InstallRoot            string
	ConfigRoot             string
	DockerPath             string
	TrustedPublicKeySHA256 string
	Runner                 Runner
}

func (c Controller) Execute(ctx context.Context, action string) ([]byte, error) {
	releaseDirectory, release, err := c.validateRelease()
	if err != nil {
		return nil, err
	}
	base := []string{
		"compose",
		"--project-name", "shakerproxy",
		// Relative bind mounts in compose.yaml (./caddy/...) resolve from deploy/.
		"--project-directory", filepath.Join(releaseDirectory, "deploy"),
		"--env-file", filepath.Join(c.configRoot(), "compose.env"),
		"--env-file", filepath.Join(releaseDirectory, "release.env"),
		"-f", filepath.Join(releaseDirectory, "deploy", "compose.yaml"),
	}
	for _, profile := range release.Profiles {
		base = append(base, "--profile", profile)
	}
	switch action {
	case "validate":
		base = append(base, "config", "--quiet")
	case "start":
		if _, err := c.run(ctx, append(append([]string{}, base...), "config", "--quiet")...); err != nil {
			return nil, err
		}
		base = append(base, "up", "--detach", "--remove-orphans", "--pull", "never", "--wait", "--wait-timeout", "120")
	case "stop":
		base = append(base, "stop", "--timeout", "30")
	case "status":
		base = append(base, "ps", "--format", "json")
	default:
		return nil, fmt.Errorf("unsupported application lifecycle action %q", action)
	}
	return c.run(ctx, base...)
}

func (c Controller) validateRelease() (string, Release, error) {
	root, err := filepath.Abs(c.installRoot())
	if err != nil {
		return "", Release{}, err
	}
	releasesRoot := filepath.Join(root, "releases")
	current := filepath.Join(root, "current")
	info, err := os.Lstat(current)
	if err != nil {
		return "", Release{}, errors.New("current application release is unavailable")
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return "", Release{}, errors.New("current application release must be an atomic symlink")
	}
	releaseDirectory, err := filepath.EvalSymlinks(current)
	if err != nil {
		return "", Release{}, errors.New("current application release symlink is invalid")
	}
	relative, err := filepath.Rel(releasesRoot, releaseDirectory)
	if err != nil || relative == "." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || relative == ".." || strings.Contains(relative, string(filepath.Separator)) {
		return "", Release{}, errors.New("current application release escapes the releases directory")
	}
	if !versionPattern.MatchString(relative) {
		return "", Release{}, errors.New("current application release directory is not a version")
	}
	metadataPath := filepath.Join(releaseDirectory, "release.json")
	metadata, err := readRegular(metadataPath, maxReleaseMetadataBytes)
	if err != nil {
		return "", Release{}, fmt.Errorf("read release metadata: %w", err)
	}
	var release Release
	decoder := json.NewDecoder(bytes.NewReader(metadata))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&release); err != nil {
		return "", Release{}, errors.New("release metadata is invalid")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return "", Release{}, errors.New("release metadata has trailing data")
	}
	if err := release.Validate(relative); err != nil {
		return "", Release{}, err
	}
	images, err := validateReleaseEnvironment(filepath.Join(releaseDirectory, "release.env"))
	if err != nil {
		return "", Release{}, err
	}
	if err := c.validateSignedManifest(releaseDirectory, release, images); err != nil {
		return "", Release{}, err
	}
	if err := validateBundleFiles(releaseDirectory); err != nil {
		return "", Release{}, err
	}
	if _, err := readRegular(filepath.Join(releaseDirectory, "deploy", "compose.yaml"), 1<<20); err != nil {
		return "", Release{}, fmt.Errorf("read release Compose file: %w", err)
	}
	return releaseDirectory, release, nil
}

func (release Release) Validate(directoryVersion string) error {
	if release.Schema != 1 || release.Version != directoryVersion || !versionPattern.MatchString(release.Version) {
		return errors.New("release metadata version is invalid")
	}
	if release.Channel != "stable" && release.Channel != "beta" && release.Channel != "nightly" {
		return errors.New("release metadata channel is invalid")
	}
	if !isSHA256(release.ManifestSHA256) || !isSHA256(release.ComposeBundleSHA256) || release.ConfigSchema < 1 || release.DatabaseSchema < 1 || release.InstalledAt.IsZero() {
		return errors.New("release metadata provenance is incomplete")
	}
	if len(release.Profiles) == 0 || len(release.Profiles) > 5 {
		return errors.New("release profile selection is invalid")
	}
	allowed := map[string]bool{"core": true, "observe": true, "dns": true, "mitm": true, "search": true}
	seen := make(map[string]bool, len(release.Profiles))
	for _, profile := range release.Profiles {
		if !allowed[profile] || seen[profile] {
			return errors.New("release profile selection is invalid")
		}
		seen[profile] = true
	}
	if !seen["core"] {
		return errors.New("release profile selection must include core")
	}
	return nil
}

func validateReleaseEnvironment(path string) (map[string]string, error) {
	contents, err := readRegular(path, 32<<10)
	if err != nil {
		return nil, fmt.Errorf("read release environment: %w", err)
	}
	values := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSuffix(string(contents), "\n"), "\n") {
		name, value, ok := strings.Cut(line, "=")
		if !ok || !envNamePattern.MatchString(name) || !digestPattern.MatchString(value) || values[name] != "" {
			return nil, errors.New("release environment contains a non-image or unpinned value")
		}
		values[name] = value
	}
	required := []string{"SHAKERPROXY_POSTGRES_IMAGE", "SHAKERPROXY_CONTROL_API_IMAGE", "SHAKERPROXY_WEB_UI_IMAGE", "SHAKERPROXY_EDGE_IMAGE", "SHAKERPROXY_INGESTD_IMAGE", "SHAKERPROXY_ZEEK_IMAGE", "SHAKERPROXY_SURICATA_IMAGE", "SHAKERPROXY_MITMPROXY_IMAGE"}
	for _, name := range required {
		if values[name] == "" {
			return nil, fmt.Errorf("release environment is missing %s", name)
		}
	}
	if len(values) != len(required) {
		return nil, errors.New("release environment has unexpected image values")
	}
	return values, nil
}

type signedManifest struct {
	Schema           int               `json:"schema"`
	Version          string            `json:"version"`
	Channel          string            `json:"channel"`
	ReleaseKeySHA256 string            `json:"release_public_key_sha256"`
	Images           map[string]string `json:"images"`
	ComposeBundle    manifestArtifact  `json:"compose_bundle"`
	ConfigSchema     int               `json:"config_schema"`
	DatabaseSchema   int               `json:"database_schema"`
}

type manifestArtifact struct {
	SHA256 string `json:"sha256"`
}

func (c Controller) validateSignedManifest(releaseDirectory string, release Release, images map[string]string) error {
	manifest, err := readRegular(filepath.Join(releaseDirectory, "manifest.json"), 128<<10)
	if err != nil {
		return fmt.Errorf("read signed release manifest: %w", err)
	}
	manifestDigest := sha256.Sum256(manifest)
	if hex.EncodeToString(manifestDigest[:]) != release.ManifestSHA256 {
		return errors.New("signed release manifest digest differs from release metadata")
	}
	signature, err := readRegular(filepath.Join(releaseDirectory, "manifest.json.sig"), 8<<10)
	if err != nil {
		return fmt.Errorf("read release manifest signature: %w", err)
	}
	publicPEM, err := readRegular(filepath.Join(releaseDirectory, "release-public.pem"), 8<<10)
	if err != nil {
		return fmt.Errorf("read release public key: %w", err)
	}
	block, rest := pem.Decode(publicPEM)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 || block.Type != "PUBLIC KEY" {
		return errors.New("release public key is invalid")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return errors.New("release public key is invalid")
	}
	publicKey, ok := parsed.(*rsa.PublicKey)
	if !ok || publicKey.N.BitLen() < 3072 {
		return errors.New("release public key is not an RSA-3072 or stronger key")
	}
	keyDigest := sha256.Sum256(block.Bytes)
	expectedKeyDigest := c.TrustedPublicKeySHA256
	if expectedKeyDigest == "" {
		expectedKeyDigest = trustedReleaseKeySHA256
	}
	if hex.EncodeToString(keyDigest[:]) != expectedKeyDigest {
		return errors.New("release public key is not the pinned ShakerProxy key")
	}
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, manifestDigest[:], signature); err != nil {
		return errors.New("release manifest signature verification failed")
	}
	var signed signedManifest
	if err := json.Unmarshal(manifest, &signed); err != nil {
		return errors.New("signed release manifest is invalid")
	}
	if signed.Schema != 1 || signed.Version != release.Version || signed.Channel != release.Channel || signed.ReleaseKeySHA256 != expectedKeyDigest || signed.ComposeBundle.SHA256 != release.ComposeBundleSHA256 || signed.ConfigSchema != release.ConfigSchema || signed.DatabaseSchema != release.DatabaseSchema {
		return errors.New("signed release manifest differs from release metadata")
	}
	if len(signed.Images) != len(images) {
		return errors.New("signed image set differs from release environment")
	}
	for name, image := range images {
		if signed.Images[name] != image {
			return errors.New("signed image set differs from release environment")
		}
	}
	return nil
}

func validateBundleFiles(releaseDirectory string) error {
	contents, err := readRegular(filepath.Join(releaseDirectory, "bundle-files.sha256"), 128<<10)
	if err != nil {
		return fmt.Errorf("read bundle file integrity manifest: %w", err)
	}
	expected := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSuffix(string(contents), "\n"), "\n") {
		digest, path, ok := strings.Cut(line, "  ")
		clean := filepath.Clean(path)
		if !ok || !isSHA256(digest) || clean != path || filepath.IsAbs(path) || path == "." || strings.HasPrefix(path, ".."+string(filepath.Separator)) || path == "bundle-files.sha256" || expected[path] != "" {
			return errors.New("bundle file integrity manifest is invalid")
		}
		expected[path] = digest
	}
	if len(expected) == 0 {
		return errors.New("bundle file integrity manifest is empty")
	}
	actual := make(map[string]bool)
	err = filepath.WalkDir(releaseDirectory, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(releaseDirectory, path)
		if err != nil || relative == "." {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		if expectedDigest := expected[relative]; expectedDigest != "" {
			data, err := readRegular(path, 4<<20)
			if err != nil {
				return err
			}
			digest := sha256.Sum256(data)
			if hex.EncodeToString(digest[:]) != expectedDigest {
				return fmt.Errorf("bundle file %s failed integrity verification", relative)
			}
			actual[relative] = true
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("verify bundle files: %w", err)
	}
	for path := range expected {
		if !actual[path] {
			return fmt.Errorf("bundle file %s is missing", path)
		}
	}
	return nil
}

func readRegular(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maximum {
		return nil, errors.New("file is not a bounded regular file")
	}
	return os.ReadFile(path)
}

func isSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if !strings.ContainsRune("0123456789abcdef", character) {
			return false
		}
	}
	return true
}

func (c Controller) run(ctx context.Context, arguments ...string) ([]byte, error) {
	runner := c.Runner
	if runner == nil {
		runner = ExecRunner{}
	}
	return runner.Run(ctx, c.dockerPath(), arguments...)
}

func (c Controller) installRoot() string {
	if c.InstallRoot != "" {
		return c.InstallRoot
	}
	return "/opt/shakerproxy"
}

func (c Controller) configRoot() string {
	if c.ConfigRoot != "" {
		return c.ConfigRoot
	}
	return "/etc/shakerproxy"
}

func (c Controller) dockerPath() string {
	if c.DockerPath != "" {
		return c.DockerPath
	}
	return "/usr/bin/docker"
}

func SortedProfiles(profiles []string) []string {
	result := append([]string(nil), profiles...)
	sort.Strings(result)
	return result
}
