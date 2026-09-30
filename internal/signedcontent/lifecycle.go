// Package signedcontent manages versioned, signed rulesets and catalogs.
package signedcontent

import (
	"bytes"
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
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"shakerproxy.dev/shakerproxy/internal/analyzer"
)

const (
	SchemaVersion  = 1
	MaxBundleBytes = 5 << 20
	MaxAudit       = 2048
)

type Kind string

const (
	SuricataRules   Kind = "SURICATA_RULESET"
	ZeekPackages    Kind = "ZEEK_PACKAGES"
	ResolverCatalog Kind = "RESOLVER_CATALOG"
)

var (
	revisionPattern = regexp.MustCompile(`^[0-9]{4}\.[0-9]{2}\.[0-9]{2}\.[1-9][0-9]{0,5}$`)
	namePattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._+-]{0,95}$`)
	shaPattern      = regexp.MustCompile(`^[a-f0-9]{64}$`)
	ErrConflict     = errors.New("signed content state revision conflict")
	ErrPinned       = errors.New("signed content channel is pinned")
)

type Artifact struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int    `json:"size"`
}

type Manifest struct {
	Schema           int        `json:"schema"`
	Kind             Kind       `json:"kind"`
	Revision         string     `json:"revision"`
	Name             string     `json:"name"`
	Source           string     `json:"source"`
	CreatedAt        time.Time  `json:"created_at"`
	SigningKeySHA256 string     `json:"signing_key_sha256"`
	Artifacts        []Artifact `json:"artifacts"`
}

// Bundle preserves the exact signed manifest bytes. JSON encodes byte slices as
// base64, so it is portable across the CLI and future API upload surfaces.
type Bundle struct {
	ManifestJSON []byte            `json:"manifest_json"`
	Signature    []byte            `json:"signature"`
	Files        map[string][]byte `json:"files"`
}

type ChannelState struct {
	Current    string     `json:"current,omitempty"`
	Previous   string     `json:"previous,omitempty"`
	Pinned     string     `json:"pinned,omitempty"`
	LastResult string     `json:"last_result,omitempty"`
	LastError  string     `json:"last_error,omitempty"`
	UpdatedAt  *time.Time `json:"updated_at,omitempty"`
}

type AuditEntry struct {
	Revision     uint64    `json:"revision"`
	Action       string    `json:"action"`
	Kind         Kind      `json:"kind"`
	Target       string    `json:"target,omitempty"`
	Actor        string    `json:"actor"`
	OccurredAt   time.Time `json:"occurred_at"`
	PreviousHash string    `json:"previous_hash"`
	Hash         string    `json:"hash"`
}

type State struct {
	Schema   int                   `json:"schema"`
	Revision uint64                `json:"revision"`
	Channels map[Kind]ChannelState `json:"channels"`
	Audit    []AuditEntry          `json:"audit"`
}

type ArtifactDiff struct {
	Name       string `json:"name"`
	Change     string `json:"change"`
	FromSHA256 string `json:"from_sha256,omitempty"`
	ToSHA256   string `json:"to_sha256,omitempty"`
}
type Preview struct {
	Valid             bool           `json:"valid"`
	Kind              Kind           `json:"kind"`
	Current           string         `json:"current,omitempty"`
	Target            string         `json:"target"`
	Pinned            string         `json:"pinned,omitempty"`
	SignatureVerified bool           `json:"signature_verified"`
	Diff              []ArtifactDiff `json:"diff"`
	Manifest          Manifest       `json:"manifest"`
}

type Manager struct {
	Root          string
	PublicKeyPath string
	Now           func() time.Time
	// PostActivate must restart/reload the consumer and prove health. Returning
	// an error causes an immediate state rollback to last known good.
	PostActivate func(Kind, string) error
}

func LoadBundle(path string) (Bundle, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Bundle{}, err
	}
	if len(data) == 0 || len(data) > MaxBundleBytes*2 {
		return Bundle{}, errors.New("signed content bundle has invalid size")
	}
	var bundle Bundle
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&bundle); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return Bundle{}, errors.New("signed content bundle is invalid JSON")
	}
	return bundle, nil
}

func (m Manager) Status() (State, error) { return m.loadState() }

func (m Manager) Preview(bundle Bundle) (Preview, error) {
	manifest, err := m.verify(bundle)
	if err != nil {
		return Preview{}, err
	}
	state, err := m.loadState()
	if err != nil {
		return Preview{}, err
	}
	channel := state.Channels[manifest.Kind]
	currentArtifacts := map[string]Artifact{}
	if channel.Current != "" {
		current, err := m.loadStoredManifest(manifest.Kind, channel.Current)
		if err != nil {
			return Preview{}, fmt.Errorf("current signed content failed verification: %w", err)
		}
		for _, artifact := range current.Artifacts {
			currentArtifacts[artifact.Name] = artifact
		}
	}
	targetArtifacts := map[string]Artifact{}
	for _, artifact := range manifest.Artifacts {
		targetArtifacts[artifact.Name] = artifact
	}
	names := map[string]struct{}{}
	for name := range currentArtifacts {
		names[name] = struct{}{}
	}
	for name := range targetArtifacts {
		names[name] = struct{}{}
	}
	ordered := make([]string, 0, len(names))
	for name := range names {
		ordered = append(ordered, name)
	}
	sort.Strings(ordered)
	diff := make([]ArtifactDiff, 0, len(ordered))
	for _, name := range ordered {
		from, had := currentArtifacts[name]
		to, has := targetArtifacts[name]
		change := "changed"
		if !had {
			change = "added"
		} else if !has {
			change = "removed"
		} else if from.SHA256 == to.SHA256 {
			change = "unchanged"
		}
		diff = append(diff, ArtifactDiff{Name: name, Change: change, FromSHA256: from.SHA256, ToSHA256: to.SHA256})
	}
	return Preview{Valid: true, Kind: manifest.Kind, Current: channel.Current, Target: manifest.Revision, Pinned: channel.Pinned, SignatureVerified: true, Diff: diff, Manifest: manifest}, nil
}

func (m Manager) Apply(bundle Bundle, expected uint64, actor string) (State, error) {
	preview, err := m.Preview(bundle)
	if err != nil {
		return State{}, err
	}
	state, err := m.loadState()
	if err != nil {
		return State{}, err
	}
	if state.Revision != expected {
		return State{}, ErrConflict
	}
	if len(state.Audit) > MaxAudit-2 {
		return State{}, errors.New("signed content audit capacity reached")
	}
	channel := state.Channels[preview.Kind]
	if channel.Pinned != "" && channel.Pinned != preview.Target {
		return State{}, ErrPinned
	}
	objectPath := m.objectPath(preview.Kind, preview.Target)
	if err := m.storeObject(objectPath, bundle); err != nil {
		return State{}, err
	}
	if channel.Current == preview.Target {
		return state, nil
	}
	prior := channel.Current
	channel.Previous, channel.Current = prior, preview.Target
	now := m.now()
	channel.UpdatedAt = &now
	channel.LastResult = "ACTIVATING"
	channel.LastError = ""
	state.Channels[preview.Kind] = channel
	if err := m.appendAudit(&state, "activated", preview.Kind, preview.Target, actor); err != nil {
		return State{}, err
	}
	if err := m.saveState(state); err != nil {
		return State{}, err
	}
	if m.PostActivate != nil {
		if err := m.PostActivate(preview.Kind, objectPath); err != nil {
			loaded, loadErr := m.loadState()
			if loadErr != nil {
				return State{}, errors.Join(err, loadErr)
			}
			state = loaded
			channel = state.Channels[preview.Kind]
			channel.Current, channel.Previous, channel.LastResult, channel.LastError = prior, preview.Target, "AUTO_ROLLED_BACK", boundError(err)
			channel.UpdatedAt = &now
			state.Channels[preview.Kind] = channel
			if auditErr := m.appendAudit(&state, "automatic_rollback", preview.Kind, prior, "engine-health"); auditErr != nil {
				return State{}, errors.Join(err, auditErr)
			}
			if saveErr := m.saveState(state); saveErr != nil {
				return State{}, errors.Join(err, saveErr)
			}
			if prior != "" {
				if restoreErr := m.PostActivate(preview.Kind, m.objectPath(preview.Kind, prior)); restoreErr != nil {
					return state, errors.Join(err, fmt.Errorf("last-known-good reload failed: %w", restoreErr))
				}
			}
			return state, fmt.Errorf("consumer health failed; restored last known good: %w", err)
		}
	}
	state, err = m.loadState()
	if err != nil {
		return State{}, err
	}
	channel = state.Channels[preview.Kind]
	channel.LastResult = "VALIDATED_PENDING_RELOAD"
	if m.PostActivate != nil {
		channel.LastResult = "HEALTHY"
	}
	channel.UpdatedAt = &now
	state.Channels[preview.Kind] = channel
	if err := m.saveState(state); err != nil {
		return State{}, err
	}
	return state, nil
}

func (m Manager) Rollback(kind Kind, expected uint64, actor string) (State, error) {
	state, err := m.loadState()
	if err != nil {
		return State{}, err
	}
	if state.Revision != expected {
		return State{}, ErrConflict
	}
	if len(state.Audit) > MaxAudit-2 {
		return State{}, errors.New("signed content audit capacity reached")
	}
	channel, ok := state.Channels[kind]
	if !ok || channel.Previous == "" {
		return State{}, errors.New("no last-known-good revision is available")
	}
	target := channel.Previous
	if _, err := m.loadStoredManifest(kind, target); err != nil {
		return State{}, err
	}
	original := channel.Current
	channel.Current, channel.Previous = target, original
	now := m.now()
	channel.UpdatedAt = &now
	channel.LastResult = "ROLLING_BACK"
	channel.LastError = ""
	state.Channels[kind] = channel
	if err := m.appendAudit(&state, "manual_rollback", kind, target, actor); err != nil {
		return State{}, err
	}
	if err := m.saveState(state); err != nil {
		return State{}, err
	}
	if m.PostActivate != nil {
		if err := m.PostActivate(kind, m.objectPath(kind, target)); err != nil {
			state, loadErr := m.loadState()
			if loadErr != nil {
				return State{}, errors.Join(err, loadErr)
			}
			channel = state.Channels[kind]
			channel.Current, channel.Previous, channel.LastResult, channel.LastError = original, target, "ROLLBACK_HEALTH_FAILED", boundError(err)
			channel.UpdatedAt = &now
			state.Channels[kind] = channel
			if auditErr := m.appendAudit(&state, "rollback_health_restore", kind, original, "engine-health"); auditErr != nil {
				return State{}, errors.Join(err, auditErr)
			}
			if saveErr := m.saveState(state); saveErr != nil {
				return State{}, errors.Join(err, saveErr)
			}
			if restoreErr := m.PostActivate(kind, m.objectPath(kind, original)); restoreErr != nil {
				return state, errors.Join(err, restoreErr)
			}
			return state, fmt.Errorf("last-known-good consumer health failed; original revision restored: %w", err)
		}
	}
	state, err = m.loadState()
	if err != nil {
		return State{}, err
	}
	channel = state.Channels[kind]
	channel.LastResult = "VALIDATED_PENDING_RELOAD"
	if m.PostActivate != nil {
		channel.LastResult = "HEALTHY"
	}
	state.Channels[kind] = channel
	if err := m.saveState(state); err != nil {
		return State{}, err
	}
	return state, nil
}

func (m Manager) Pin(kind Kind, revision string, expected uint64, actor string) (State, error) {
	state, err := m.loadState()
	if err != nil {
		return State{}, err
	}
	if state.Revision != expected {
		return State{}, ErrConflict
	}
	if !validKind(kind) || len(state.Audit) >= MaxAudit {
		return State{}, errors.New("signed content kind or audit capacity is invalid")
	}
	channel := state.Channels[kind]
	if revision != "" {
		if !revisionPattern.MatchString(revision) {
			return State{}, errors.New("invalid pin revision")
		}
		if _, err := m.loadStoredManifest(kind, revision); err != nil {
			return State{}, errors.New("pin target is not installed")
		}
	}
	channel.Pinned = revision
	now := m.now()
	channel.UpdatedAt = &now
	state.Channels[kind] = channel
	action := "unpinned"
	if revision != "" {
		action = "pinned"
	}
	if err := m.appendAudit(&state, action, kind, revision, actor); err != nil {
		return State{}, err
	}
	if err := m.saveState(state); err != nil {
		return State{}, err
	}
	return state, nil
}

func (m Manager) verify(bundle Bundle) (Manifest, error) {
	if len(bundle.ManifestJSON) == 0 || len(bundle.ManifestJSON) > 64<<10 || len(bundle.Signature) < 256 || len(bundle.Signature) > 1024 || len(bundle.Files) == 0 || len(bundle.Files) > 8 {
		return Manifest{}, errors.New("signed content bundle has invalid bounds")
	}
	var manifest Manifest
	decoder := json.NewDecoder(bytes.NewReader(bundle.ManifestJSON))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil || decoder.Decode(&struct{}{}) != io.EOF || manifest.validate() != nil {
		return Manifest{}, errors.New("signed content manifest is invalid")
	}
	public, der, err := readPublicKey(m.PublicKeyPath)
	if err != nil {
		return Manifest{}, err
	}
	keyDigest := sha256.Sum256(der)
	if hex.EncodeToString(keyDigest[:]) != manifest.SigningKeySHA256 {
		return Manifest{}, errors.New("signed content key identity does not match manifest")
	}
	digest := sha256.Sum256(bundle.ManifestJSON)
	if err := rsa.VerifyPKCS1v15(public, crypto.SHA256, digest[:], bundle.Signature); err != nil {
		return Manifest{}, errors.New("signed content signature verification failed")
	}
	total := 0
	expected := map[string]Artifact{}
	for _, artifact := range manifest.Artifacts {
		expected[artifact.Name] = artifact
	}
	if len(expected) != len(bundle.Files) {
		return Manifest{}, errors.New("signed content artifact inventory differs")
	}
	for name, data := range bundle.Files {
		artifact, ok := expected[name]
		sum := sha256.Sum256(data)
		total += len(data)
		if !ok || artifact.Size != len(data) || artifact.SHA256 != hex.EncodeToString(sum[:]) || total > MaxBundleBytes {
			return Manifest{}, errors.New("signed content artifact hash or size differs")
		}
	}
	if err := validatePayload(manifest.Kind, bundle.Files); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func (manifest Manifest) validate() error {
	if manifest.Schema != SchemaVersion || !validKind(manifest.Kind) || !revisionPattern.MatchString(manifest.Revision) || !namePattern.MatchString(manifest.Name) || len(manifest.Source) < 3 || len(manifest.Source) > 512 || strings.TrimSpace(manifest.Source) != manifest.Source || strings.ContainsAny(manifest.Source, "\r\n\x00") || manifest.CreatedAt.IsZero() || !shaPattern.MatchString(manifest.SigningKeySHA256) || len(manifest.Artifacts) == 0 || len(manifest.Artifacts) > 8 {
		return errors.New("invalid manifest")
	}
	allowed := allowedFiles(manifest.Kind)
	seen := map[string]bool{}
	for _, item := range manifest.Artifacts {
		if !allowed[item.Name] || seen[item.Name] || !shaPattern.MatchString(item.SHA256) || item.Size < 1 || item.Size > MaxBundleBytes {
			return errors.New("invalid artifact")
		}
		seen[item.Name] = true
	}
	for name := range allowed {
		if !seen[name] {
			return errors.New("required artifact missing")
		}
	}
	return nil
}

func allowedFiles(kind Kind) map[string]bool {
	switch kind {
	case SuricataRules:
		return map[string]bool{"suricata.rules": true, "suricata-ruleset.json": true}
	case ZeekPackages:
		return map[string]bool{"zkg.lock.json": true}
	case ResolverCatalog:
		return map[string]bool{"resolver-catalog.json": true}
	}
	return nil
}
func validKind(kind Kind) bool { return allowedFiles(kind) != nil }

func validatePayload(kind Kind, files map[string][]byte) error {
	temporary, err := os.MkdirTemp("", "shakerproxy-signed-content-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temporary)
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(temporary, name), data, 0600); err != nil {
			return err
		}
	}
	switch kind {
	case SuricataRules:
		_, err = analyzer.LoadRulesetManifest(filepath.Join(temporary, "suricata.rules"), filepath.Join(temporary, "suricata-ruleset.json"))
		return err
	case ZeekPackages:
		var value struct {
			Schema   int `json:"schema"`
			Packages []struct {
				Name    string `json:"name"`
				Version string `json:"version"`
				SHA256  string `json:"sha256"`
			} `json:"packages"`
		}
		if strictJSON(files["zkg.lock.json"], &value) != nil || value.Schema != 1 || len(value.Packages) > 256 {
			return errors.New("Zeek package lock is invalid")
		}
		for _, item := range value.Packages {
			if !namePattern.MatchString(item.Name) || item.Version == "" || !shaPattern.MatchString(item.SHA256) {
				return errors.New("Zeek package lock entry is invalid")
			}
		}
	case ResolverCatalog:
		var value struct {
			Schema   int               `json:"schema"`
			Revision string            `json:"revision"`
			Entries  []json.RawMessage `json:"entries"`
		}
		if strictJSON(files["resolver-catalog.json"], &value) != nil || value.Schema != 1 || !revisionPattern.MatchString(value.Revision) || len(value.Entries) > 10000 {
			return errors.New("resolver catalog is invalid")
		}
	}
	return nil
}

func strictJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("multiple JSON values")
	}
	return nil
}

func readPublicKey(path string) (*rsa.PublicKey, []byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, nil, errors.New("invalid signing public key")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	key, ok := parsed.(*rsa.PublicKey)
	if !ok || key.N.BitLen() < 3072 {
		return nil, nil, errors.New("signing key must be RSA-3072 or stronger")
	}
	return key, block.Bytes, nil
}

func (m Manager) loadState() (State, error) {
	state := State{Schema: SchemaVersion, Channels: map[Kind]ChannelState{}, Audit: []AuditEntry{}}
	data, err := os.ReadFile(filepath.Join(m.Root, "state.json"))
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return State{}, err
	}
	if len(data) > 1<<20 || strictJSON(data, &state) != nil || state.Schema != SchemaVersion || state.Channels == nil || len(state.Audit) > MaxAudit {
		return State{}, errors.New("signed content state is invalid")
	}
	previous := ""
	replayed := map[Kind]ChannelState{}
	for index, entry := range state.Audit {
		if entry.Revision != uint64(index+1) || entry.PreviousHash != previous || auditHash(entry) != entry.Hash || !validKind(entry.Kind) || !revisionOrEmpty(entry.Target) || len(entry.Actor) < 1 || len(entry.Actor) > 96 || entry.OccurredAt.IsZero() {
			return State{}, errors.New("signed content audit chain is invalid")
		}
		channel := replayed[entry.Kind]
		switch entry.Action {
		case "activated":
			if entry.Target == "" {
				return State{}, errors.New("signed content activation audit is invalid")
			}
			channel.Previous, channel.Current = channel.Current, entry.Target
		case "automatic_rollback", "manual_rollback", "rollback_health_restore":
			if entry.Target != channel.Previous {
				return State{}, errors.New("signed content rollback audit is invalid")
			}
			channel.Current, channel.Previous = entry.Target, channel.Current
		case "pinned":
			if entry.Target == "" {
				return State{}, errors.New("signed content pin audit is invalid")
			}
			channel.Pinned = entry.Target
		case "unpinned":
			if entry.Target != "" {
				return State{}, errors.New("signed content unpin audit is invalid")
			}
			channel.Pinned = ""
		default:
			return State{}, errors.New("signed content audit action is invalid")
		}
		replayed[entry.Kind] = channel
		previous = entry.Hash
	}
	if state.Revision != uint64(len(state.Audit)) {
		return State{}, errors.New("signed content revision differs from audit")
	}
	for kind, channel := range state.Channels {
		if !validKind(kind) || !revisionOrEmpty(channel.Current) || !revisionOrEmpty(channel.Previous) || !revisionOrEmpty(channel.Pinned) {
			return State{}, errors.New("signed content channel is invalid")
		}
		expected := replayed[kind]
		if channel.Current != expected.Current || channel.Previous != expected.Previous || channel.Pinned != expected.Pinned {
			return State{}, errors.New("signed content channel differs from its audit")
		}
	}
	for kind, expected := range replayed {
		channel := state.Channels[kind]
		if channel.Current != expected.Current || channel.Previous != expected.Previous || channel.Pinned != expected.Pinned {
			return State{}, errors.New("signed content audit channel is missing")
		}
	}
	return state, nil
}

func (m Manager) saveState(state State) error {
	return writeAtomic(filepath.Join(m.Root, "state.json"), mustJSON(state), 0600)
}
func (m Manager) appendAudit(state *State, action string, kind Kind, target, actor string) error {
	if len(state.Audit) >= MaxAudit || len(actor) < 1 || len(actor) > 96 || strings.ContainsAny(actor, "\r\n\x00") {
		return errors.New("signed content audit capacity or actor is invalid")
	}
	previous := ""
	if len(state.Audit) > 0 {
		previous = state.Audit[len(state.Audit)-1].Hash
	}
	entry := AuditEntry{Revision: state.Revision + 1, Action: action, Kind: kind, Target: target, Actor: actor, OccurredAt: m.now(), PreviousHash: previous}
	entry.Hash = auditHash(entry)
	state.Audit = append(state.Audit, entry)
	state.Revision = entry.Revision
	return nil
}
func auditHash(entry AuditEntry) string {
	entry.Hash = ""
	sum := sha256.Sum256(mustJSON(entry))
	return hex.EncodeToString(sum[:])
}
func (m Manager) objectPath(kind Kind, revision string) string {
	return filepath.Join(m.Root, "objects", strings.ToLower(string(kind)), revision)
}
func (m Manager) storeObject(path string, bundle Bundle) error {
	if _, err := os.Stat(path); err == nil {
		existing, verifyErr := m.loadStoredBundle(path)
		if verifyErr != nil {
			return verifyErr
		}
		if !bytes.Equal(existing.ManifestJSON, bundle.ManifestJSON) || !bytes.Equal(existing.Signature, bundle.Signature) {
			return errors.New("installed revision differs from update bundle")
		}
		for name, data := range bundle.Files {
			if !bytes.Equal(existing.Files[name], data) {
				return errors.New("installed revision artifact differs from update bundle")
			}
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temporary := path + fmt.Sprintf(".tmp-%d", os.Getpid())
	if err := os.MkdirAll(temporary, 0700); err != nil {
		return err
	}
	defer os.RemoveAll(temporary)
	if err := os.WriteFile(filepath.Join(temporary, "manifest.json"), bundle.ManifestJSON, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(temporary, "manifest.sig"), bundle.Signature, 0600); err != nil {
		return err
	}
	for name, data := range bundle.Files {
		if err := os.WriteFile(filepath.Join(temporary, name), data, 0600); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}
func (m Manager) loadStoredManifest(kind Kind, revision string) (Manifest, error) {
	bundle, err := m.loadStoredBundle(m.objectPath(kind, revision))
	if err != nil {
		return Manifest{}, err
	}
	return m.verify(bundle)
}
func (m Manager) loadStoredBundle(path string) (Bundle, error) {
	manifestJSON, err := os.ReadFile(filepath.Join(path, "manifest.json"))
	if err != nil {
		return Bundle{}, err
	}
	var manifest Manifest
	if strictJSON(manifestJSON, &manifest) != nil || manifest.validate() != nil {
		return Bundle{}, errors.New("stored signed content manifest is invalid")
	}
	signature, err := os.ReadFile(filepath.Join(path, "manifest.sig"))
	if err != nil {
		return Bundle{}, err
	}
	bundle := Bundle{ManifestJSON: manifestJSON, Signature: signature, Files: map[string][]byte{}}
	for _, artifact := range manifest.Artifacts {
		data, readErr := os.ReadFile(filepath.Join(path, artifact.Name))
		if readErr != nil {
			return Bundle{}, readErr
		}
		bundle.Files[artifact.Name] = data
	}
	if _, err := m.verify(bundle); err != nil {
		return Bundle{}, err
	}
	return bundle, nil
}
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".signed-content-")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if err := file.Chmod(mode); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(append(data, '\n')); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
func mustJSON(value any) []byte { data, _ := json.Marshal(value); return data }
func boundError(err error) string {
	value := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, err.Error())
	if len(value) > 256 {
		return value[:256]
	}
	return value
}
func revisionOrEmpty(value string) bool { return value == "" || revisionPattern.MatchString(value) }
func (m Manager) now() time.Time {
	if m.Now != nil {
		return m.Now().UTC()
	}
	return time.Now().UTC()
}
