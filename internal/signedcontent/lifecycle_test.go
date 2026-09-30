package signedcontent

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fixtureSigner struct {
	key                 *rsa.PrivateKey
	keyHash, publicPath string
	now                 time.Time
}

func newSigner(t *testing.T) fixtureSigner {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	path := filepath.Join(t.TempDir(), "release-public.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	return fixtureSigner{key: key, keyHash: hex.EncodeToString(sum[:]), publicPath: path, now: time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)}
}

func (signer fixtureSigner) rulesBundle(t *testing.T, revision string, sid int) Bundle {
	t.Helper()
	rules := []byte(fmt.Sprintf("alert tcp any any -> any 23 (msg:\"ShakerProxy test\"; sid:%d; rev:1;)\n", sid))
	ruleHash := sha256.Sum256(rules)
	provenance := map[string]any{"schema": 1, "ruleset_id": "shakerproxy-test", "version": revision, "source": "test fixture", "license": "Apache-2.0", "engine": "SURICATA", "engine_version": "8.0.6", "sha256": hex.EncodeToString(ruleHash[:]), "rule_count": 1, "sid_min": sid, "sid_max": sid, "updated_at": signer.now}
	provenanceJSON, _ := json.Marshal(provenance)
	files := map[string][]byte{"suricata.rules": rules, "suricata-ruleset.json": provenanceJSON}
	artifacts := make([]Artifact, 0, 2)
	for _, name := range []string{"suricata.rules", "suricata-ruleset.json"} {
		sum := sha256.Sum256(files[name])
		artifacts = append(artifacts, Artifact{Name: name, SHA256: hex.EncodeToString(sum[:]), Size: len(files[name])})
	}
	manifest := Manifest{Schema: 1, Kind: SuricataRules, Revision: revision, Name: "ShakerProxy test rules", Source: "offline test fixture", CreatedAt: signer.now, SigningKeySHA256: signer.keyHash, Artifacts: artifacts}
	manifestJSON, _ := json.Marshal(manifest)
	digest := sha256.Sum256(manifestJSON)
	signature, err := rsa.SignPKCS1v15(rand.Reader, signer.key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return Bundle{ManifestJSON: manifestJSON, Signature: signature, Files: files}
}

func TestSignedLifecyclePreviewPinRollbackAndTamperRejection(t *testing.T) {
	signer := newSigner(t)
	manager := Manager{Root: t.TempDir(), PublicKeyPath: signer.publicPath, Now: func() time.Time { return signer.now }}
	first := signer.rulesBundle(t, "2026.09.02.1", 9900001)
	preview, err := manager.Preview(first)
	if err != nil || !preview.Valid || !preview.SignatureVerified || len(preview.Diff) != 2 {
		t.Fatalf("preview failed: %#v %v", preview, err)
	}
	state, err := manager.Apply(first, 0, "test-admin")
	if err != nil || state.Channels[SuricataRules].Current != "2026.09.02.1" {
		t.Fatalf("first apply failed: %#v %v", state, err)
	}
	second := signer.rulesBundle(t, "2026.09.02.2", 9900002)
	preview, err = manager.Preview(second)
	if err != nil || preview.Diff[0].Change != "changed" {
		t.Fatalf("diff failed: %#v %v", preview, err)
	}
	state, err = manager.Pin(SuricataRules, "2026.09.02.1", state.Revision, "test-admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = manager.Apply(second, state.Revision, "test-admin"); !errors.Is(err, ErrPinned) {
		t.Fatalf("pin did not block update: %v", err)
	}
	state, err = manager.Pin(SuricataRules, "", state.Revision, "test-admin")
	if err != nil {
		t.Fatal(err)
	}
	state, err = manager.Apply(second, state.Revision, "test-admin")
	if err != nil {
		t.Fatal(err)
	}
	state, err = manager.Rollback(SuricataRules, state.Revision, "test-admin")
	if err != nil || state.Channels[SuricataRules].Current != "2026.09.02.1" {
		t.Fatalf("rollback failed: %#v %v", state, err)
	}
	tampered := first
	tampered.Files = map[string][]byte{"suricata.rules": []byte("tampered"), "suricata-ruleset.json": first.Files["suricata-ruleset.json"]}
	if _, err := manager.Preview(tampered); err == nil {
		t.Fatal("tampered artifact was accepted")
	}
	badSignature := first
	badSignature.Signature = append([]byte(nil), first.Signature...)
	badSignature.Signature[0] ^= 0xff
	if _, err := manager.Preview(badSignature); err == nil {
		t.Fatal("modified signature was accepted")
	}
	statePath := filepath.Join(manager.Root, "state.json")
	stateJSON, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	stateJSON = []byte(strings.Replace(string(stateJSON), `"current":"2026.09.02.1"`, `"current":"2026.09.02.9"`, 1))
	if err := os.WriteFile(statePath, stateJSON, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Status(); err == nil {
		t.Fatal("channel state that differed from its audit was accepted")
	}
}

func TestFailedConsumerHealthAutomaticallyRestoresLastKnownGood(t *testing.T) {
	signer := newSigner(t)
	fail := false
	manager := Manager{Root: t.TempDir(), PublicKeyPath: signer.publicPath, Now: func() time.Time { return signer.now }, PostActivate: func(_ Kind, _ string) error {
		if fail {
			return errors.New("suricata -T failed")
		}
		return nil
	}}
	state, err := manager.Apply(signer.rulesBundle(t, "2026.09.02.1", 9900001), 0, "admin")
	if err != nil {
		t.Fatal(err)
	}
	fail = true
	state, err = manager.Apply(signer.rulesBundle(t, "2026.09.02.2", 9900002), state.Revision, "admin")
	if err == nil {
		t.Fatal("failed health was reported as success")
	}
	channel := state.Channels[SuricataRules]
	if channel.Current != "2026.09.02.1" || channel.LastResult != "AUTO_ROLLED_BACK" || channel.Previous != "2026.09.02.2" {
		t.Fatalf("last known good was not restored: %#v", channel)
	}
}

func TestZeekLockAndResolverCatalogPayloadSchemas(t *testing.T) {
	zeek := map[string][]byte{"zkg.lock.json": []byte(`{"schema":1,"packages":[{"name":"shakerproxy-dns-evidence","version":"1.2.3","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}`)}
	if err := validatePayload(ZeekPackages, zeek); err != nil {
		t.Fatalf("valid Zeek package lock rejected: %v", err)
	}
	resolver := map[string][]byte{"resolver-catalog.json": []byte(`{"schema":1,"revision":"2026.09.02.1","entries":[]}`)}
	if err := validatePayload(ResolverCatalog, resolver); err != nil {
		t.Fatalf("valid resolver catalog rejected: %v", err)
	}
	resolver["resolver-catalog.json"] = []byte(`{"schema":1,"revision":"../../escape","entries":[]}`)
	if err := validatePayload(ResolverCatalog, resolver); err == nil {
		t.Fatal("unsafe resolver catalog revision was accepted")
	}
}
