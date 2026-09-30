package managementpki

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnsureCreatesSeparatedPurposeConstrainedPKI(t *testing.T) {
	root := t.TempDir()
	options := Options{EtcRoot: filepath.Join(root, "etc"), DataRoot: filepath.Join(root, "data"), EdgeGID: -1, Testing: true, Now: time.Now().UTC()}
	first, err := Ensure(options)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Ensure(options)
	if err != nil {
		t.Fatal(err)
	}
	if first.SHA256Fingerprint != second.SHA256Fingerprint || first.Purpose != Purpose || first.InterceptionCAState != "separate-authority" {
		t.Fatalf("unexpected idempotent status: %#v %#v", first, second)
	}
	management := filepath.Join(options.EtcRoot, "pki", "management")
	assertMode(t, filepath.Join(management, "root-ca.key"), 0o400)
	assertMode(t, filepath.Join(management, "root-ca.crt"), 0o444)
	assertMode(t, filepath.Join(options.EtcRoot, "pki", "interception"), 0o700)
	leafTarget, err := os.Readlink(filepath.Join(management, "current"))
	if err != nil {
		t.Fatal(err)
	}
	assertMode(t, filepath.Join(management, leafTarget, "tls.key"), 0o440)
	assertMode(t, filepath.Join(management, leafTarget, "tls.crt"), 0o444)
	certificatePEM, status, err := LoadPublic(filepath.Join(options.DataRoot, "public", "management-ca.crt"), filepath.Join(options.DataRoot, "public", "management-pki.json"))
	if err != nil || len(certificatePEM) == 0 || status.SHA256Fingerprint != first.SHA256Fingerprint {
		t.Fatalf("public projection failed: %v %#v", err, status)
	}
	markerData, err := os.ReadFile(filepath.Join(options.EtcRoot, "pki", "interception", "purpose.json"))
	if err != nil {
		t.Fatal(err)
	}
	var marker purposeMarker
	if json.Unmarshal(markerData, &marker) != nil || marker.Purpose != InterceptionPurpose || marker.State != "unprovisioned" {
		t.Fatalf("unexpected marker: %s", markerData)
	}
	if _, err := os.Stat(filepath.Join(options.EtcRoot, "pki", "interception", "root-ca.key")); !os.IsNotExist(err) {
		t.Fatal("interception private key was provisioned")
	}
}

func TestEnsureRejectsAuthorityReuseAndCorruption(t *testing.T) {
	root := t.TempDir()
	options := Options{EtcRoot: filepath.Join(root, "etc"), DataRoot: filepath.Join(root, "data"), EdgeGID: -1, Testing: true, Now: time.Now().UTC()}
	if _, err := Ensure(options); err != nil {
		t.Fatal(err)
	}
	managementCert := filepath.Join(options.EtcRoot, "pki", "management", "root-ca.crt")
	data, err := os.ReadFile(managementCert)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(options.EtcRoot, "pki", "interception", "root-ca.crt"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Ensure(options); err == nil {
		t.Fatal("authority key reuse was accepted")
	}
	if block, _ := pem.Decode(data); block == nil {
		t.Fatal("invalid test certificate")
	} else if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(options.EtcRoot, "pki", "interception", "root-ca.crt")); err != nil {
		t.Fatal(err)
	}
	managementKey := filepath.Join(options.EtcRoot, "pki", "management", "root-ca.key")
	if err := os.Chmod(managementKey, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(managementKey, []byte("corrupt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(managementKey, 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := Ensure(options); err == nil {
		t.Fatal("corrupt management key was silently replaced")
	}
}

func TestEnsureRotatesNearExpiryLeafWithoutChangingRoot(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC().Truncate(time.Second)
	options := Options{EtcRoot: filepath.Join(root, "etc"), DataRoot: filepath.Join(root, "data"), EdgeGID: -1, Testing: true, Now: now.AddDate(0, 0, -338)}
	first, err := Ensure(options)
	if err != nil {
		t.Fatal(err)
	}
	management := filepath.Join(options.EtcRoot, "pki", "management")
	firstLeaf, err := os.Readlink(filepath.Join(management, "current"))
	if err != nil {
		t.Fatal(err)
	}
	options.Now = now
	second, err := Ensure(options)
	if err != nil {
		t.Fatal(err)
	}
	secondLeaf, err := os.Readlink(filepath.Join(management, "current"))
	if err != nil {
		t.Fatal(err)
	}
	if firstLeaf == secondLeaf {
		t.Fatal("near-expiry leaf was not rotated")
	}
	if first.SHA256Fingerprint != second.SHA256Fingerprint {
		t.Fatal("leaf rotation changed the management root")
	}
	if !second.LeafNotAfter.After(first.LeafNotAfter) {
		t.Fatal("rotated leaf did not extend validity")
	}
}

func assertMode(t *testing.T, path string, expected os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != expected {
		t.Fatalf("%s mode %o, want %o", path, info.Mode().Perm(), expected)
	}
}
