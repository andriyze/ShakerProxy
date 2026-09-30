package interceptionpki

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnsureCreatesPrivateMITMCAAndPublicCertificateOnly(t *testing.T) {
	root := t.TempDir()
	options := Options{
		PrivateRoot:  filepath.Join(root, "private"),
		PublicRoot:   filepath.Join(root, "public"),
		Now:          time.Date(2026, 9, 2, 20, 0, 0, 0, time.UTC),
		KeyBits:      2048,
		PrivateOwner: &FileOwner{UID: os.Getuid(), GID: os.Getgid()},
	}
	first, err := Ensure(options)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Ensure(options)
	if err != nil {
		t.Fatal(err)
	}
	if first.SHA256Fingerprint != second.SHA256Fingerprint || first.Purpose != Purpose || first.PrivateKeyExport {
		t.Fatalf("interception CA was not stable and private: %#v %#v", first, second)
	}
	bundlePath := filepath.Join(options.PrivateRoot, "mitmproxy-ca.pem")
	bundleInfo, err := os.Stat(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	if bundleInfo.Mode().Perm() != 0o400 {
		t.Fatalf("private CA bundle mode %o, want 400", bundleInfo.Mode().Perm())
	}
	publicPEM, contentType, filename, err := PublicCertificate(options.PublicRoot, "pem")
	if err != nil || contentType != "application/x-pem-file" || filename != "shakerproxy-interception-ca.pem" {
		t.Fatalf("public certificate projection failed: %v %q %q", err, contentType, filename)
	}
	block, rest := pem.Decode(publicPEM)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatal("public projection is not exactly one certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !certificate.IsCA {
		t.Fatalf("public projection is not a CA: %v", err)
	}
	if bytes.Contains(publicPEM, []byte("PRIVATE KEY")) {
		t.Fatal("private key leaked into public projection")
	}
	if _, err := os.Stat(filepath.Join(options.PublicRoot, "mitmproxy-ca.pem")); !os.IsNotExist(err) {
		t.Fatal("private mitmproxy CA bundle appeared in public root")
	}
}

func TestEnsureRejectsPrivateBundleSymlink(t *testing.T) {
	root := t.TempDir()
	privateRoot := filepath.Join(root, "private")
	if err := os.MkdirAll(privateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(root, "outside")
	if err := os.WriteFile(outside, []byte("not a CA"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(privateRoot, "mitmproxy-ca.pem")); err != nil {
		t.Fatal(err)
	}
	_, err := Ensure(Options{PrivateRoot: privateRoot, PublicRoot: filepath.Join(root, "public"), KeyBits: 2048})
	if err == nil {
		t.Fatal("private CA symlink was accepted")
	}
}

func TestEnsureRejectsCorruptExistingAuthority(t *testing.T) {
	root := t.TempDir()
	options := Options{
		PrivateRoot: filepath.Join(root, "private"),
		PublicRoot:  filepath.Join(root, "public"),
		KeyBits:     2048,
	}
	if _, err := Ensure(options); err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(options.PrivateRoot, "mitmproxy-ca.pem")
	if err := os.Chmod(bundlePath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundlePath, []byte("corrupt\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := Ensure(options); err == nil {
		t.Fatal("corrupt interception CA was silently replaced")
	}
}

func TestPublicCertificateRejectsPrivateOrUnknownFormat(t *testing.T) {
	root := t.TempDir()
	if _, _, _, err := PublicCertificate(root, "private-key"); err == nil {
		t.Fatal("private-key format was accepted")
	}
}
