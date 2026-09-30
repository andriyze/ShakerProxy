package cloudconnector

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHeartbeatPublishesPublicInterceptionCAWithoutPrivateKey(t *testing.T) {
	root := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: "ShakerProxy Test Interception CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(filepath.Join(root, "interception-ca.pem"), certificatePEM, 0o444); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(der)
	fingerprint := hex.EncodeToString(digest[:])
	status, _ := json.Marshal(map[string]any{
		"sha256_fingerprint": fingerprint,
		"private_key_export": false,
	})
	if err := os.WriteFile(filepath.Join(root, "interception-ca.json"), status, 0o444); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SHAKERPROXY_PUBLIC_ROOT", root)

	encoded, err := json.Marshal(Heartbeat{Payload: map[string]any{"existing": true}})
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	if !strings.Contains(text, `"certificate_pem"`) || !strings.Contains(text, fingerprint) {
		t.Fatalf("public interception CA metadata is missing: %s", text)
	}
	if strings.Contains(strings.ToLower(text), "private key") || strings.Contains(text, "EC PRIVATE KEY") {
		t.Fatalf("heartbeat leaked private key material: %s", text)
	}
	if !strings.Contains(text, `"private_key_export":false`) {
		t.Fatalf("heartbeat did not explicitly deny private key export: %s", text)
	}
}

func TestHeartbeatKeepsWorkingBeforeInterceptionPKIExists(t *testing.T) {
	t.Setenv("SHAKERPROXY_PUBLIC_ROOT", filepath.Join(t.TempDir(), "missing"))
	encoded, err := json.Marshal(Heartbeat{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"available":false`) {
		t.Fatalf("missing public CA was not represented safely: %s", encoded)
	}
}
