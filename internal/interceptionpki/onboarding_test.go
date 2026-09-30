package interceptionpki

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func testCertificate(t *testing.T) (string, []byte) {
	t.Helper()
	publicRoot := filepath.Join(t.TempDir(), "public")
	if _, err := Ensure(Options{PrivateRoot: filepath.Join(t.TempDir(), "private"), PublicRoot: publicRoot, KeyBits: 2048, CommonName: "ShakerProxy <Test> & CA"}); err != nil {
		t.Fatal(err)
	}
	pemBytes, err := os.ReadFile(filepath.Join(publicRoot, "interception-ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	return publicRoot, pemBytes
}

func TestSubjectHashOldMatchesOpenSSL(t *testing.T) {
	publicRoot, _ := testCertificate(t)
	certificate, err := LoadPublicCertificate(publicRoot)
	if err != nil {
		t.Fatal(err)
	}
	hash := SubjectHashOld(certificate)
	if !regexp.MustCompile(`^[0-9a-f]{8}$`).MatchString(hash) {
		t.Fatalf("hash %q is not 8 hex digits", hash)
	}
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl is not installed")
	}
	output, err := exec.Command(openssl, "x509", "-subject_hash_old", "-noout", "-in", filepath.Join(publicRoot, "interception-ca.pem")).Output()
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(output)); got != hash {
		t.Fatalf("subject_hash_old = %s, openssl says %s", hash, got)
	}
}

func TestMobileConfigIsAWellFormedRootPayload(t *testing.T) {
	publicRoot, _ := testCertificate(t)
	certificate, err := LoadPublicCertificate(publicRoot)
	if err != nil {
		t.Fatal(err)
	}
	profile := MobileConfig(certificate)
	decoder := xml.NewDecoder(bytes.NewReader(profile))
	decoder.Strict = true
	var data []string
	var inData bool
	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		switch value := token.(type) {
		case xml.StartElement:
			inData = value.Name.Local == "data"
		case xml.CharData:
			if inData {
				data = append(data, string(value))
			}
		case xml.EndElement:
			inData = false
		}
	}
	if len(data) != 1 {
		t.Fatalf("profile has %d data payloads", len(data))
	}
	der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(data[0]))
	if err != nil || !bytes.Equal(der, certificate.Raw) {
		t.Fatal("profile payload is not the CA certificate")
	}
	for _, fragment := range []string{"com.apple.security.root", "ShakerProxy &lt;Test&gt; &amp; CA", "<key>PayloadRemovalDisallowed</key>\n\t<false/>"} {
		if !strings.Contains(string(profile), fragment) {
			t.Fatalf("profile lacks %q", fragment)
		}
	}
	if !bytes.Equal(profile, MobileConfig(certificate)) {
		t.Fatal("profile is not deterministic, so re-downloads would add duplicates")
	}
}

func TestFingerprintAndInstructions(t *testing.T) {
	publicRoot, _ := testCertificate(t)
	certificate, err := LoadPublicCertificate(publicRoot)
	if err != nil {
		t.Fatal(err)
	}
	status, err := LoadPublicStatus(publicRoot)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := FormatFingerprint(certificate)
	if strings.ReplaceAll(strings.ToLower(fingerprint), ":", "") != status.SHA256Fingerprint || len(fingerprint) != 95 {
		t.Fatalf("fingerprint %q does not match status %q", fingerprint, status.SHA256Fingerprint)
	}
	platforms := map[string]bool{}
	for _, instruction := range OnboardingInstructions("http://10.77.0.1/") {
		platforms[instruction.Platform] = true
		if instruction.Title == "" || len(instruction.Steps) == 0 {
			t.Fatalf("instruction for %s is empty", instruction.Platform)
		}
	}
	for _, platform := range []string{"ios", "android", "android-tv", "macos", "windows", "linux", "smart-tv", "other"} {
		if !platforms[platform] {
			t.Fatalf("no instructions for %s", platform)
		}
	}
	ios := OnboardingInstructions("http://10.77.0.1/")[0]
	if !strings.Contains(strings.Join(ios.Steps, " "), "Certificate Trust Settings") || !strings.Contains(strings.Join(ios.Steps, " "), "http://10.77.0.1/") {
		t.Fatalf("iOS steps omit trust settings or the page URL: %v", ios.Steps)
	}
}
