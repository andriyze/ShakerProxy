package managementpki

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
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	Schema              = 1
	Purpose             = "shakerproxy-management-tls"
	InterceptionPurpose = "shakerproxy-tls-interception"
)

type Options struct {
	EtcRoot  string
	DataRoot string
	EdgeGID  int
	Now      time.Time
	Testing  bool
}

type Status struct {
	Schema              int       `json:"schema"`
	Purpose             string    `json:"purpose"`
	Authority           string    `json:"authority"`
	Subject             string    `json:"subject"`
	Serial              string    `json:"serial"`
	SHA256Fingerprint   string    `json:"sha256_fingerprint"`
	NotBefore           time.Time `json:"not_before"`
	NotAfter            time.Time `json:"not_after"`
	LeafNotAfter        time.Time `json:"leaf_not_after"`
	InterceptionCAState string    `json:"interception_ca_state"`
}

type purposeMarker struct {
	Schema  int    `json:"schema"`
	Purpose string `json:"purpose"`
	State   string `json:"state"`
	Warning string `json:"warning"`
}

func Ensure(options Options) (Status, error) {
	if options.EtcRoot == "" || options.DataRoot == "" {
		return Status{}, errors.New("PKI roots are required")
	}
	if !filepath.IsAbs(options.EtcRoot) || !filepath.IsAbs(options.DataRoot) {
		return Status{}, errors.New("PKI roots must be absolute")
	}
	if options.EdgeGID < 0 && !options.Testing {
		return Status{}, errors.New("edge group ID is required")
	}
	if options.Now.IsZero() {
		options.Now = time.Now().UTC()
	}
	managementDir := filepath.Join(options.EtcRoot, "pki", "management")
	interceptionDir := filepath.Join(options.EtcRoot, "pki", "interception")
	publicDir := filepath.Join(options.DataRoot, "public")
	for _, item := range []struct {
		path string
		mode os.FileMode
	}{{managementDir, 0o750}, {interceptionDir, 0o700}, {publicDir, 0o755}} {
		if err := secureDirectory(item.path, item.mode); err != nil {
			return Status{}, err
		}
	}
	if !options.Testing {
		if err := os.Chown(managementDir, 0, options.EdgeGID); err != nil {
			return Status{}, err
		}
	}
	markerPath := filepath.Join(interceptionDir, "purpose.json")
	marker := purposeMarker{Schema: Schema, Purpose: InterceptionPurpose, State: "unprovisioned", Warning: "Never reuse the management CA for traffic interception."}
	if err := ensureJSON(markerPath, marker, 0o600); err != nil {
		return Status{}, err
	}

	rootCertPath := filepath.Join(managementDir, "root-ca.crt")
	rootKeyPath := filepath.Join(managementDir, "root-ca.key")
	rootCert, rootKey, err := ensureRoot(rootCertPath, rootKeyPath, options.Now)
	if err != nil {
		return Status{}, err
	}
	if err := validateSeparation(rootCert, interceptionDir); err != nil {
		return Status{}, err
	}
	leafCert, err := ensureLeaf(managementDir, rootCert, rootKey, options)
	if err != nil {
		return Status{}, err
	}
	status := statusFor(rootCert, leafCert)
	if err := atomicCopy(rootCertPath, filepath.Join(publicDir, "management-ca.crt"), 0o644); err != nil {
		return Status{}, err
	}
	if err := writeJSON(filepath.Join(publicDir, "management-pki.json"), status, 0o644); err != nil {
		return Status{}, err
	}
	if err := writeJSON(filepath.Join(managementDir, "status.json"), status, 0o444); err != nil {
		return Status{}, err
	}
	if !options.Testing {
		for _, item := range []struct {
			path string
			gid  int
		}{
			{rootCertPath, 0}, {rootKeyPath, 0}, {markerPath, 0},
			{filepath.Join(publicDir, "management-ca.crt"), 0},
			{filepath.Join(publicDir, "management-pki.json"), 0},
			{filepath.Join(managementDir, "status.json"), 0},
		} {
			if err := os.Chown(item.path, 0, item.gid); err != nil {
				return Status{}, err
			}
		}
	}
	return status, nil
}

func LoadPublic(certPath, statusPath string) ([]byte, Status, error) {
	certificatePEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, Status{}, fmt.Errorf("read management CA: %w", err)
	}
	certificate, err := parseCertificate(certificatePEM)
	if err != nil {
		return nil, Status{}, err
	}
	if err := validateRoot(certificate); err != nil {
		return nil, Status{}, err
	}
	data, err := os.ReadFile(statusPath)
	if err != nil {
		return nil, Status{}, fmt.Errorf("read management PKI metadata: %w", err)
	}
	var status Status
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&status); err != nil {
		return nil, Status{}, fmt.Errorf("decode management PKI metadata: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, Status{}, errors.New("management PKI metadata contains trailing data")
	}
	if status.Schema != Schema || status.Purpose != Purpose || status.Authority != "management-only" || status.InterceptionCAState != "separate-authority" || status.Subject != certificate.Subject.String() || status.Serial != certificate.SerialNumber.Text(16) || status.SHA256Fingerprint != fingerprint(certificate.Raw) || !status.NotBefore.Equal(certificate.NotBefore) || !status.NotAfter.Equal(certificate.NotAfter) {
		return nil, Status{}, errors.New("management PKI metadata does not match the certificate")
	}
	return certificatePEM, status, nil
}

func ensureRoot(certPath, keyPath string, now time.Time) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certExists := regularExists(certPath)
	keyExists := regularExists(keyPath)
	if certExists != keyExists {
		return nil, nil, errors.New("management CA certificate/key pair is incomplete")
	}
	if certExists {
		certPEM, err := os.ReadFile(certPath)
		if err != nil {
			return nil, nil, err
		}
		keyPEM, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, nil, err
		}
		cert, err := parseCertificate(certPEM)
		if err != nil {
			return nil, nil, err
		}
		key, err := parseECKey(keyPEM)
		if err != nil {
			return nil, nil, err
		}
		if err := validateRoot(cert); err != nil {
			return nil, nil, err
		}
		if !cert.PublicKey.(*ecdsa.PublicKey).Equal(&key.PublicKey) {
			return nil, nil, errors.New("management CA certificate and key do not match")
		}
		if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			return nil, nil, errors.New("existing management CA is not currently valid")
		}
		if err := os.Chmod(certPath, 0o444); err != nil {
			return nil, nil, err
		}
		if err := os.Chmod(keyPath, 0o400); err != nil {
			return nil, nil, err
		}
		return cert, key, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{Organization: []string{"ShakerProxy"}, OrganizationalUnit: []string{"Management Plane"}, CommonName: "ShakerProxy Management Root CA"},
		NotBefore:    now.Add(-5 * time.Minute), NotAfter: now.AddDate(10, 0, 0),
		IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	if err := atomicWrite(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o400); err != nil {
		return nil, nil, err
	}
	if err := atomicWrite(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o444); err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	return cert, key, err
}

func ensureLeaf(managementDir string, root *x509.Certificate, rootKey *ecdsa.PrivateKey, options Options) (*x509.Certificate, error) {
	current := filepath.Join(managementDir, "current")
	if target, err := os.Readlink(current); err == nil {
		if filepath.IsAbs(target) || strings.Contains(target, "..") || filepath.Dir(target) != "." {
			return nil, errors.New("management TLS current link is unsafe")
		}
		leafDir := filepath.Join(managementDir, target)
		cert, _, err := loadLeaf(filepath.Join(leafDir, "tls.crt"), filepath.Join(leafDir, "tls.key"), root)
		if err != nil {
			return nil, err
		}
		if options.Now.Before(cert.NotAfter.Add(-30 * 24 * time.Hour)) {
			if err := repairLeafModes(leafDir, options); err != nil {
				return nil, err
			}
			return cert, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect management TLS current link: %w", err)
	}
	version := fmt.Sprintf("leaf-%s", options.Now.UTC().Format("20060102T150405Z"))
	leafDir := filepath.Join(managementDir, version)
	if err := secureDirectory(leafDir, 0o750); err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{Organization: []string{"ShakerProxy"}, OrganizationalUnit: []string{"Management Plane"}, CommonName: "shakerproxy.local"},
		NotBefore:    options.Now.Add(-5 * time.Minute), NotAfter: options.Now.AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"shakerproxy.local", "localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, root, &key.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := atomicWrite(filepath.Join(leafDir, "tls.key"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o440); err != nil {
		return nil, err
	}
	if err := atomicWrite(filepath.Join(leafDir, "tls.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o444); err != nil {
		return nil, err
	}
	if err := repairLeafModes(leafDir, options); err != nil {
		return nil, err
	}
	temporary := current + ".new"
	_ = os.Remove(temporary)
	if err := os.Symlink(version, temporary); err != nil {
		return nil, err
	}
	if err := os.Rename(temporary, current); err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func loadLeaf(certPath, keyPath string, root *x509.Certificate) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, err
	}
	cert, err := parseCertificate(certPEM)
	if err != nil {
		return nil, nil, err
	}
	key, err := parseECKey(keyPEM)
	if err != nil {
		return nil, nil, err
	}
	if cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign != 0 || len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		return nil, nil, errors.New("management leaf has invalid purpose constraints")
	}
	publicKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !publicKey.Equal(&key.PublicKey) {
		return nil, nil, errors.New("management leaf certificate and key do not match")
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, DNSName: "shakerproxy.local", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return nil, nil, fmt.Errorf("verify management leaf: %w", err)
	}
	return cert, key, nil
}

func validateRoot(cert *x509.Certificate) error {
	publicKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() {
		return errors.New("management CA must use ECDSA P-256")
	}
	if !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign || len(cert.Subject.OrganizationalUnit) != 1 || cert.Subject.OrganizationalUnit[0] != "Management Plane" {
		return errors.New("management CA has invalid purpose constraints")
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		return errors.New("management CA is not self-signed")
	}
	return nil
}

func validateSeparation(management *x509.Certificate, interceptionDir string) error {
	entries, err := os.ReadDir(interceptionDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || entry.Name() == "purpose.json" {
			continue
		}
		path := filepath.Join(interceptionDir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		block, _ := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("invalid interception certificate %s", path)
		}
		if sha256.Sum256(cert.RawSubjectPublicKeyInfo) == sha256.Sum256(management.RawSubjectPublicKeyInfo) {
			return errors.New("management and interception authorities reuse the same public key")
		}
	}
	return nil
}

func statusFor(root, leaf *x509.Certificate) Status {
	return Status{Schema: Schema, Purpose: Purpose, Authority: "management-only", Subject: root.Subject.String(), Serial: root.SerialNumber.Text(16), SHA256Fingerprint: fingerprint(root.Raw), NotBefore: root.NotBefore.UTC(), NotAfter: root.NotAfter.UTC(), LeafNotAfter: leaf.NotAfter.UTC(), InterceptionCAState: "separate-authority"}
}

func fingerprint(raw []byte) string {
	sum := sha256.Sum256(raw)
	encoded := strings.ToUpper(hex.EncodeToString(sum[:]))
	parts := make([]string, 0, len(encoded)/2)
	for i := 0; i < len(encoded); i += 2 {
		parts = append(parts, encoded[i:i+2])
	}
	return strings.Join(parts, ":")
}

func parseCertificate(data []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("invalid certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func parseECKey(data []byte) (*ecdsa.PrivateKey, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "EC PRIVATE KEY" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("invalid EC private key PEM")
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, err
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	return serial, nil
}

func regularExists(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular()
}

func secureDirectory(path string, mode os.FileMode) error {
	if info, err := os.Lstat(path); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing unsafe directory: %s", path)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	} else if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

func repairLeafModes(directory string, options Options) error {
	if err := os.Chmod(directory, 0o750); err != nil {
		return err
	}
	if err := os.Chmod(filepath.Join(directory, "tls.crt"), 0o444); err != nil {
		return err
	}
	if err := os.Chmod(filepath.Join(directory, "tls.key"), 0o440); err != nil {
		return err
	}
	if !options.Testing {
		if err := os.Chown(directory, 0, options.EdgeGID); err != nil {
			return err
		}
		if err := os.Chown(filepath.Join(directory, "tls.key"), 0, options.EdgeGID); err != nil {
			return err
		}
		if err := os.Chown(filepath.Join(directory, "tls.crt"), 0, 0); err != nil {
			return err
		}
	}
	return nil
}

func ensureJSON(path string, value any, mode os.FileMode) error {
	if data, err := os.ReadFile(path); err == nil {
		var actual purposeMarker
		if json.Unmarshal(data, &actual) != nil || actual != value {
			return fmt.Errorf("existing purpose marker is invalid: %s", path)
		}
		return os.Chmod(path, mode)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return writeJSON(path, value, mode)
}

func writeJSON(path string, value any, mode os.FileMode) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(path, append(data, '\n'), mode)
}

func atomicCopy(source, target string, mode os.FileMode) error {
	data, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	if existing, err := os.ReadFile(target); err == nil && string(existing) == string(data) {
		return os.Chmod(target, mode)
	}
	return atomicWrite(target, data, mode)
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return fmt.Errorf("refusing unsafe target: %s", path)
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".shakerproxy-pki-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
