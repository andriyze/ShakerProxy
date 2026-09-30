// Package interceptionpki owns the TLS interception authority used only by
// mitmproxy. It is deliberately separate from ShakerProxy management and cloud
// connector identities. Only public projections are exposed to the Web UI.
package interceptionpki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	SchemaVersion = 1
	Purpose       = "tls-interception"
)

type Options struct {
	PrivateRoot  string
	PublicRoot   string
	CommonName   string
	Now          time.Time
	KeyBits      int
	PrivateOwner *FileOwner
}

type FileOwner struct {
	UID int
	GID int
}

type Status struct {
	SchemaVersion     int       `json:"schema_version"`
	Purpose           string    `json:"purpose"`
	CommonName        string    `json:"common_name"`
	SHA256Fingerprint string    `json:"sha256_fingerprint"`
	Serial            string    `json:"serial"`
	NotBefore         time.Time `json:"not_before"`
	NotAfter          time.Time `json:"not_after"`
	PEMPath           string    `json:"pem_path"`
	DERPath           string    `json:"der_path"`
	PrivateKeyExport  bool      `json:"private_key_export"`
}

func Ensure(options Options) (Status, error) {
	if err := normalizeOptions(&options); err != nil {
		return Status{}, err
	}
	if err := os.MkdirAll(options.PrivateRoot, 0o700); err != nil {
		return Status{}, fmt.Errorf("create interception PKI private root: %w", err)
	}
	if err := os.MkdirAll(options.PublicRoot, 0o755); err != nil {
		return Status{}, fmt.Errorf("create interception PKI public root: %w", err)
	}
	bundlePath := filepath.Join(options.PrivateRoot, "mitmproxy-ca.pem")
	certificatePath := filepath.Join(options.PrivateRoot, "mitmproxy-ca-cert.pem")
	derPath := filepath.Join(options.PrivateRoot, "mitmproxy-ca-cert.cer")

	if info, err := os.Lstat(bundlePath); err == nil {
		if !info.Mode().IsRegular() {
			return Status{}, errors.New("interception CA bundle is not a regular file")
		}
		bundle, err := os.ReadFile(bundlePath)
		if err != nil {
			return Status{}, fmt.Errorf("read interception CA bundle: %w", err)
		}
		certificate, privateKey, err := parseBundle(bundle)
		if err != nil {
			return Status{}, fmt.Errorf("existing interception CA is corrupt: %w", err)
		}
		if certificate.NotAfter.Before(options.Now.Add(30 * 24 * time.Hour)) {
			return Status{}, errors.New("interception CA expires within 30 days; explicit rotation is required")
		}
		if err := verifyKeyPair(certificate, privateKey); err != nil {
			return Status{}, err
		}
		if err := securePrivateBundle(bundlePath, options.PrivateOwner); err != nil {
			return Status{}, err
		}
		return project(options, certificate, bundle, certificatePath, derPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return Status{}, fmt.Errorf("read interception CA bundle: %w", err)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, options.KeyBits)
	if err != nil {
		return Status{}, fmt.Errorf("generate interception CA key: %w", err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 160)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return Status{}, err
	}
	if serial.Sign() == 0 {
		serial = big.NewInt(1)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   options.CommonName,
			Organization: []string{"ShakerProxy Local Sensor"},
		},
		NotBefore:             options.Now.Add(-5 * time.Minute),
		NotAfter:              options.Now.AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SubjectKeyId:          subjectKeyID(&privateKey.PublicKey),
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return Status{}, fmt.Errorf("create interception CA certificate: %w", err)
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		return Status{}, err
	}
	privateKeyDER := x509.MarshalPKCS1PrivateKey(privateKey)
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privateKeyDER})
	bundle := append(append([]byte{}, certificatePEM...), privateKeyPEM...)
	if err := atomicWriteOwned(bundlePath, bundle, 0o400, options.PrivateOwner); err != nil {
		return Status{}, fmt.Errorf("persist interception CA bundle: %w", err)
	}
	return project(options, certificate, bundle, certificatePath, derPath)
}

func LoadPublicStatus(publicRoot string) (Status, error) {
	data, err := os.ReadFile(filepath.Join(publicRoot, "interception-ca.json"))
	if err != nil {
		return Status{}, err
	}
	if len(data) > 64<<10 {
		return Status{}, errors.New("interception CA status exceeds maximum size")
	}
	var status Status
	if err := json.Unmarshal(data, &status); err != nil {
		return Status{}, err
	}
	if status.SchemaVersion != SchemaVersion || status.Purpose != Purpose || status.PrivateKeyExport {
		return Status{}, errors.New("interception CA status is invalid")
	}
	return status, nil
}

func PublicCertificate(publicRoot, format string) ([]byte, string, string, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "pem", "crt":
		data, err := os.ReadFile(filepath.Join(publicRoot, "interception-ca.pem"))
		return data, "application/x-pem-file", "shakerproxy-interception-ca.pem", err
	case "der", "cer":
		data, err := os.ReadFile(filepath.Join(publicRoot, "interception-ca.der"))
		return data, "application/pkix-cert", "shakerproxy-interception-ca.cer", err
	default:
		return nil, "", "", errors.New("unsupported interception CA format")
	}
}

func project(options Options, certificate *x509.Certificate, bundle []byte, certificatePath, derPath string) (Status, error) {
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	if err := atomicWrite(certificatePath, certificatePEM, 0o444); err != nil {
		return Status{}, err
	}
	if err := atomicWrite(derPath, certificate.Raw, 0o444); err != nil {
		return Status{}, err
	}
	if err := atomicWrite(filepath.Join(options.PublicRoot, "interception-ca.pem"), certificatePEM, 0o444); err != nil {
		return Status{}, err
	}
	if err := atomicWrite(filepath.Join(options.PublicRoot, "interception-ca.der"), certificate.Raw, 0o444); err != nil {
		return Status{}, err
	}
	fingerprint := sha256.Sum256(certificate.Raw)
	status := Status{
		SchemaVersion:     SchemaVersion,
		Purpose:           Purpose,
		CommonName:        certificate.Subject.CommonName,
		SHA256Fingerprint: hex.EncodeToString(fingerprint[:]),
		Serial:            certificate.SerialNumber.Text(16),
		NotBefore:         certificate.NotBefore.UTC(),
		NotAfter:          certificate.NotAfter.UTC(),
		PEMPath:           filepath.Join(options.PublicRoot, "interception-ca.pem"),
		DERPath:           filepath.Join(options.PublicRoot, "interception-ca.der"),
		PrivateKeyExport:  false,
	}
	encoded, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return Status{}, err
	}
	if err := atomicWrite(filepath.Join(options.PublicRoot, "interception-ca.json"), append(encoded, '\n'), 0o444); err != nil {
		return Status{}, err
	}
	_ = bundle // Bundle remains private and is intentionally never projected.
	return status, nil
}

func parseBundle(data []byte) (*x509.Certificate, *rsa.PrivateKey, error) {
	var certificate *x509.Certificate
	var privateKey *rsa.PrivateKey
	rest := data
	for len(strings.TrimSpace(string(rest))) != 0 {
		block, remaining := pem.Decode(rest)
		if block == nil {
			return nil, nil, errors.New("interception CA bundle contains invalid PEM")
		}
		switch block.Type {
		case "CERTIFICATE":
			if certificate != nil {
				return nil, nil, errors.New("interception CA bundle contains multiple certificates")
			}
			parsed, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, nil, err
			}
			certificate = parsed
		case "RSA PRIVATE KEY":
			if privateKey != nil {
				return nil, nil, errors.New("interception CA bundle contains multiple private keys")
			}
			parsed, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, nil, err
			}
			privateKey = parsed
		default:
			return nil, nil, fmt.Errorf("interception CA bundle contains unsupported PEM type %q", block.Type)
		}
		rest = remaining
	}
	if certificate == nil || privateKey == nil {
		return nil, nil, errors.New("interception CA bundle is incomplete")
	}
	if !certificate.IsCA || !certificate.BasicConstraintsValid || certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, nil, errors.New("interception certificate is not a signing CA")
	}
	return certificate, privateKey, nil
}

func verifyKeyPair(certificate *x509.Certificate, privateKey *rsa.PrivateKey) error {
	publicKey, ok := certificate.PublicKey.(*rsa.PublicKey)
	if !ok || publicKey.N.Cmp(privateKey.N) != 0 || publicKey.E != privateKey.E {
		return errors.New("interception CA certificate and private key do not match")
	}
	return privateKey.Validate()
}

func normalizeOptions(options *Options) error {
	options.PrivateRoot = strings.TrimSpace(options.PrivateRoot)
	options.PublicRoot = strings.TrimSpace(options.PublicRoot)
	options.CommonName = strings.TrimSpace(options.CommonName)
	if options.PrivateRoot == "" || options.PublicRoot == "" || !filepath.IsAbs(options.PrivateRoot) || !filepath.IsAbs(options.PublicRoot) {
		return errors.New("interception PKI roots must be absolute")
	}
	if options.CommonName == "" {
		options.CommonName = "ShakerProxy Interception CA"
	}
	if len(options.CommonName) > 128 {
		return errors.New("interception CA common name is too long")
	}
	if options.Now.IsZero() {
		options.Now = time.Now().UTC()
	} else {
		options.Now = options.Now.UTC()
	}
	if options.KeyBits == 0 {
		options.KeyBits = 3072
	}
	if options.KeyBits < 2048 || options.KeyBits > 4096 {
		return errors.New("interception CA RSA key size must be between 2048 and 4096 bits")
	}
	if options.PrivateOwner != nil && (options.PrivateOwner.UID < 0 || options.PrivateOwner.GID < 0) {
		return errors.New("interception CA private owner IDs must be non-negative")
	}
	return nil
}

func subjectKeyID(publicKey *rsa.PublicKey) []byte {
	encoded, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil
	}
	digest := sha256.Sum256(encoded)
	return append([]byte(nil), digest[:20]...)
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	return atomicWriteOwned(path, data, mode, nil)
}

func atomicWriteOwned(path string, data []byte, mode os.FileMode, owner *FileOwner) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".shakerproxy-interception-pki-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if owner != nil {
		if err := temporary.Chown(owner.UID, owner.GID); err != nil {
			_ = temporary.Close()
			return err
		}
	}
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
	return nil
}

func securePrivateBundle(path string, owner *FileOwner) error {
	if owner != nil {
		if err := os.Chown(path, owner.UID, owner.GID); err != nil {
			return fmt.Errorf("set interception CA bundle ownership: %w", err)
		}
	}
	if err := os.Chmod(path, 0o400); err != nil {
		return fmt.Errorf("set interception CA bundle permissions: %w", err)
	}
	return nil
}
