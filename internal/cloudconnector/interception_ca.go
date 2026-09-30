package cloudconnector

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type PublicInterceptionCA struct {
	CertificatePEM    string    `json:"certificate_pem"`
	SHA256Fingerprint string    `json:"sha256_fingerprint"`
	NotAfter          time.Time `json:"not_after"`
}

func LoadPublicInterceptionCA(publicRoot string) (PublicInterceptionCA, error) {
	publicRoot = strings.TrimSpace(publicRoot)
	if publicRoot == "" || !filepath.IsAbs(publicRoot) {
		return PublicInterceptionCA{}, errors.New("public interception CA root must be absolute")
	}
	certificateData, err := os.ReadFile(filepath.Join(publicRoot, "interception-ca.pem"))
	if err != nil {
		return PublicInterceptionCA{}, err
	}
	if len(certificateData) > 64<<10 {
		return PublicInterceptionCA{}, errors.New("public interception CA certificate exceeds maximum size")
	}
	block, rest := pem.Decode(certificateData)
	if block == nil || block.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		return PublicInterceptionCA{}, errors.New("public interception CA must contain exactly one certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !certificate.IsCA || certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
		return PublicInterceptionCA{}, errors.New("public interception CA is invalid")
	}
	fingerprintBytes := sha256.Sum256(certificate.Raw)
	fingerprint := hex.EncodeToString(fingerprintBytes[:])
	statusData, err := os.ReadFile(filepath.Join(publicRoot, "interception-ca.json"))
	if err == nil {
		var status struct {
			SHA256Fingerprint string `json:"sha256_fingerprint"`
			PrivateKeyExport  bool   `json:"private_key_export"`
		}
		if json.Unmarshal(statusData, &status) != nil || status.PrivateKeyExport || status.SHA256Fingerprint != fingerprint {
			return PublicInterceptionCA{}, errors.New("public interception CA status does not match certificate")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return PublicInterceptionCA{}, err
	}
	return PublicInterceptionCA{
		CertificatePEM:    string(pem.EncodeToMemory(block)),
		SHA256Fingerprint: fingerprint,
		NotAfter:          certificate.NotAfter.UTC(),
	}, nil
}
