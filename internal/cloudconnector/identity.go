package cloudconnector

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const (
	identityFile        = "sensor-identity.pem"
	pendingIdentityFile = "sensor-identity.pending.pem"
)

func (c Client) installEnrollmentIdentity(certificatePEM string) error {
	keyPEM, err := os.ReadFile(filepath.Join(c.Root, privateKeyFile))
	if err != nil {
		return fmt.Errorf("read enrollment private key: %w", err)
	}
	bundle := append([]byte(certificatePEM), keyPEM...)
	if _, _, err := parseIdentityBundle(bundle); err != nil {
		return fmt.Errorf("build sensor identity bundle: %w", err)
	}
	return atomicWrite(filepath.Join(c.Root, identityFile), bundle, 0o600)
}

func (c Client) loadCurrentIdentity() (tls.Certificate, *x509.Certificate, error) {
	path := filepath.Join(c.Root, identityFile)
	if bundle, err := os.ReadFile(path); err == nil {
		return parseIdentityBundle(bundle)
	} else if !errors.Is(err, os.ErrNotExist) {
		return tls.Certificate{}, nil, err
	}

	certificatePEM, certErr := os.ReadFile(filepath.Join(c.Root, certificateFile))
	privateKeyPEM, keyErr := os.ReadFile(filepath.Join(c.Root, privateKeyFile))
	if certErr != nil || keyErr != nil {
		if certErr != nil {
			return tls.Certificate{}, nil, fmt.Errorf("read legacy sensor certificate: %w", certErr)
		}
		return tls.Certificate{}, nil, fmt.Errorf("read legacy sensor private key: %w", keyErr)
	}
	bundle := append(append([]byte{}, certificatePEM...), privateKeyPEM...)
	identity, leaf, err := parseIdentityBundle(bundle)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	if err := atomicWrite(path, bundle, 0o600); err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("migrate sensor identity bundle: %w", err)
	}
	return identity, leaf, nil
}

func (c Client) loadPendingIdentity() (tls.Certificate, *x509.Certificate, error) {
	bundle, err := os.ReadFile(filepath.Join(c.Root, pendingIdentityFile))
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	return parseIdentityBundle(bundle)
}

func parseIdentityBundle(bundle []byte) (tls.Certificate, *x509.Certificate, error) {
	identity, err := tls.X509KeyPair(bundle, bundle)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("parse sensor identity bundle: %w", err)
	}
	if len(identity.Certificate) == 0 {
		return tls.Certificate{}, nil, errors.New("sensor identity bundle has no certificate")
	}
	leaf, err := x509.ParseCertificate(identity.Certificate[0])
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("parse sensor certificate: %w", err)
	}
	identity.Leaf = leaf
	return identity, leaf, nil
}

func identityBundle(certificatePEM string, key *ecdsa.PrivateKey) ([]byte, *x509.Certificate, error) {
	if key == nil {
		return nil, nil, errors.New("sensor private key is required")
	}
	encodedKey, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: encodedKey})
	bundle := append(append([]byte{}, []byte(certificatePEM)...), keyPEM...)
	_, leaf, err := parseIdentityBundle(bundle)
	if err != nil {
		return nil, nil, err
	}
	return bundle, leaf, nil
}

func (c Client) clientWithIdentity(identity tls.Certificate) (*http.Client, error) {
	baseClient := c.HTTPClient
	if baseClient == nil {
		baseClient = &http.Client{Timeout: 15 * time.Second}
	}
	clientCopy := *baseClient
	if clientCopy.Timeout == 0 {
		clientCopy.Timeout = 15 * time.Second
	}

	var transport *http.Transport
	switch configured := baseClient.Transport.(type) {
	case nil:
		transport = http.DefaultTransport.(*http.Transport).Clone()
	case *http.Transport:
		transport = configured.Clone()
	default:
		return nil, errors.New("connector HTTP client transport must be *http.Transport when mTLS is required")
	}
	var tlsConfig *tls.Config
	if transport.TLSClientConfig != nil {
		tlsConfig = transport.TLSClientConfig.Clone()
	} else {
		tlsConfig = &tls.Config{}
	}
	if tlsConfig.MinVersion < tls.VersionTLS13 {
		tlsConfig.MinVersion = tls.VersionTLS13
	}
	tlsConfig.Certificates = []tls.Certificate{identity}
	transport.TLSClientConfig = tlsConfig
	clientCopy.Transport = transport
	return &clientCopy, nil
}

func certificatePEMFromBundle(bundle []byte) (string, error) {
	remaining := bundle
	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			return "", errors.New("sensor identity bundle does not contain a certificate")
		}
		if block.Type == "CERTIFICATE" {
			return string(pem.EncodeToMemory(block)), nil
		}
		remaining = rest
	}
}

func (c Client) reconcileStateWithCurrentIdentity(state State) (State, error) {
	_, leaf, err := c.loadCurrentIdentity()
	if err != nil {
		return State{}, err
	}
	bundle, err := os.ReadFile(filepath.Join(c.Root, identityFile))
	if err != nil {
		return State{}, fmt.Errorf("read active sensor identity: %w", err)
	}
	certificatePEM, err := certificatePEMFromBundle(bundle)
	if err != nil {
		return State{}, err
	}
	expiresAt := leaf.NotAfter.UTC()
	if state.CertificatePEM == certificatePEM && state.CertificateEnds.Equal(expiresAt) {
		return state, nil
	}
	state.CertificatePEM = certificatePEM
	state.CertificateEnds = expiresAt
	if err := c.saveState(state); err != nil {
		return State{}, fmt.Errorf("reconcile connector state with active identity: %w", err)
	}
	return state, nil
}

func (c Client) currentCertificateExpiry() (time.Time, error) {
	_, leaf, err := c.loadCurrentIdentity()
	if err != nil {
		return time.Time{}, err
	}
	return leaf.NotAfter.UTC(), nil
}
