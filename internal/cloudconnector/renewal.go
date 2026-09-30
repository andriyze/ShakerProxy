package cloudconnector

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const DefaultRenewBefore = 8 * time.Hour

type RenewalRequest struct {
	ProtocolVersion string `json:"protocol_version"`
	SensorID        string `json:"sensor_id"`
	OrganizationID  string `json:"organization_id"`
	CSRPEM          string `json:"csr_pem"`
}

type RenewalResponse struct {
	CertificatePEM       string    `json:"certificate_pem"`
	CertificateExpiresAt time.Time `json:"certificate_expires_at"`
	ProtocolVersion      string    `json:"protocol_version"`
	ActivationRequired   bool      `json:"activation_required"`
}

type ActivationRequest struct {
	ProtocolVersion string `json:"protocol_version"`
	SensorID        string `json:"sensor_id"`
	OrganizationID  string `json:"organization_id"`
}

type ActivationResponse struct {
	Activated       bool   `json:"activated"`
	ProtocolVersion string `json:"protocol_version"`
}

// EnsureCertificate resumes any interrupted activation first, then rotates the
// local private key and certificate when the active certificate enters the
// renewal window. The old identity remains authoritative until the cloud has
// accepted proof of possession of the newly issued key.
func (c Client) EnsureCertificate(ctx context.Context, renewBefore time.Duration) (bool, error) {
	state, err := c.LoadState()
	if err != nil {
		return false, err
	}
	if state.SensorID == "" || state.OrganizationID == "" {
		return false, errors.New("sensor enrollment state is incomplete")
	}
	state, err = c.reconcileStateWithCurrentIdentity(state)
	if err != nil {
		return false, err
	}
	if renewBefore <= 0 {
		renewBefore = DefaultRenewBefore
	}
	if renewBefore < time.Hour || renewBefore > 12*time.Hour {
		return false, errors.New("certificate renewal window must be between one and twelve hours")
	}

	if _, err := os.Stat(filepath.Join(c.Root, pendingIdentityFile)); err == nil {
		if err := c.activatePendingIdentity(ctx, state); err != nil {
			return true, err
		}
		return true, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}

	identity, leaf, err := c.loadCurrentIdentity()
	if err != nil {
		return false, err
	}
	now := c.now()
	if !leaf.NotAfter.After(now) {
		return false, errors.New("sensor certificate has expired and cannot be renewed with mTLS")
	}
	if leaf.NotAfter.Sub(now) > renewBefore {
		return false, nil
	}
	if err := c.prepareAndActivateRenewal(ctx, state, identity); err != nil {
		return true, err
	}
	return true, nil
}

func (c Client) prepareAndActivateRenewal(ctx context.Context, state State, currentIdentity tls.Certificate) error {
	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate renewed sensor key: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: state.SensorID},
	}, newKey)
	if err != nil {
		return fmt.Errorf("create renewed sensor CSR: %w", err)
	}
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
	request := RenewalRequest{
		ProtocolVersion: ProtocolVersion,
		SensorID:        state.SensorID,
		OrganizationID:  state.OrganizationID,
		CSRPEM:          csrPEM,
	}
	client, err := c.clientWithIdentity(currentIdentity)
	if err != nil {
		return err
	}
	var response RenewalResponse
	if err := c.doJSONWithClient(ctx, client, http.MethodPost, state.CloudURL+"/connector/v1/renew", request, &response, nil); err != nil {
		return fmt.Errorf("request sensor certificate renewal: %w", err)
	}
	if response.ProtocolVersion != ProtocolVersion || !response.ActivationRequired || response.CertificatePEM == "" || response.CertificateExpiresAt.IsZero() {
		return errors.New("cloud certificate renewal response is incomplete")
	}
	bundle, leaf, err := identityBundle(response.CertificatePEM, newKey)
	if err != nil {
		return fmt.Errorf("validate renewed sensor identity: %w", err)
	}
	if !leaf.NotAfter.After(c.now().Add(time.Hour)) {
		return errors.New("renewed sensor certificate expires too soon")
	}
	if response.CertificateExpiresAt.Sub(leaf.NotAfter.UTC()) > time.Second || leaf.NotAfter.UTC().Sub(response.CertificateExpiresAt) > time.Second {
		return errors.New("renewal response expiry does not match the issued certificate")
	}
	if err := atomicWrite(filepath.Join(c.Root, pendingIdentityFile), bundle, 0o600); err != nil {
		return fmt.Errorf("persist pending sensor identity: %w", err)
	}
	return c.activatePendingIdentity(ctx, state)
}

func (c Client) activatePendingIdentity(ctx context.Context, state State) error {
	identity, _, err := c.loadPendingIdentity()
	if err != nil {
		return fmt.Errorf("load pending sensor identity: %w", err)
	}
	client, err := c.clientWithIdentity(identity)
	if err != nil {
		return err
	}
	request := ActivationRequest{
		ProtocolVersion: ProtocolVersion,
		SensorID:        state.SensorID,
		OrganizationID:  state.OrganizationID,
	}
	var response ActivationResponse
	if err := c.doJSONWithClient(ctx, client, http.MethodPost, state.CloudURL+"/connector/v1/activate", request, &response, nil); err != nil {
		return fmt.Errorf("activate renewed sensor certificate: %w", err)
	}
	if !response.Activated || response.ProtocolVersion != ProtocolVersion {
		return errors.New("cloud did not confirm renewed certificate activation")
	}
	return c.commitPendingIdentity(state)
}

func (c Client) commitPendingIdentity(state State) error {
	pendingPath := filepath.Join(c.Root, pendingIdentityFile)
	bundle, err := os.ReadFile(pendingPath)
	if err != nil {
		return err
	}
	_, leaf, err := parseIdentityBundle(bundle)
	if err != nil {
		return err
	}
	certificatePEM, err := certificatePEMFromBundle(bundle)
	if err != nil {
		return err
	}
	currentPath := filepath.Join(c.Root, identityFile)
	if err := os.Rename(pendingPath, currentPath); err != nil {
		return fmt.Errorf("activate local sensor identity: %w", err)
	}
	if directory, err := os.Open(c.Root); err == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
	state.CertificatePEM = certificatePEM
	state.CertificateEnds = leaf.NotAfter.UTC()
	if err := c.saveState(state); err != nil {
		return fmt.Errorf("persist renewed sensor state: %w", err)
	}
	// These files are enrollment-era compatibility artifacts. Once an atomic
	// identity bundle has been rotated successfully, retaining the obsolete key
	// only increases secret material on disk.
	_ = os.Remove(filepath.Join(c.Root, privateKeyFile))
	_ = os.Remove(filepath.Join(c.Root, certificateFile))
	return nil
}
