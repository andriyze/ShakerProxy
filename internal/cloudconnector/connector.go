package cloudconnector

import (
	"bytes"
	"compress/gzip"
	"context"
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
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const ProtocolVersion = "1.0"

const gzipRequestThreshold = 4 << 10

const (
	privateKeyFile  = "sensor-key.pem"
	certificateFile = "sensor-cert.pem"
	stateFile       = "state.json"
)

type HTTPStatusError struct {
	StatusCode int
}

func (e HTTPStatusError) Error() string {
	return fmt.Sprintf("cloud connector request failed with HTTP %d", e.StatusCode)
}

type State struct {
	SchemaVersion   int       `json:"schema_version"`
	CloudURL        string    `json:"cloud_url"`
	SensorID        string    `json:"sensor_id"`
	OrganizationID  string    `json:"organization_id"`
	CertificatePEM  string    `json:"certificate_pem"`
	CertificateEnds time.Time `json:"certificate_expires_at"`
	EnrolledAt      time.Time `json:"enrolled_at"`
}

type EnrollmentRequest struct {
	Token           string `json:"token"`
	Name            string `json:"name"`
	CSRPEM          string `json:"csr_pem"`
	ProtocolVersion string `json:"protocol_version"`
	SoftwareVersion string `json:"software_version"`
	OSVersion       string `json:"os_version,omitempty"`
	KernelVersion   string `json:"kernel_version,omitempty"`
}

type EnrollmentResponse struct {
	SensorID             string    `json:"sensor_id"`
	OrganizationID       string    `json:"organization_id"`
	CertificatePEM       string    `json:"certificate_pem"`
	CertificateExpiresAt time.Time `json:"certificate_expires_at"`
}

type Heartbeat struct {
	ProtocolVersion string         `json:"protocol_version"`
	SensorID        string         `json:"sensor_id"`
	OrganizationID  string         `json:"organization_id"`
	ObservedAt      time.Time      `json:"observed_at"`
	HealthState     string         `json:"health_state"`
	SoftwareVersion string         `json:"software_version"`
	AppliedRevision uint64         `json:"applied_revision"`
	QueueDepth      uint64         `json:"queue_depth"`
	Payload         map[string]any `json:"payload,omitempty"`
}

type Client struct {
	Root       string
	HTTPClient *http.Client
	Now        func() time.Time
}

func (c Client) Enroll(ctx context.Context, cloudURL, token, sensorName, softwareVersion string) (State, error) {
	cloudURL, err := normalizeCloudURL(cloudURL)
	if err != nil {
		return State{}, err
	}
	token = strings.TrimSpace(token)
	sensorName = strings.TrimSpace(sensorName)
	if len(token) < 20 || len(token) > 512 {
		return State{}, errors.New("enrollment token length is invalid")
	}
	if sensorName == "" || len(sensorName) > 128 {
		return State{}, errors.New("sensor name is required and must be at most 128 characters")
	}
	if c.Root == "" {
		return State{}, errors.New("connector state root is required")
	}
	if existing, err := c.LoadState(); err == nil && existing.SensorID != "" {
		return State{}, errors.New("sensor is already enrolled; revoke or remove the existing cloud identity before enrolling again")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return State{}, err
	}
	csrPEM, err := c.ensurePrivateKeyAndCSR(sensorName)
	if err != nil {
		return State{}, err
	}
	request := EnrollmentRequest{Token: token, Name: sensorName, CSRPEM: csrPEM, ProtocolVersion: ProtocolVersion, SoftwareVersion: softwareVersion}
	var response EnrollmentResponse
	if err := c.doJSON(ctx, http.MethodPost, cloudURL+"/connector/v1/enroll", request, &response, nil); err != nil {
		return State{}, err
	}
	if err := validateEnrollmentResponse(response, csrPEM); err != nil {
		return State{}, err
	}
	now := c.now()
	state := State{SchemaVersion: 1, CloudURL: cloudURL, SensorID: response.SensorID, OrganizationID: response.OrganizationID, CertificatePEM: response.CertificatePEM, CertificateEnds: response.CertificateExpiresAt, EnrolledAt: now}
	if err := c.saveCertificate(response.CertificatePEM); err != nil {
		return State{}, err
	}
	if err := c.installEnrollmentIdentity(response.CertificatePEM); err != nil {
		return State{}, err
	}
	if err := c.saveState(state); err != nil {
		return State{}, err
	}
	return state, nil
}

func (c Client) SendHeartbeat(ctx context.Context, heartbeat Heartbeat) error {
	state, err := c.LoadState()
	if err != nil {
		return err
	}
	if state.SensorID == "" || state.OrganizationID == "" {
		return errors.New("sensor enrollment state is incomplete")
	}
	identity, leaf, err := c.loadCurrentIdentity()
	if err != nil {
		return fmt.Errorf("load sensor mTLS identity: %w", err)
	}
	if !leaf.NotAfter.After(c.now()) {
		return errors.New("sensor certificate has expired")
	}
	client, err := c.clientWithIdentity(identity)
	if err != nil {
		return err
	}
	heartbeat.ProtocolVersion = ProtocolVersion
	heartbeat.SensorID = state.SensorID
	heartbeat.OrganizationID = state.OrganizationID
	if heartbeat.ObservedAt.IsZero() {
		heartbeat.ObservedAt = c.now()
	}
	if heartbeat.HealthState == "" {
		heartbeat.HealthState = "ONLINE"
	}
	return c.doJSONWithClient(ctx, client, http.MethodPost, state.CloudURL+"/connector/v1/heartbeat", heartbeat, nil, nil)
}

func (c Client) LoadState() (State, error) {
	data, err := os.ReadFile(filepath.Join(c.Root, stateFile))
	if err != nil {
		return State{}, err
	}
	if len(data) > 64<<10 {
		return State{}, errors.New("connector state exceeds maximum size")
	}
	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return State{}, fmt.Errorf("decode connector state: %w", err)
	}
	if state.SchemaVersion != 1 {
		return State{}, errors.New("unsupported connector state schema")
	}
	return state, nil
}

func (c Client) ensurePrivateKeyAndCSR(commonName string) (string, error) {
	if err := os.MkdirAll(c.Root, 0o700); err != nil {
		return "", fmt.Errorf("create connector state directory: %w", err)
	}
	keyPath := filepath.Join(c.Root, privateKeyFile)
	var key *ecdsa.PrivateKey
	if data, err := os.ReadFile(keyPath); err == nil {
		block, _ := pem.Decode(data)
		if block == nil || block.Type != "EC PRIVATE KEY" {
			return "", errors.New("sensor private key file is invalid")
		}
		parsed, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return "", fmt.Errorf("parse sensor private key: %w", err)
		}
		key = parsed
	} else if errors.Is(err, os.ErrNotExist) {
		generated, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return "", err
		}
		encoded, err := x509.MarshalECPrivateKey(generated)
		if err != nil {
			return "", err
		}
		if err := atomicWrite(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: encoded}), 0o600); err != nil {
			return "", err
		}
		key = generated
	} else {
		return "", err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}}, key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})), nil
}

func validateEnrollmentResponse(response EnrollmentResponse, csrPEM string) error {
	if response.SensorID == "" || response.OrganizationID == "" || response.CertificatePEM == "" || response.CertificateExpiresAt.IsZero() {
		return errors.New("cloud enrollment response is incomplete")
	}
	csrBlock, _ := pem.Decode([]byte(csrPEM))
	certBlock, _ := pem.Decode([]byte(response.CertificatePEM))
	if csrBlock == nil || certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return errors.New("cloud enrollment certificate is invalid")
	}
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return err
	}
	csrKey, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return err
	}
	certKey, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return err
	}
	if !bytes.Equal(csrKey, certKey) {
		return errors.New("issued certificate does not match the locally generated sensor private key")
	}
	return nil
}

func (c Client) saveCertificate(value string) error {
	return atomicWrite(filepath.Join(c.Root, certificateFile), []byte(value), 0o600)
}

func (c Client) saveState(state State) error {
	encoded, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(c.Root, stateFile), append(encoded, '\n'), 0o600)
}

func (c Client) doJSON(ctx context.Context, method, endpoint string, request, response any, headers http.Header) error {
	client := c.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return c.doJSONWithClient(ctx, client, method, endpoint, request, response, headers)
}

func (c Client) doJSONWithClient(ctx context.Context, client *http.Client, method, endpoint string, request, response any, headers http.Header) error {
	return c.doJSONWithClientLimit(ctx, client, method, endpoint, request, response, headers, 128<<10)
}

func (c Client) doJSONWithClientLimit(ctx context.Context, client *http.Client, method, endpoint string, request, response any, headers http.Header, maximumRequestBytes int) error {
	return c.doJSONWithClientLimitAndCompression(ctx, client, method, endpoint, request, response, headers, maximumRequestBytes, false)
}

func (c Client) doCompressedJSONWithClientLimit(ctx context.Context, client *http.Client, method, endpoint string, request, response any, headers http.Header, maximumRequestBytes int) error {
	return c.doJSONWithClientLimitAndCompression(ctx, client, method, endpoint, request, response, headers, maximumRequestBytes, true)
}

func (c Client) doJSONWithClientLimitAndCompression(ctx context.Context, client *http.Client, method, endpoint string, request, response any, headers http.Header, maximumRequestBytes int, allowCompression bool) error {
	var body io.Reader
	contentEncoding := ""
	if request != nil {
		encoded, err := json.Marshal(request)
		if err != nil {
			return err
		}
		if maximumRequestBytes <= 0 || maximumRequestBytes > 2<<20 {
			return errors.New("connector request limit is invalid")
		}
		if len(encoded) > maximumRequestBytes {
			return errors.New("connector request exceeds maximum size")
		}
		if allowCompression && len(encoded) >= gzipRequestThreshold {
			var compressed bytes.Buffer
			writer, err := gzip.NewWriterLevel(&compressed, gzip.BestSpeed)
			if err != nil {
				return fmt.Errorf("create connector request compressor: %w", err)
			}
			writer.Header.ModTime = time.Unix(0, 0)
			if _, err := writer.Write(encoded); err != nil {
				return fmt.Errorf("compress connector request: %w", err)
			}
			if err := writer.Close(); err != nil {
				return fmt.Errorf("finish connector request compression: %w", err)
			}
			if compressed.Len() < len(encoded) && compressed.Len() <= maximumRequestBytes {
				encoded = compressed.Bytes()
				contentEncoding = "gzip"
			}
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if contentEncoding != "" {
		req.Header.Set("Content-Encoding", contentEncoding)
	}
	for key, values := range headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	limited := io.LimitReader(resp.Body, 256<<10)
	data, err := io.ReadAll(limited)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return HTTPStatusError{StatusCode: resp.StatusCode}
	}
	if response != nil && len(data) != 0 {
		if err := json.Unmarshal(data, response); err != nil {
			return fmt.Errorf("decode cloud connector response: %w", err)
		}
	}
	return nil
}

func normalizeCloudURL(value string) (string, error) {
	parsed, err := url.Parse(strings.TrimRight(strings.TrimSpace(value), "/"))
	if err != nil || parsed.Host == "" {
		return "", errors.New("cloud URL is invalid")
	}
	if parsed.Scheme != "https" {
		if !(parsed.Scheme == "http" && (parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "localhost")) {
			return "", errors.New("cloud URL must use HTTPS; plain HTTP is allowed only for loopback development")
		}
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("cloud URL must not include credentials, query parameters, or fragments")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	return parsed.String(), nil
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".shakerproxy-cloud-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

func PublicKeyFingerprint(csrPEM string) (string, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return "", errors.New("invalid CSR")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return "", err
	}
	publicKey, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(publicKey)
	return hex.EncodeToString(digest[:]), nil
}

func (c Client) now() time.Time {
	if c.Now != nil {
		return c.Now().UTC()
	}
	return time.Now().UTC()
}
