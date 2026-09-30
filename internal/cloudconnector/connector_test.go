package cloudconnector

import (
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNormalizeCloudURLRequiresHTTPSOutsideLoopback(t *testing.T) {
	if _, err := normalizeCloudURL("http://cloud.example.test"); err == nil {
		t.Fatal("expected non-loopback HTTP cloud URL to be rejected")
	}
	if got, err := normalizeCloudURL("http://127.0.0.1:8090/"); err != nil || got != "http://127.0.0.1:8090" {
		t.Fatalf("unexpected loopback normalization: %q %v", got, err)
	}
}

func TestCompressedJSONRequestUsesGzipForMetadataSizedPayload(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Encoding") != "gzip" {
			http.Error(w, "request was not compressed", http.StatusBadRequest)
			return
		}
		reader, err := gzip.NewReader(r.Body)
		if err != nil {
			http.Error(w, "invalid gzip body", http.StatusBadRequest)
			return
		}
		decompressed, err := io.ReadAll(reader)
		if err != nil || reader.Close() != nil {
			http.Error(w, "could not decompress body", http.StatusBadRequest)
			return
		}
		var request map[string]string
		if err := json.Unmarshal(decompressed, &request); err != nil || len(request["events"]) != 8192 {
			http.Error(w, "unexpected JSON body", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]bool{"accepted": true})
	}))
	defer server.Close()

	var response map[string]bool
	client := Client{}
	err := client.doCompressedJSONWithClientLimit(
		t.Context(),
		server.Client(),
		http.MethodPost,
		server.URL,
		map[string]string{"events": string(make([]byte, 8192))},
		&response,
		nil,
		MaxMetadataRequestBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !response["accepted"] {
		t.Fatal("compressed request response was not decoded")
	}
}

func TestEnrollPersistsCertificateMatchingLocalKey(t *testing.T) {
	root := t.TempDir()
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuerTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test issuer"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/connector/v1/enroll" {
			http.NotFound(w, r)
			return
		}
		var request EnrollmentRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		block, _ := pem.Decode([]byte(request.CSRPEM))
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil || csr.CheckSignature() != nil {
			http.Error(w, "bad csr", http.StatusBadRequest)
			return
		}
		expires := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)
		leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "sensor-1"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: expires, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
		der, err := x509.CreateCertificate(rand.Reader, leaf, issuer, csr.PublicKey, issuerKey)
		if err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(EnrollmentResponse{SensorID: "sensor-1", OrganizationID: "org-1", CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), CertificateExpiresAt: expires})
	}))
	defer server.Close()

	client := Client{Root: root, HTTPClient: server.Client()}
	state, err := client.Enroll(t.Context(), server.URL, "01234567890123456789012345678901", "lab-1", "0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	if state.SensorID != "sensor-1" || state.OrganizationID != "org-1" {
		t.Fatalf("unexpected state: %+v", state)
	}
	if _, err := client.Enroll(t.Context(), server.URL, "01234567890123456789012345678901", "lab-1", "0.1.0"); err == nil {
		t.Fatal("expected duplicate local enrollment to be rejected")
	}
}
