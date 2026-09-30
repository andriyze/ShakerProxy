package cloudconnector

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"
)

const maximumCloudServerCABytes = 1 << 20

func cloudHTTPClient(serverCAFile string) (*http.Client, error) {
	if serverCAFile == "" {
		return nil, nil
	}
	info, err := os.Stat(serverCAFile)
	if err != nil {
		return nil, fmt.Errorf("inspect cloud server CA file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximumCloudServerCABytes {
		return nil, errors.New("cloud server CA file is empty, oversized, or not a regular file")
	}
	pemBytes, err := os.ReadFile(serverCAFile)
	if err != nil {
		return nil, fmt.Errorf("read cloud server CA file: %w", err)
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if !roots.AppendCertsFromPEM(pemBytes) {
		return nil, errors.New("cloud server CA file contains no valid certificates")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}
	return &http.Client{Transport: transport, Timeout: 15 * time.Second}, nil
}
