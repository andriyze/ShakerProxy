package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"shakerproxy.dev/shakerproxy/internal/interceptionpki"
)

func provisionCA(t *testing.T) string {
	t.Helper()
	publicRoot := filepath.Join(t.TempDir(), "public")
	if _, err := interceptionpki.Ensure(interceptionpki.Options{PrivateRoot: filepath.Join(t.TempDir(), "private"), PublicRoot: publicRoot, KeyBits: 2048}); err != nil {
		t.Fatal(err)
	}
	return publicRoot
}

func TestHandlerServesPublicCertificateFormatsOnly(t *testing.T) {
	publicRoot := provisionCA(t)
	handler := newHandler(publicRoot, "http://10.77.0.1/", make(chan struct{}, 4))
	certificate, err := interceptionpki.LoadPublicCertificate(publicRoot)
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{
		"/":                            "text/html; charset=utf-8",
		"/shakerproxy-ca.pem":          "application/x-pem-file",
		"/shakerproxy-ca.crt":          "application/x-x509-ca-cert",
		"/shakerproxy-ca.mobileconfig": "application/x-apple-aspen-config",
		"/shakerproxy-ca-android.0":    "application/octet-stream",
		"/shakerproxy-ca.pem?format=x": "application/x-pem-file",
	} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		body := recorder.Body.Bytes()
		if recorder.Code != http.StatusOK || recorder.Header().Get("Content-Type") != want {
			t.Fatalf("%s: %d %q", path, recorder.Code, recorder.Header().Get("Content-Type"))
		}
		if bytes.Contains(body, []byte("PRIVATE KEY")) {
			t.Fatalf("%s leaked private key material", path)
		}
		if recorder.Header().Get("Cache-Control") != "no-store" || !strings.Contains(recorder.Header().Get("Content-Security-Policy"), "default-src 'none'") {
			t.Fatalf("%s lacks security headers", path)
		}
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/shakerproxy-ca.crt", nil))
	if !bytes.Equal(recorder.Body.Bytes(), certificate.Raw) {
		t.Fatal("DER download is not the CA certificate")
	}
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/shakerproxy-ca-android.0", nil))
	if want := `filename="` + interceptionpki.SubjectHashOld(certificate) + `.0"`; !strings.Contains(recorder.Header().Get("Content-Disposition"), want) {
		t.Fatalf("Android file name is %q", recorder.Header().Get("Content-Disposition"))
	}
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	page := recorder.Body.String()
	for _, fragment := range []string{interceptionpki.FormatFingerprint(certificate), "Certificate Trust Settings", "http://10.77.0.1/", "width=device-width"} {
		if !strings.Contains(page, fragment) {
			t.Fatalf("page lacks %q", fragment)
		}
	}
	for _, request := range []*http.Request{httptest.NewRequest(http.MethodPost, "/", nil), httptest.NewRequest(http.MethodGet, "/private.key", nil)} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusMethodNotAllowed && recorder.Code != http.StatusNotFound {
			t.Fatalf("%s %s returned %d", request.Method, request.URL.Path, recorder.Code)
		}
	}
}

func TestHandlerExplainsMissingCertificate(t *testing.T) {
	handler := newHandler(t.TempDir(), "http://10.77.0.1/", make(chan struct{}, 1))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), "has not created its interception certificate") {
		t.Fatalf("unexpected response %d", recorder.Code)
	}
}

func TestServiceListensOnlyOnPublishedLabAddresses(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "lab-endpoints.json")
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	_ = probe.Close()
	service := &service{endpointsPath: path, publicRoot: provisionCA(t), logger: slog.New(slog.NewTextHandler(io.Discard, nil)), servers: map[string]*http.Server{}, limiter: make(chan struct{}, 4)}
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		service.apply(ctx, nil)
	}()

	service.reconcile(ctx)
	if len(service.servers) != 0 {
		t.Fatal("service listened without a projection")
	}
	// Loopback is refused as a lab address even when published.
	writeEndpoints(t, path, endpoints{Schema: 1, Serve: true, IPv4: "127.0.0.1", Port: port})
	service.reconcile(ctx)
	if len(service.servers) != 0 {
		t.Fatal("service listened on loopback")
	}
	writeEndpoints(t, path, endpoints{Schema: 1, Serve: true, IPv4: "10.255.255.254", Port: 80})
	service.reconcile(ctx)
	if len(service.servers) != 0 {
		t.Fatal("service accepted a privileged port")
	}
	addresses, err := service.desiredAddresses()
	if err == nil || addresses != nil {
		t.Fatalf("privileged port accepted: %v %v", addresses, err)
	}
	writeEndpoints(t, path, endpoints{Schema: 1, Serve: false, IPv4: "10.77.0.1", Port: port})
	if addresses, err := service.desiredAddresses(); err != nil || len(addresses) != 0 {
		t.Fatalf("serve=false still wants %v (%v)", addresses, err)
	}
	writeEndpoints(t, path, endpoints{Schema: 1, Serve: true, IPv4: "10.77.0.1", IPv6: "fd12::1", Port: port})
	addresses, err = service.desiredAddresses()
	if err != nil || strings.Join(addresses, ",") != "10.77.0.1:"+strconv.Itoa(port)+",[fd12::1]:"+strconv.Itoa(port) {
		t.Fatalf("unexpected listen addresses %v (%v)", addresses, err)
	}
}

func writeEndpoints(t *testing.T, path string, value endpoints) {
	t.Helper()
	encoded, _ := json.Marshal(value)
	if err := os.WriteFile(path, encoded, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestHelpDoesNotServe(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--help"}, func(string) string { return "" }, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "Usage:") {
		t.Fatalf("code=%d output=%q", code, stdout.String())
	}
	if code := run([]string{"serve"}, func(string) string { return "" }, &stdout, &stderr); code != 2 {
		t.Fatalf("unexpected argument accepted: %d", code)
	}
}
