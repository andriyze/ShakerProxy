// shakerproxy-ca-onboarding serves the public interception CA and install steps
// to lab devices at http://<lab gateway>/. It runs without privileges or
// capabilities: it listens on an unprivileged port bound only to ShakerProxy's
// lab-side addresses, and shakerproxy-gatewayd forwards lab TCP/80 for the
// gateway address to it only while HTTPS interception is configured.
package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"shakerproxy.dev/shakerproxy/internal/interceptionpki"
)

const usage = `shakerproxy-ca-onboarding — lab-side ShakerProxy CA onboarding page

Usage:
  shakerproxy-ca-onboarding          serve (normally started by systemd)
  shakerproxy-ca-onboarding --help   show this help and exit

Lab devices open http://<ShakerProxy lab address>/ to download the public
interception certificate (PEM, DER, iOS profile, Android system-store file)
and read install steps. The page exists only while HTTPS decryption is on.

Environment:
  SHAKERPROXY_ONBOARDING_ENDPOINTS   gateway projection (default /var/lib/shakerproxy/onboarding/lab-endpoints.json)
  SHAKERPROXY_PUBLIC_ROOT            public certificate directory (default /var/lib/shakerproxy/public)
`

const (
	maxConcurrentRequests = 32
	reconcileInterval     = 5 * time.Second
	maxEndpointsBytes     = 16 << 10
)

type endpoints struct {
	Schema int    `json:"schema"`
	Serve  bool   `json:"serve"`
	IPv4   string `json:"ipv4"`
	IPv6   string `json:"ipv6"`
	Port   int    `json:"port"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}

func run(arguments []string, getenv func(string) string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("shakerproxy-ca-onboarding", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	help := flags.Bool("help", false, "show help")
	flags.BoolVar(help, "h", false, "show help")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	if *help {
		fmt.Fprint(stdout, usage)
		return 0
	}
	logger := slog.New(slog.NewJSONHandler(stdout, nil))
	service := &service{
		endpointsPath: envOr(getenv, "SHAKERPROXY_ONBOARDING_ENDPOINTS", "/var/lib/shakerproxy/onboarding/lab-endpoints.json"),
		publicRoot:    envOr(getenv, "SHAKERPROXY_PUBLIC_ROOT", "/var/lib/shakerproxy/public"),
		logger:        logger,
		servers:       map[string]*http.Server{},
		limiter:       make(chan struct{}, maxConcurrentRequests),
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	logger.Info("ShakerProxy CA onboarding service starting", "endpoints", service.endpointsPath)
	service.run(ctx)
	return 0
}

func envOr(getenv func(string) string, name, fallback string) string {
	if value := getenv(name); value != "" {
		return value
	}
	return fallback
}

type service struct {
	endpointsPath string
	publicRoot    string
	logger        *slog.Logger
	limiter       chan struct{}
	mu            sync.Mutex
	servers       map[string]*http.Server
	lastErr       string
}

func (s *service) run(ctx context.Context) {
	ticker := time.NewTicker(reconcileInterval)
	defer ticker.Stop()
	for {
		s.reconcile(ctx)
		select {
		case <-ctx.Done():
			s.apply(ctx, nil)
			return
		case <-ticker.C:
		}
	}
}

// desiredAddresses returns the listen addresses for the current projection.
// Missing or invalid projections mean "serve nothing".
func (s *service) desiredAddresses() ([]string, error) {
	info, err := os.Lstat(s.endpointsPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxEndpointsBytes {
		return nil, errors.New("onboarding endpoints file is not a bounded regular file")
	}
	data, err := os.ReadFile(s.endpointsPath)
	if err != nil {
		return nil, err
	}
	var current endpoints
	if err := json.Unmarshal(data, &current); err != nil || current.Schema != 1 {
		return nil, errors.New("onboarding endpoints file is invalid")
	}
	if !current.Serve {
		return nil, nil
	}
	if current.Port < 1024 || current.Port > 65535 {
		return nil, errors.New("onboarding port must be unprivileged")
	}
	result := []string{}
	for _, raw := range []string{current.IPv4, current.IPv6} {
		if raw == "" {
			continue
		}
		address, err := netip.ParseAddr(raw)
		if err != nil || address.IsUnspecified() || address.IsLoopback() || address.IsMulticast() || address.Zone() != "" {
			return nil, fmt.Errorf("onboarding address %q is not a lab unicast address", raw)
		}
		result = append(result, net.JoinHostPort(address.String(), strconv.Itoa(current.Port)))
	}
	return result, nil
}

func (s *service) reconcile(ctx context.Context) {
	desired, err := s.desiredAddresses()
	if err != nil {
		s.warnOnce("onboarding endpoints unavailable; serving nothing", err)
		desired = nil
	}
	s.apply(ctx, desired)
}

func (s *service) apply(ctx context.Context, desired []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	wanted := map[string]bool{}
	for _, address := range desired {
		wanted[address] = true
	}
	for address, server := range s.servers {
		if wanted[address] {
			continue
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = server.Shutdown(shutdownCtx)
		cancel()
		delete(s.servers, address)
		s.logger.Info("onboarding page closed", "address", address)
	}
	if ctx.Err() != nil {
		return
	}
	for _, address := range desired {
		if _, running := s.servers[address]; running {
			continue
		}
		listener, err := net.Listen("tcp", address)
		if err != nil {
			// The lab address may not be configured yet; retry next tick.
			s.warnOnce("onboarding page cannot listen yet", err)
			continue
		}
		server := &http.Server{
			Handler:           s.handler(address),
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       30 * time.Second,
			MaxHeaderBytes:    8 << 10,
		}
		s.servers[address] = server
		go func() {
			if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				s.logger.Warn("onboarding page stopped", "address", address, "error", err)
			}
		}()
		s.logger.Info("onboarding page listening", "address", address)
	}
}

func (s *service) warnOnce(message string, err error) {
	if err.Error() == s.lastErr {
		return
	}
	s.lastErr = err.Error()
	s.logger.Warn(message, "error", err)
}

// handler serves one listener. pageURL shows the lab-facing URL derived
// from the bound address, never from the request's Host header.
func (s *service) handler(listenAddress string) http.Handler {
	host, _, _ := net.SplitHostPort(listenAddress)
	pageURL := "http://" + host + "/"
	if address, err := netip.ParseAddr(host); err == nil && address.Is6() {
		pageURL = "http://[" + host + "]/"
	}
	return newHandler(s.publicRoot, pageURL, s.limiter)
}

func newHandler(publicRoot, pageURL string, limiter chan struct{}) http.Handler {
	mux := http.NewServeMux()
	serveCertificate := func(build func(*x509.Certificate) ([]byte, string, string)) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			certificate, err := interceptionpki.LoadPublicCertificate(publicRoot)
			if err != nil {
				http.Error(w, "ShakerProxy has not created its interception certificate yet.", http.StatusServiceUnavailable)
				return
			}
			body, contentType, filename := build(certificate)
			w.Header().Set("Content-Type", contentType)
			w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			_, _ = w.Write(body)
		}
	}
	mux.Handle("GET "+interceptionpki.OnboardingPEMPath, serveCertificate(func(certificate *x509.Certificate) ([]byte, string, string) {
		return interceptionpki.CertificatePEM(certificate), "application/x-pem-file", "shakerproxy-ca.pem"
	}))
	mux.Handle("GET "+interceptionpki.OnboardingDERPath, serveCertificate(func(certificate *x509.Certificate) ([]byte, string, string) {
		return certificate.Raw, "application/x-x509-ca-cert", "shakerproxy-ca.crt"
	}))
	mux.Handle("GET "+interceptionpki.OnboardingMobileConfigPath, serveCertificate(func(certificate *x509.Certificate) ([]byte, string, string) {
		return interceptionpki.MobileConfig(certificate), "application/x-apple-aspen-config", "shakerproxy-ca.mobileconfig"
	}))
	mux.Handle("GET "+interceptionpki.OnboardingAndroidPath, serveCertificate(func(certificate *x509.Certificate) ([]byte, string, string) {
		return interceptionpki.AndroidSystemStoreFile(certificate), "application/octet-stream", interceptionpki.SubjectHashOld(certificate) + ".0"
	}))
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		page := pageData{PageURL: pageURL, Instructions: interceptionpki.OnboardingInstructions(pageURL)}
		status := http.StatusOK
		if certificate, err := interceptionpki.LoadPublicCertificate(publicRoot); err == nil {
			page.Available = true
			page.Fingerprint = interceptionpki.FormatFingerprint(certificate)
			page.CommonName = certificate.Subject.CommonName
			page.NotAfter = certificate.NotAfter.UTC().Format("2006-01-02")
			page.AndroidName = interceptionpki.SubjectHashOld(certificate) + ".0"
		} else {
			status = http.StatusServiceUnavailable
		}
		var body bytes.Buffer
		if err := pageTemplate.Execute(&body, page); err != nil {
			http.Error(w, "page unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(status)
		_, _ = w.Write(body.Bytes())
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case limiter <- struct{}{}:
			defer func() { <-limiter }()
		default:
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

type pageData struct {
	PageURL      string
	Available    bool
	Fingerprint  string
	CommonName   string
	NotAfter     string
	AndroidName  string
	Instructions []interceptionpki.PlatformInstructions
}

var pageTemplate = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ShakerProxy certificate</title>
<style>
:root{color-scheme:light dark;--fg:#1b1f24;--bg:#fff;--muted:#57606a;--line:#d0d7de;--accent:#0b6bcb;--card:#f6f8fa}
@media (prefers-color-scheme:dark){:root{--fg:#e6edf3;--bg:#0d1117;--muted:#9da7b3;--line:#30363d;--accent:#58a6ff;--card:#161b22}}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:44rem;margin:0 auto;padding:16px}
h1{font-size:1.4rem;margin:.5rem 0}
h2{font-size:1.1rem;margin:1.5rem 0 .5rem}
p{margin:.5rem 0}
.muted{color:var(--muted)}
.fp{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.8rem;word-break:break-all;background:var(--card);border:1px solid var(--line);border-radius:8px;padding:8px}
.downloads{display:grid;gap:8px;margin:1rem 0}
.downloads a{display:block;padding:12px 14px;border:1px solid var(--line);border-radius:10px;background:var(--card);color:var(--accent);text-decoration:none;font-weight:600}
.downloads a span{display:block;font-weight:400;color:var(--muted);font-size:.85rem}
details{border:1px solid var(--line);border-radius:10px;margin:8px 0;background:var(--card)}
summary{cursor:pointer;padding:12px 14px;font-weight:600}
details ol,details ul{margin:0 0 12px;padding:0 14px 0 34px}
details li{margin:.3rem 0}
.warn{border-left:4px solid #bf8700;padding:8px 12px;background:var(--card);border-radius:4px}
</style>
</head>
<body>
<main>
<h1>Trust ShakerProxy on this device</h1>
{{if .Available}}
<p>Install this certificate only on devices you are testing, so ShakerProxy can decrypt their HTTPS. Remove it when you are done.</p>
<p class="muted">{{.CommonName}} · valid until {{.NotAfter}}</p>
<p>SHA-256 fingerprint — check it matches the one in ShakerProxy (System → Interception CA):</p>
<p class="fp">{{.Fingerprint}}</p>
<div class="downloads">
<a href="/shakerproxy-ca.mobileconfig">iPhone / iPad profile<span>Open this page in Safari, then follow the iPhone steps below.</span></a>
<a href="/shakerproxy-ca.crt">Android / Windows certificate (.crt)<span>DER format.</span></a>
<a href="/shakerproxy-ca.pem">PEM certificate<span>For Mac, Linux and most other systems.</span></a>
<a href="/shakerproxy-ca-android.0">Android system store file ({{.AndroidName}})<span>Only for emulators and rooted devices.</span></a>
</div>
{{else}}
<p class="warn">ShakerProxy has not created its interception certificate yet. Ask the ShakerProxy administrator to check the interception certificate service.</p>
{{end}}
<p class="warn">This page is served over plain HTTP on the lab network. Compare the fingerprint before trusting the certificate.</p>
<h2>Install steps</h2>
{{range .Instructions}}<details>
<summary>{{.Title}}</summary>
<ol>{{range .Steps}}<li>{{.}}</li>{{end}}</ol>
{{if .Limitations}}<ul class="muted">{{range .Limitations}}<li>{{.}}</li>{{end}}</ul>{{end}}
</details>
{{end}}
<p class="muted">Can't install certificates on this device? Leave it uninstalled and turn on Decrypt HTTPS anyway: anything that still works means the device accepts untrusted certificates.</p>
</main>
</body>
</html>
`))
