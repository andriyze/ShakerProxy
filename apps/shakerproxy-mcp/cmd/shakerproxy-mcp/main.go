package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"shakerproxy.dev/shakerproxy/internal/agentapi"
	"shakerproxy.dev/shakerproxy/internal/mcpserver"
	"shakerproxy.dev/shakerproxy/internal/secretfile"
)

const version = "0.1.0-dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args, os.Stdout); err != nil {
		fatal(err)
	}
}

func run(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) == 2 && args[1] == "--version" {
		_, err := fmt.Fprintln(stdout, version)
		return err
	}
	if len(args) >= 2 {
		switch args[1] {
		case "setup":
			if len(args) != 2 {
				return errors.New("usage: shakerproxy-mcp setup")
			}
			return runSetup(os.Stdin, stdout, os.Stderr)
		case "doctor":
			if len(args) != 2 {
				return errors.New("usage: shakerproxy-mcp doctor")
			}
			return runDoctor(ctx, stdout)
		case "config":
			return runConfig(args[2:], stdout)
		case "help", "--help", "-h":
			return writeHelp(stdout)
		default:
			return errors.New("unknown shakerproxy-mcp command; use 'shakerproxy-mcp help'")
		}
	}
	backend, token, err := agentBackendFromEnvironment()
	if err != nil {
		return err
	}
	defer wipe(token)
	server, err := mcpserver.New(backend)
	if err != nil {
		return err
	}
	if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil && ctx.Err() == nil {
		return fmt.Errorf("MCP stdio server stopped: %w", err)
	}
	return nil
}

func agentBackendFromEnvironment() (*agentapi.Client, []byte, error) {
	apiURL := envOr("SHAKERPROXY_API_URL", "https://127.0.0.1:8443")
	tokenPath := strings.TrimSpace(os.Getenv("SHAKERPROXY_API_TOKEN_FILE"))
	if tokenPath == "" {
		var err error
		tokenPath, err = defaultMCPTokenPath()
		if err != nil {
			return nil, nil, err
		}
	}
	caPath := envOr("SHAKERPROXY_MANAGEMENT_CA_FILE", "/var/lib/shakerproxy/public/management-ca.crt")
	token, err := loadMCPToken(tokenPath)
	if err != nil {
		return nil, nil, errors.New("MCP API token file is unavailable or unsafe")
	}
	httpClient, err := localAPIHTTPClient(apiURL, caPath)
	if err != nil {
		wipe(token)
		return nil, nil, err
	}
	backend, err := agentapi.NewClient(apiURL, string(token), httpClient)
	if err != nil {
		wipe(token)
		return nil, nil, err
	}
	return backend, token, nil
}

func wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func defaultMCPTokenPath() (string, error) {
	configurationDirectory, err := os.UserConfigDir()
	if err != nil || !filepath.IsAbs(configurationDirectory) {
		return "", errors.New("user configuration directory is unavailable; set SHAKERPROXY_API_TOKEN_FILE")
	}
	return filepath.Join(configurationDirectory, "shakerproxy", "mcp-token"), nil
}

func loadMCPToken(path string) ([]byte, error) {
	path = strings.TrimSpace(path)
	if !filepath.IsAbs(path) {
		return nil, errors.New("MCP token path must be absolute")
	}
	return secretfile.LoadPrivateToken(path, uint32(os.Geteuid()))
}

func localAPIHTTPClient(apiURL, caPath string) (*http.Client, error) {
	parsed, err := url.Parse(strings.TrimSpace(apiURL))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" && parsed.Path != "/" {
		return nil, errors.New("SHAKERPROXY_API_URL must be an HTTP(S) service origin")
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return nil, errors.New("SHAKERPROXY_API_URL must use HTTPS or loopback HTTP")
	}
	if parsed.Scheme == "http" && !isLoopback(parsed.Hostname()) {
		return nil, errors.New("cleartext MCP API access is permitted only on loopback")
	}
	// Device reports and comparisons aggregate up to 31 days of events, so
	// responses may take longer than a plain query.
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 4 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          4,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   4 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
	}
	if parsed.Scheme == "https" {
		certificate, err := os.ReadFile(caPath)
		if err != nil || len(certificate) == 0 || len(certificate) > 1<<20 {
			return nil, errors.New("ShakerProxy management CA is unavailable or invalid")
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(certificate) {
			return nil, errors.New("ShakerProxy management CA contains no valid PEM certificate")
		}
		transport.TLSClientConfig = &tls.Config{
			MinVersion: tls.VersionTLS13,
			RootCAs:    roots,
			ServerName: parsed.Hostname(),
		}
	}
	return &http.Client{Transport: transport, Timeout: 25 * time.Second}, nil
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "shakerproxy-mcp: %v\n", err)
	os.Exit(1)
}
