package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"shakerproxy.dev/shakerproxy/internal/apitoken"
)

const (
	defaultAPIURL       = "https://127.0.0.1:8443"
	defaultAPITokenFile = "/etc/shakerproxy/secrets/cli-api-token"
	defaultManagementCA = "/var/lib/shakerproxy/public/management-ca.crt"
	maxAPIRequestBytes  = 1 << 20
	maxAPIResponseBytes = 4 << 20
)

type apiClient struct {
	base   *url.URL
	client *http.Client
}

// apiError is a non-2xx control API answer in the standard error shape.
type apiError struct {
	status     int
	method     string
	path       string
	code       string
	message    string
	candidates []deviceMatch
}

func (e *apiError) Error() string {
	if e.message != "" {
		return e.message
	}
	return fmt.Sprintf("control API returned HTTP %d for %s %s", e.status, e.method, e.path)
}

// unsupported reports that the running control API does not have this route
// yet (older release), as opposed to a missing object.
func (e *apiError) unsupported() bool {
	return (e.status == http.StatusNotFound || e.status == http.StatusMethodNotAllowed) && (e.code == "" || e.code == "not_found" || e.code == "method_not_allowed")
}

func parseAPIError(status int, method, path string, body []byte) *apiError {
	result := &apiError{status: status, method: method, path: path}
	var envelope struct {
		Error struct {
			Code       string        `json:"code"`
			Message    string        `json:"message"`
			Candidates []deviceMatch `json:"candidates"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &envelope) == nil {
		result.code = envelope.Error.Code
		result.message = sanitize(strings.TrimSpace(envelope.Error.Message))
		result.candidates = envelope.Error.Candidates
	}
	return result
}

func (c *cli) apiCommand(args []string) error {
	flags := newFlags("api")
	dataPath := flags.String("data", "", "JSON request body file")
	positional, err := parseFlags("api", flags, args)
	if err != nil {
		return err
	}
	if len(positional) == 0 && *dataPath == "" {
		return c.apiIndex()
	}
	if err := expectArgs("api", positional, 2, 2, "METHOD", "/api/v1/path"); err != nil {
		return err
	}
	method := strings.ToUpper(positional[0])
	switch method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
	default:
		return usagef("api", "API method must be GET, POST, PUT, PATCH or DELETE.")
	}
	if reference, err := url.Parse(positional[1]); err != nil || reference.IsAbs() || reference.Host != "" || reference.Fragment != "" || !apiPathAllowed(reference.Path) {
		return usagef("api", "The path must be a local API path such as /api/v1/devices.")
	}
	var body []byte
	if *dataPath != "" {
		body, err = readBoundedRegularFile(*dataPath, maxAPIRequestBytes, false)
		if err != nil {
			return fmt.Errorf("read API body: %w", err)
		}
		if !json.Valid(body) {
			return usagef("api", "%s is not valid JSON.", *dataPath)
		}
	}
	session, err := c.openAPI()
	if err != nil {
		return err
	}
	status, response, err := session.client.call(context.Background(), method, positional[1], session.token, body, nil)
	if err != nil {
		return session.transportError(err)
	}
	_, _ = c.stdout.Write(response)
	if len(response) == 0 || response[len(response)-1] != '\n' {
		fmt.Fprintln(c.stdout)
	}
	if status < 200 || status >= 300 {
		return &silentFailure{code: exitFailure}
	}
	return nil
}

// apiIndex prints the control API's resource index (GET /api/v1).
func (c *cli) apiIndex() error {
	client, err := newAPIClient()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	status, response, err := client.call(ctx, http.MethodGet, "/api/v1", "", nil, nil)
	if err != nil {
		return (&apiSession{client: client}).transportError(err)
	}
	if status != http.StatusOK {
		return explainAPIError(parseAPIError(status, http.MethodGet, "/api/v1", response))
	}
	if err := c.printRawJSON(response); err != nil {
		return err
	}
	if !c.jsonOutput {
		fmt.Fprintln(c.stderr, "Call one: sudo shakerproxy api GET /api/v1/<path>  ·  full spec: sudo shakerproxy api GET /api/v1/openapi.yaml")
	}
	return nil
}

func (c *cli) tokenCommand(args []string) error {
	subcommand := ""
	if len(args) > 0 {
		subcommand = args[0]
	}
	switch subcommand {
	case "create":
		flags := newFlags("token create")
		name := flags.String("name", "", "token name")
		scopes := flags.String("scopes", "", "comma-separated scopes")
		expires := flags.Duration("expires", 24*time.Hour, "credential lifetime")
		passwordFile := flags.String("password-file", "", "administrator password file")
		output := flags.String("output", "", "write the display-once credential to a new mode-0600 file")
		deviceIDs := flags.String("device-ids", "", "comma-separated device restrictions")
		caseIDs := flags.String("case-ids", "", "comma-separated case restrictions")
		acknowledgeSensitive := flags.Bool("acknowledge-sensitive-scopes", false, "acknowledge capture/case write authority")
		positional, err := parseFlags("token", flags, args[1:])
		if err != nil {
			return err
		}
		if err := expectArgs("token", positional, 0, 0); err != nil {
			return err
		}
		if *name == "" || *scopes == "" || *passwordFile == "" {
			return usagef("token", "token create needs --name, --scopes and --password-file.")
		}
		requestScopes := make([]apitoken.Scope, 0)
		for _, scope := range splitCSV(*scopes) {
			requestScopes = append(requestScopes, apitoken.Scope(scope))
		}
		payload := map[string]any{"name": *name, "scopes": requestScopes, "expires_in_seconds": int64(*expires / time.Second), "restrictions": apitoken.Restrictions{DeviceIDs: splitCSV(*deviceIDs), CaseIDs: splitCSV(*caseIDs)}, "sensitive_scope_acknowledged": *acknowledgeSensitive}
		password, err := readPasswordFile(*passwordFile)
		if err != nil {
			return err
		}
		admin, err := c.adminSession(envOr("SHAKERPROXY_API_USERNAME", "admin"), password)
		if err != nil {
			return err
		}
		defer admin.close()
		response, err := admin.do(http.MethodPost, "/api/v1/auth/tokens", withPassword(payload, password))
		if err != nil {
			return err
		}
		var created struct {
			Token  json.RawMessage `json:"token"`
			Secret string          `json:"secret"`
		}
		if err := json.Unmarshal(response, &created); err != nil || created.Secret == "" {
			return errors.New("API did not return a valid display-once credential")
		}
		if *output != "" {
			if err := writeSecretExclusive(*output, created.Secret); err != nil {
				return err
			}
			return c.printJSON(map[string]any{"token": created.Token, "secret_file": *output})
		}
		return c.printRawJSON(response)
	case "list":
		flags := newFlags("token list")
		passwordFile := flags.String("password-file", "", "administrator password file")
		positional, err := parseFlags("token", flags, args[1:])
		if err != nil {
			return err
		}
		if err := expectArgs("token", positional, 0, 0); err != nil {
			return err
		}
		if *passwordFile == "" {
			return usagef("token", "token list needs --password-file.")
		}
		password, err := readPasswordFile(*passwordFile)
		if err != nil {
			return err
		}
		admin, err := c.adminSession(envOr("SHAKERPROXY_API_USERNAME", "admin"), password)
		if err != nil {
			return err
		}
		defer admin.close()
		response, err := admin.do(http.MethodGet, "/api/v1/auth/tokens", nil)
		if err != nil {
			return err
		}
		return c.printRawJSON(response)
	case "revoke":
		flags := newFlags("token revoke")
		passwordFile := flags.String("password-file", "", "administrator password file")
		reason := flags.String("reason", "", "revocation reason")
		positional, err := parseFlags("token", flags, args[1:])
		if err != nil {
			return err
		}
		if err := expectArgs("token", positional, 1, 1, "TOKEN_ID"); err != nil {
			return err
		}
		if *passwordFile == "" || *reason == "" {
			return usagef("token", "token revoke needs --password-file and --reason.")
		}
		password, err := readPasswordFile(*passwordFile)
		if err != nil {
			return err
		}
		admin, err := c.adminSession(envOr("SHAKERPROXY_API_USERNAME", "admin"), password)
		if err != nil {
			return err
		}
		defer admin.close()
		response, err := admin.do(http.MethodDelete, "/api/v1/auth/tokens/"+url.PathEscape(positional[0]), map[string]any{"reason": *reason, "password": password})
		if err != nil {
			return err
		}
		return c.printRawJSON(response)
	default:
		return unknownSubcommand("token", subcommand, []string{"create", "list", "revoke"})
	}
}

func withPassword(payload map[string]any, password string) map[string]any {
	copied := make(map[string]any, len(payload)+1)
	for key, value := range payload {
		copied[key] = value
	}
	copied["password"] = password
	return copied
}

// apiSession is an authenticated connection to the local control API using
// either the stored CLI token or an administrator session.
type apiSession struct {
	client *apiClient
	token  string
}

// openAPI loads the stored CLI token and management CA with actionable
// errors for the common first-run problems.
func (c *cli) openAPI() (*apiSession, error) {
	secret, err := loadAPIToken()
	if err != nil {
		return nil, err
	}
	client, err := newAPIClient()
	if err != nil {
		return nil, err
	}
	return &apiSession{client: client, token: secret}, nil
}

// adminSession signs in with the administrator password for operations that
// the API only allows to interactive administrators.
func (c *cli) adminSession(username, password string) (*apiSession, error) {
	client, err := newAPIClient()
	if err != nil {
		return nil, err
	}
	login, _ := json.Marshal(map[string]string{"username": username, "password": password})
	status, response, err := client.call(context.Background(), http.MethodPost, "/api/v1/auth/login", "", login, nil)
	if err != nil {
		return nil, (&apiSession{client: client}).transportError(err)
	}
	if status == http.StatusTooManyRequests {
		return nil, withHints("too many password attempts", "Wait a minute and try again.")
	}
	if status == http.StatusUnauthorized {
		return nil, withHints("Wrong username or password.", fmt.Sprintf("The username is %q unless you changed it (use --user).", username), "Forgot the password? Run `sudo shakerproxy admin reset`.")
	}
	if status != http.StatusOK {
		return nil, explainAPIError(parseAPIError(status, http.MethodPost, "/api/v1/auth/login", response))
	}
	var session struct {
		Token string `json:"session_token"`
	}
	if err := json.Unmarshal(response, &session); err != nil || session.Token == "" {
		return nil, errors.New("administrator login response was invalid")
	}
	return &apiSession{client: client, token: session.Token}, nil
}

// close signs an administrator session out (best effort); API-token
// sessions have nothing to close.
func (s *apiSession) close() {
	if s == nil || s.client == nil || s.token == "" || strings.HasPrefix(s.token, "lgt_") {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, _ = s.client.call(ctx, http.MethodPost, "/api/v1/auth/logout", s.token, nil, nil)
}

// do sends a JSON request and returns the raw 2xx body or a friendly error.
func (s *apiSession) do(method, path string, payload any) ([]byte, error) {
	return s.doWithHeaders(method, path, payload, nil)
}

func (s *apiSession) doWithHeaders(method, path string, payload any, headers map[string]string) ([]byte, error) {
	var body []byte
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = encoded
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	status, response, err := s.client.call(ctx, method, path, s.token, body, headers)
	if err != nil {
		return nil, s.transportError(err)
	}
	if status < 200 || status >= 300 {
		return nil, explainAPIError(parseAPIError(status, method, path, response))
	}
	return response, nil
}

func (s *apiSession) getJSON(path string, out any) ([]byte, error) {
	response, err := s.do(http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	if out != nil {
		if err := json.Unmarshal(response, out); err != nil {
			return nil, fmt.Errorf("control API returned an unexpected answer for %s: %v", path, err)
		}
	}
	return response, nil
}

func (s *apiSession) transportError(err error) error {
	base := defaultAPIURL
	if s != nil && s.client != nil {
		base = s.client.base.String()
	}
	var unknownAuthority x509.UnknownAuthorityError
	var hostnameError x509.HostnameError
	switch {
	case errors.As(err, &unknownAuthority), errors.As(err, &hostnameError):
		return withHints(fmt.Sprintf("the control API certificate at %s is not signed by the ShakerProxy management CA", base), "Run `sudo shakerproxy repair` to re-provision certificates.")
	case errors.Is(err, syscall.ECONNREFUSED):
		return withHints(fmt.Sprintf("nothing is listening at %s (the ShakerProxy app is not running)", base), "Check it: sudo shakerproxy app status", "Start it: sudo systemctl start shakerproxy-app")
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded):
		return withHints(fmt.Sprintf("the control API at %s did not answer in time", base), "Check it: sudo shakerproxy status", "Logs: sudo shakerproxy logs control-api")
	}
	return withHints(fmt.Sprintf("cannot reach the control API at %s: %v", base, err), "Check it: sudo shakerproxy app status", "Logs: sudo shakerproxy logs control-api")
}

// explainAPIError turns API error codes into messages with next steps.
func explainAPIError(err *apiError) error {
	switch {
	case err.code == "device_ambiguous" && len(err.candidates) > 0:
		return ambiguousDeviceError(err.message, err.candidates)
	case err.status == http.StatusUnauthorized && (err.code == "invalid_api_token" || err.code == "invalid_session" || err.code == "authentication_required" || err.code == ""):
		return withHints("the control API rejected the stored token (it may have expired or been revoked)", "Run `"+commandHint("shakerproxy login")+"` again.")
	case err.status == http.StatusForbidden && err.code == "insufficient_scope":
		return withHints("the stored API token is not allowed to do this", "Run `"+commandHint("shakerproxy login")+"` again to get a token with the standard CLI permissions.")
	case err.unsupported():
		return &hintError{message: fmt.Sprintf("this ShakerProxy version does not support %s %s yet", err.method, pathWithoutQuery(err.path)), hints: []string{"Update ShakerProxy: sudo shakerproxy update"}, cause: err}
	case err.status == http.StatusTooManyRequests:
		return withHints(orText(err.message, "too many requests"), "Wait a minute and try again.")
	case err.status >= 500:
		return withHints(orText(err.message, fmt.Sprintf("control API returned HTTP %d", err.status)), "Check the appliance: sudo shakerproxy status", "Logs: sudo shakerproxy logs control-api")
	}
	return err
}

// isUnsupported reports whether an API call failed because the running
// control API does not have that route yet.
func isUnsupported(err error) bool {
	var api *apiError
	return errors.As(err, &api) && api.unsupported()
}

func orText(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func pathWithoutQuery(path string) string {
	if index := strings.IndexByte(path, '?'); index >= 0 {
		return path[:index]
	}
	return path
}

func newAPIClient() (*apiClient, error) {
	base, err := url.Parse(envOr("SHAKERPROXY_API_URL", defaultAPIURL))
	if err != nil || !validLocalAPIBase(base) {
		return nil, errors.New("SHAKERPROXY_API_URL must be an HTTPS loopback origin without credentials, query, or path")
	}
	caPath := envOr("SHAKERPROXY_MANAGEMENT_CA_PATH", defaultManagementCA)
	ca, err := os.ReadFile(caPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, withHints(fmt.Sprintf("the ShakerProxy management CA was not found at %s", caPath), "Is ShakerProxy installed on this machine? Check with `shakerproxy status`.", "For a custom setup, set SHAKERPROXY_MANAGEMENT_CA_PATH.")
	}
	if err != nil {
		return nil, fmt.Errorf("read management CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, errors.New("management CA file contains no trusted certificate")
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}, DialContext: (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 15 * time.Second}).DialContext, ResponseHeaderTimeout: 20 * time.Second, IdleConnTimeout: 30 * time.Second, DisableCompression: true}
	return &apiClient{base: base, client: &http.Client{Transport: transport, Timeout: 45 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (client *apiClient) call(ctx context.Context, method, path, bearer string, body []byte, headers map[string]string) (int, []byte, error) {
	reference, err := url.Parse(path)
	if err != nil || reference.IsAbs() || reference.Host != "" || reference.Fragment != "" || !apiPathAllowed(reference.Path) {
		return 0, nil, errors.New("API path must be a local /api/v1/ path")
	}
	target := client.base.ResolveReference(reference)
	if !apiPathAllowed(target.Path) {
		return 0, nil, errors.New("API path must stay under /api/v1/")
	}
	var reader io.Reader
	if len(body) > 0 {
		if len(body) > maxAPIRequestBytes || !json.Valid(body) {
			return 0, nil, errors.New("API request body must be valid JSON no larger than 1 MiB")
		}
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, target.String(), reader)
	if err != nil {
		return 0, nil, err
	}
	request.Host = client.base.Host
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "shakerproxy-cli/"+version)
	if len(body) > 0 {
		request.Header.Set("Content-Type", "application/json")
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	response, err := client.client.Do(request)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	limited := io.LimitReader(response.Body, maxAPIResponseBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return 0, nil, err
	}
	if len(data) > maxAPIResponseBytes {
		return 0, nil, errors.New("API response exceeded 4 MiB")
	}
	return response.StatusCode, data, nil
}

// apiPathAllowed keeps every request on the local versioned API.
func apiPathAllowed(path string) bool {
	return path == "/api/v1" || strings.HasPrefix(path, "/api/v1/")
}

// geteuid is replaceable in tests.
var geteuid = os.Geteuid

// apiTokenPath is where login stores the API token and the device commands
// read it: the appliance-wide file for root (and sudo), otherwise the user's
// own config directory, so everyday commands need no sudo.
func apiTokenPath() string {
	if configured := os.Getenv("SHAKERPROXY_API_TOKEN_FILE"); configured != "" {
		return configured
	}
	if path, ok := userAPITokenPath(); ok {
		return path
	}
	return defaultAPITokenFile
}

func userAPITokenPath() (string, bool) {
	if geteuid() == 0 {
		return "", false
	}
	directory, err := os.UserConfigDir()
	if err != nil || !filepath.IsAbs(directory) {
		return "", false
	}
	return filepath.Join(directory, "shakerproxy", "cli-api-token"), true
}

// commandHint spells a command the way this user should run it: with sudo
// only when they are already using sudo.
func commandHint(command string) string {
	if geteuid() == 0 && os.Getenv("SUDO_USER") != "" {
		return "sudo " + command
	}
	return command
}

func loadAPIToken() (string, error) {
	path := apiTokenPath()
	data, err := readBoundedRegularFile(path, 512, true)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return "", withHints(fmt.Sprintf("you are not logged in (no API token at %s)", path), "Run `"+commandHint("shakerproxy login")+"` first.")
	case errors.Is(err, os.ErrPermission):
		return "", withHints(fmt.Sprintf("permission denied reading the API token at %s", path), "Sign in as yourself: shakerproxy login", "Or run the command with sudo to use the appliance-wide login.")
	case errors.Is(err, syscall.ELOOP):
		return "", fmt.Errorf("the API token path %s is a symbolic link; refusing to follow it", path)
	case err != nil && strings.Contains(err.Error(), "private file permissions"):
		return "", withHints(fmt.Sprintf("the API token at %s is readable by other users: %v", path, err), "Fix it: "+commandHint("chmod 600 "+path), "Or sign in again: "+commandHint("shakerproxy login"))
	case err != nil:
		return "", fmt.Errorf("read API token: %w", err)
	}
	secret := strings.TrimSpace(string(data))
	if !strings.HasPrefix(secret, "lgt_") || strings.ContainsAny(secret, " \t\r\n") {
		return "", withHints("API token file does not contain one valid token", "Run `"+commandHint("shakerproxy login")+"` again.")
	}
	return secret, nil
}

func readBoundedRegularFile(path string, maximum int64, private bool) ([]byte, error) {
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	file := os.NewFile(uintptr(descriptor), path)
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, errors.New("could not inspect file")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maximum {
		return nil, errors.New("file must be a bounded regular file")
	}
	if private && info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("private file permissions are %s; expected no group/other access", strconv.FormatUint(uint64(info.Mode().Perm()), 8))
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximum {
		return nil, errors.New("file exceeded its size limit while being read")
	}
	return data, nil
}

func writeSecretExclusive(path, secret string) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(absolute, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create token output without overwrite: %w", err)
	}
	if _, err := file.WriteString(secret + "\n"); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

func validLocalAPIBase(base *url.URL) bool {
	if base == nil || base.Scheme != "https" || base.User != nil || base.RawQuery != "" || base.Fragment != "" || base.Path != "" {
		return false
	}
	host := base.Hostname()
	if host == "localhost" {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

func splitCSV(value string) []string {
	result := make([]string, 0)
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			result = append(result, item)
		}
	}
	return result
}
