package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"shakerproxy.dev/shakerproxy/internal/apitoken"
)

// cliTokenLifetime is the longest lifetime the API accepts.
const cliTokenLifetime = apitoken.MaxLifetime

// cliTokenScopes are what the device and traffic commands need. captures:write
// is sensitive and acknowledged explicitly; lab:write covers test runs and
// device controls.
var cliTokenScopes = []string{"system:read", "devices:read", "traffic:read", "captures:read", "captures:write", "cases:read", "lab:write"}

// tokenMetadata is stored next to the token (never the secret itself) so
// logout can revoke it and login can replace it.
type tokenMetadata struct {
	Schema    int      `json:"schema"`
	TokenID   string   `json:"token_id"`
	Name      string   `json:"name"`
	Username  string   `json:"username"`
	Scopes    []string `json:"scopes"`
	CreatedAt string   `json:"created_at"`
	ExpiresAt string   `json:"expires_at"`
}

func tokenMetadataPath() string { return apiTokenPath() + ".json" }

func readPasswordFile(path string) (string, error) {
	data, err := readBoundedRegularFile(path, 4096, true)
	if errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("password file %s does not exist", path)
	}
	if err != nil {
		return "", fmt.Errorf("read administrator password: %w", err)
	}
	password := strings.TrimRight(string(data), "\r\n")
	if strings.TrimSpace(password) == "" || strings.ContainsAny(password, "\r\n") {
		return "", errors.New("administrator password file must contain one non-empty line")
	}
	return password, nil
}

// obtainPassword reads the admin password from a file, stdin, or an
// interactive prompt without echo.
func (c *cli) obtainPassword(passwordFile string, fromStdin bool, prompt string) (string, error) {
	switch {
	case passwordFile != "" && fromStdin:
		return "", errors.New("use either --password-file or --password-stdin, not both")
	case passwordFile != "":
		return readPasswordFile(passwordFile)
	case fromStdin:
		line, err := readLine(c.stdin, 1024)
		if err != nil {
			return "", fmt.Errorf("read password from stdin: %w", err)
		}
		if strings.TrimSpace(line) == "" {
			return "", errors.New("the password on stdin is empty")
		}
		return line, nil
	}
	file, ok := c.stdin.(*os.File)
	if !ok || !c.stdinTTY {
		return "", withHints("no terminal is available to ask for the admin password", "Use --password-file FILE (mode 0600) or --password-stdin.")
	}
	password, err := readPasswordFromTerminal(file, prompt, c.stderr)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(password) == "" {
		return "", errors.New("no password was entered")
	}
	return password, nil
}

// ensureWritableTokenDirectory fails early (before asking for a password)
// when the token cannot be stored, e.g. without sudo.
func (c *cli) ensureWritableTokenDirectory(path string) error {
	directory := filepath.Dir(path)
	if userPath, ok := userAPITokenPath(); ok && path == userPath {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return fmt.Errorf("create %s: %w", directory, err)
		}
	}
	info, err := os.Stat(directory)
	if errors.Is(err, os.ErrNotExist) {
		if path == defaultAPITokenFile {
			return withHints(fmt.Sprintf("%s does not exist; ShakerProxy does not appear to be installed here", directory), "Install ShakerProxy first (docs/installation.md), or set SHAKERPROXY_API_TOKEN_FILE.")
		}
		return fmt.Errorf("token directory %s does not exist", directory)
	}
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return withHints(fmt.Sprintf("permission denied on %s", directory), "Run `sudo shakerproxy login`, or sign in as yourself without sudo.")
		}
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", directory)
	}
	if err := unix.Access(directory, unix.W_OK); err != nil {
		return withHints(fmt.Sprintf("cannot write the API token to %s", directory), "Run `sudo shakerproxy login`, or sign in as yourself without sudo.")
	}
	if existing, err := os.Lstat(path); err == nil && !existing.Mode().IsRegular() {
		return fmt.Errorf("%s exists and is not a regular file; refusing to replace it", path)
	}
	return nil
}

func (c *cli) loginCommand(args []string) error {
	flags := newFlags("login")
	user := flags.String("user", envOr("SHAKERPROXY_API_USERNAME", "admin"), "administrator username")
	passwordFile := flags.String("password-file", "", "file with the admin password")
	passwordStdin := flags.Bool("password-stdin", false, "read the admin password from stdin")
	positional, err := parseFlags("login", flags, args)
	if err != nil {
		return err
	}
	if err := expectArgs("login", positional, 0, 0); err != nil {
		return err
	}
	tokenPath := apiTokenPath()
	if err := c.ensureWritableTokenDirectory(tokenPath); err != nil {
		return err
	}
	if _, err := newAPIClient(); err != nil {
		return err
	}
	password, err := c.obtainPassword(*passwordFile, *passwordStdin, fmt.Sprintf("Password for %s: ", *user))
	if err != nil {
		return err
	}
	admin, err := c.adminSession(*user, password)
	if err != nil {
		return err
	}
	defer admin.close()
	now := c.now().UTC()
	hostname, _ := os.Hostname()
	name := tokenName(hostname, now)
	scopes := append([]string(nil), cliTokenScopes...)
	payload := map[string]any{"name": name, "scopes": scopes, "expires_in_seconds": int64(cliTokenLifetime / time.Second), "sensitive_scope_acknowledged": true, "password": password}
	raw, err := admin.do(http.MethodPost, "/api/v1/auth/tokens", payload)
	var notices []string
	if err != nil {
		// A control API without lab:write rejects the whole request; fall
		// back to the scopes it knows so read commands still work.
		var api *apiError
		if !errors.As(err, &api) || api.status != http.StatusBadRequest || !strings.Contains(strings.ToLower(api.message), "scope") {
			return err
		}
		scopes = withoutScope(scopes, "lab:write")
		payload["scopes"] = scopes
		raw, err = admin.do(http.MethodPost, "/api/v1/auth/tokens", payload)
		if err != nil {
			return err
		}
		notices = append(notices, "This ShakerProxy version has no lab:write permission yet, so test runs, decrypt and block need an update (sudo shakerproxy update).")
	}
	var created struct {
		Token struct {
			ID        string   `json:"id"`
			Name      string   `json:"name"`
			Scopes    []string `json:"scopes"`
			ExpiresAt string   `json:"expires_at"`
		} `json:"token"`
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(raw, &created); err != nil || !strings.HasPrefix(created.Secret, "lgt_") || strings.ContainsAny(created.Secret, " \t\r\n") {
		return errors.New("the control API did not return a valid token")
	}
	previous := readTokenMetadata()
	if err := storeToken(tokenPath, created.Secret); err != nil {
		return err
	}
	metadata := tokenMetadata{Schema: 1, TokenID: created.Token.ID, Name: created.Token.Name, Username: *user, Scopes: created.Token.Scopes, CreatedAt: now.Format(time.RFC3339), ExpiresAt: created.Token.ExpiresAt}
	if encoded, err := json.MarshalIndent(metadata, "", "  "); err == nil {
		if _, err := writePrivateFileAtomically(tokenMetadataPath(), append(encoded, '\n')); err != nil {
			notices = append(notices, "Could not save token details for logout: "+err.Error())
		}
	}
	if previous != nil && previous.TokenID != "" && previous.TokenID != created.Token.ID {
		if _, err := admin.do(http.MethodDelete, "/api/v1/auth/tokens/"+url.PathEscape(previous.TokenID), map[string]any{"password": password, "reason": "replaced by shakerproxy login"}); err != nil {
			notices = append(notices, fmt.Sprintf("The previous CLI token %s could not be revoked: %v", previous.TokenID, err))
		}
	}
	if c.jsonOutput {
		return c.printJSON(map[string]any{"token_id": created.Token.ID, "token_file": tokenPath, "scopes": created.Token.Scopes, "expires_at": created.Token.ExpiresAt, "notices": notices})
	}
	expires := created.Token.ExpiresAt
	if parsed, ok := parseTime(expires); ok {
		expires = parsed.Format("2006-01-02")
	}
	c.printf("Logged in as %s. Token saved to %s (valid until %s).\n", *user, tokenPath, expires)
	for _, notice := range notices {
		c.printf("%s %s\n", c.style(styleYellow, "!"), notice)
	}
	c.println("Try: " + commandHint("shakerproxy devices"))
	return nil
}

func tokenName(hostname string, now time.Time) string {
	cleaned := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '.', r == '_':
			return r
		default:
			return -1
		}
	}, hostname)
	if len(cleaned) > 24 {
		cleaned = cleaned[:24]
	}
	name := "shakerproxy cli " + now.Format("20060102T150405Z")
	if cleaned != "" {
		name = "shakerproxy cli " + cleaned + " " + now.Format("20060102T150405Z")
	}
	return strings.TrimRight(name, ".-_ ")
}

func withoutScope(scopes []string, remove string) []string {
	result := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		if scope != remove {
			result = append(result, scope)
		}
	}
	return result
}

func readTokenMetadata() *tokenMetadata {
	data, err := readBoundedRegularFile(tokenMetadataPath(), 16<<10, true)
	if err != nil {
		return nil
	}
	var metadata tokenMetadata
	if json.Unmarshal(data, &metadata) != nil {
		return nil
	}
	return &metadata
}

// storeToken replaces the token file atomically with a mode-0600 file.
func storeToken(path, secret string) error {
	if _, err := writePrivateFileAtomically(path, []byte(secret+"\n")); err != nil {
		return fmt.Errorf("save API token: %w", err)
	}
	return nil
}

func writePrivateFileAtomically(path string, data []byte) (string, error) {
	if existing, err := os.Lstat(path); err == nil && !existing.Mode().IsRegular() {
		return "", fmt.Errorf("%s exists and is not a regular file", path)
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".shakerproxy-token-*")
	if err != nil {
		return "", err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return "", err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return "", err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return "", err
	}
	if err := temporary.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(name, path); err != nil {
		return "", err
	}
	if handle, err := os.Open(directory); err == nil {
		_ = handle.Sync()
		_ = handle.Close()
	}
	return path, nil
}

func (c *cli) logoutCommand(args []string) error {
	flags := newFlags("logout")
	revoke := flags.Bool("revoke", false, "also revoke the token on the appliance")
	user := flags.String("user", envOr("SHAKERPROXY_API_USERNAME", "admin"), "administrator username")
	passwordFile := flags.String("password-file", "", "file with the admin password (for --revoke)")
	positional, err := parseFlags("logout", flags, args)
	if err != nil {
		return err
	}
	if err := expectArgs("logout", positional, 0, 0); err != nil {
		return err
	}
	tokenPath := apiTokenPath()
	info, err := os.Lstat(tokenPath)
	if errors.Is(err, os.ErrNotExist) {
		c.println("You are not logged in.")
		return nil
	}
	if errors.Is(err, os.ErrPermission) {
		return withHints("permission denied on "+tokenPath, "Run `"+commandHint("shakerproxy logout")+"` as the user who signed in, or with sudo.")
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file; remove it manually", tokenPath)
	}
	metadata := readTokenMetadata()
	revoked := false
	if *revoke {
		if metadata == nil || metadata.TokenID == "" {
			return withHints("the token ID is unknown, so it cannot be revoked from here", "Revoke it in the web UI (Integrations → API tokens), then run `"+commandHint("shakerproxy logout")+"`.")
		}
		password, err := c.obtainPassword(*passwordFile, false, fmt.Sprintf("Password for %s (to revoke the token): ", *user))
		if err != nil {
			return err
		}
		admin, err := c.adminSession(*user, password)
		if err != nil {
			return err
		}
		defer admin.close()
		if _, err := admin.do(http.MethodDelete, "/api/v1/auth/tokens/"+url.PathEscape(metadata.TokenID), map[string]any{"password": password, "reason": "shakerproxy logout"}); err != nil {
			// Already revoked or deleted on the appliance: still remove it here.
			var api *apiError
			if !errors.As(err, &api) || api.code != "api_token_not_found" {
				return err
			}
		}
		revoked = true
	}
	if err := os.Remove(tokenPath); err != nil {
		if errors.Is(err, os.ErrPermission) {
			return withHints("permission denied removing "+tokenPath, "Run `"+commandHint("shakerproxy logout")+"` as the user who signed in, or with sudo.")
		}
		return err
	}
	_ = os.Remove(tokenMetadataPath())
	switch {
	case c.jsonOutput:
		return c.printJSON(map[string]any{"logged_out": true, "revoked": revoked})
	case revoked:
		c.println("Logged out and revoked the token on the appliance.")
	default:
		c.println("Logged out: the token was removed from this machine.")
		if metadata != nil && metadata.ExpiresAt != "" {
			c.printf("It stays valid on the appliance until %s unless revoked (web UI → Integrations → API tokens).\n", shortTime(metadata.ExpiresAt))
		}
	}
	return nil
}
