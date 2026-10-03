package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"shakerproxy.dev/shakerproxy/internal/capture"
	"shakerproxy.dev/shakerproxy/internal/configlock"
	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/managementpki"
	"shakerproxy.dev/shakerproxy/internal/signedcontent"
)

const (
	defaultReleaseMetadata     = "/opt/shakerproxy/current/release.json"
	defaultAdminResetRequest   = "/var/lib/shakerproxy/control-api/admin-reset.request"
	installerExecutable        = "/usr/libexec/shakerproxy/shakerproxy-installer"
	uninstallExecutable        = "/usr/libexec/shakerproxy/shakerproxy-uninstall"
	appLifecycleExecutable     = "/usr/libexec/shakerproxy/shakerproxy-app"
	managementURLForOperators  = "https://127.0.0.1:8443/"
	managementTunnelForRemotes = "ssh -N -L 8443:127.0.0.1:8443 <admin>@<sensor-ip>"
)

var lifecycleEnvironment = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8"}

type releaseMetadata struct {
	Schema      int      `json:"schema"`
	Version     string   `json:"version"`
	Channel     string   `json:"channel"`
	Profiles    []string `json:"profiles"`
	InstalledAt string   `json:"installed_at"`
}

func readReleaseMetadata() (*releaseMetadata, error) {
	path := envOr("SHAKERPROXY_RELEASE_METADATA", defaultReleaseMetadata)
	data, err := readBoundedRegularFile(path, 64<<10, false)
	if errors.Is(err, os.ErrPermission) {
		// Release directories are root-only; the symlink still names the version.
		if target, linkErr := os.Readlink(filepath.Dir(path)); linkErr == nil && filepath.Base(target) != "." {
			return &releaseMetadata{Version: filepath.Base(target)}, nil
		}
	}
	if err != nil {
		return nil, err
	}
	var release releaseMetadata
	if err := json.Unmarshal(data, &release); err != nil {
		return nil, fmt.Errorf("release metadata is invalid: %w", err)
	}
	return &release, nil
}

func (c *cli) versionCommand(args []string) error {
	if err := c.noArgs("version", args); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var status gatewayprotocol.Status
	daemonErr := c.gateway().CallWithTimeout(ctx, "GetManagedState", gatewayprotocol.EmptyParams{}, &status, 3*time.Second)
	release, releaseErr := readReleaseMetadata()
	if c.jsonOutput {
		result := map[string]any{"cli": version, "daemon": nil, "api_version": nil, "release": nil}
		if daemonErr == nil {
			result["daemon"], result["api_version"] = status.DaemonVersion, status.APIVersion
		} else {
			result["daemon_error"] = c.gatewayError(daemonErr).Error()
		}
		if releaseErr == nil {
			result["release"] = release
		}
		return c.printJSON(result)
	}
	c.printf("  %-18s %s\n", "shakerproxy CLI", version)
	if daemonErr == nil {
		c.printf("  %-18s %s (API %s)\n", "gateway daemon", status.DaemonVersion, status.APIVersion)
	} else {
		c.printf("  %-18s %s\n", "gateway daemon", c.dim("not reachable: "+c.gatewayError(daemonErr).Error()))
	}
	switch {
	case releaseErr == nil:
		line := release.Version
		if release.Channel != "" {
			line += " · " + release.Channel
		}
		if installed, ok := parseTime(release.InstalledAt); ok {
			line += " · installed " + installed.Local().Format("2006-01-02")
		}
		c.printf("  %-18s %s\n", "installed release", line)
	case errors.Is(releaseErr, os.ErrNotExist):
		c.printf("  %-18s %s\n", "installed release", c.dim("none (not installed from a signed release)"))
	default:
		c.printf("  %-18s %s\n", "installed release", c.dim("unreadable: "+releaseErr.Error()))
	}
	return nil
}

// hostUnits maps friendly service names to systemd units.
var hostUnits = map[string]string{
	"gatewayd": "shakerproxy-gatewayd.service", "gateway": "shakerproxy-gatewayd.service", "daemon": "shakerproxy-gatewayd.service",
	"dns": "shakerproxy-dnsd.service", "dnsd": "shakerproxy-dnsd.service",
	"dhcp": "shakerproxy-dhcp4.service", "dhcp4": "shakerproxy-dhcp4.service",
	"wifi": "shakerproxy-hostapd.service", "hostapd": "shakerproxy-hostapd.service",
	"ipv6": "shakerproxy-radvd.service", "radvd": "shakerproxy-radvd.service",
	"traffic-policy": "shakerproxy-traffic-policy.service", "policy": "shakerproxy-traffic-policy.service",
	"testlab": "shakerproxy-testlab.service",
	"pki":     "shakerproxy-interception-pki.service", "interception-pki": "shakerproxy-interception-pki.service",
	"cloud": "shakerproxy-cloud-connector.service", "cloud-connector": "shakerproxy-cloud-connector.service",
	"dns-forwarder": "shakerproxy-encrypted-dns-event-forwarder.service",
	"syslog":        "shakerproxy-syslog-collectord.service", "syslog-collector": "shakerproxy-syslog-collectord.service",
	"mitm-forwarder": "shakerproxy-mitm-event-forwarder.service",
	"app-service":    "shakerproxy-app.service",
}

// appContainers are the Compose services of the application stack.
var appContainers = []string{"control-api", "web-ui", "edge", "ingestd", "forwarderd", "zeek", "suricata", "postgres", "mitmproxy", "mitm-event-forwarder", "dns-event-forwarder", "syslog-event-forwarder", "inventory-cloud-forwarder"}

func firstExecutable(candidates ...string) string {
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0 {
			return candidate
		}
	}
	return ""
}

func (c *cli) logsCommand(args []string) error {
	flags := newFlags("logs")
	follow := flags.Bool("f", false, "follow new lines")
	flags.BoolVar(follow, "follow", false, "follow new lines")
	lines := flags.Int("n", 200, "number of recent lines")
	flags.IntVar(lines, "lines", 200, "number of recent lines")
	since := flags.String("since", "", "only lines newer than this, e.g. 30m or 2h")
	positional, err := parseFlags("logs", flags, args)
	if err != nil {
		return err
	}
	if err := expectArgs("logs", positional, 0, 2); err != nil {
		return err
	}
	if *lines < 1 || *lines > 100000 {
		return usagef("logs", "-n must be between 1 and 100000.")
	}
	if *since != "" && !windowPattern.MatchString(*since) {
		return usagef("logs", "--since must look like 30m, 2h or 1d.")
	}
	service := ""
	if len(positional) > 0 {
		service = strings.ToLower(positional[0])
	}
	if len(positional) == 2 && service != "capture" {
		return usagef("logs", "Unexpected extra argument %q.", positional[1])
	}
	journal := func(units ...string) error {
		journalctl := c.findExecutable("/usr/bin/journalctl", "/bin/journalctl")
		if journalctl == "" {
			return withHints("the journalctl command was not found; host service logs need systemd", "On a development machine use: make dev-logs")
		}
		arguments := []string{"--no-pager", "--output", "short-iso", "-n", fmt.Sprint(*lines)}
		for _, unit := range units {
			arguments = append(arguments, "-u", unit)
		}
		if *since != "" {
			arguments = append(arguments, "--since", "-"+*since)
		}
		if *follow {
			arguments = append(arguments, "-f")
		}
		return c.runHelper(journalctl, arguments)
	}
	compose := func(container string) error {
		docker := c.findExecutable("/usr/bin/docker", "/usr/local/bin/docker", "/bin/docker")
		if docker == "" {
			return withHints("the docker command was not found; application logs need Docker", "Check the install: sudo shakerproxy doctor")
		}
		arguments := []string{"compose", "--project-name", "shakerproxy", "logs", "--no-color", "--timestamps", "--tail", fmt.Sprint(*lines)}
		if *since != "" {
			arguments = append(arguments, "--since", dockerSince(*since))
		}
		if *follow {
			arguments = append(arguments, "--follow")
		}
		if container != "" {
			arguments = append(arguments, container)
		}
		return c.runHelper(docker, arguments)
	}
	switch {
	case service == "":
		return journal("shakerproxy-*")
	case service == "app" || service == "apps" || service == "containers":
		return compose("")
	case service == "capture" || service == "captures":
		if len(positional) == 2 {
			if !capture.ValidSessionID(positional[1]) {
				return usagef("logs", "%q is not a capture ID (see `shakerproxy capture list`).", positional[1])
			}
			return journal("shakerproxy-capture@" + strings.TrimPrefix(positional[1], "capture-") + ".service")
		}
		return journal("shakerproxy-capture@*")
	case hostUnits[service] != "":
		return journal(hostUnits[service])
	}
	for _, container := range appContainers {
		if container == service {
			return compose(container)
		}
	}
	options := []string{"app", "capture"}
	for name := range hostUnits {
		options = append(options, name)
	}
	options = append(options, appContainers...)
	sort.Strings(options)
	return unknownSubcommand("logs", service, options)
}

// dockerSince converts a day window ("2d") into hours, because Docker parses
// relative --since values as Go durations, which have no day unit.
func dockerSince(window string) string {
	if strings.HasSuffix(window, "d") {
		if days, err := strconv.Atoi(strings.TrimSuffix(window, "d")); err == nil {
			return fmt.Sprintf("%dh", days*24)
		}
	}
	return window
}

// runHelper runs journalctl/docker, passing its exit status through.
func (c *cli) runHelper(path string, args []string) error {
	if err := c.runProgram(path, args); err != nil {
		var exitErr interface{ ExitCode() int }
		if errors.As(err, &exitErr) && exitErr.ExitCode() > 0 {
			if exitErr.ExitCode() == 1 && c.geteuid() != 0 {
				fmt.Fprintln(c.stderr, "Hint: logs usually need root; try again with sudo.")
			}
			return &silentFailure{code: exitFailure}
		}
		return fmt.Errorf("run %s: %w", filepath.Base(path), err)
	}
	return nil
}

func (c *cli) adminCommand(args []string) error {
	subcommand := ""
	if len(args) > 0 {
		subcommand = args[0]
	}
	switch subcommand {
	case "reset", "reset-setup", "reset-password":
		return c.adminReset(args[1:])
	default:
		return unknownSubcommand("admin", subcommand, []string{"reset"})
	}
}

func requesterName() string {
	name := firstNonEmpty(os.Getenv("SUDO_USER"), os.Getenv("USER"), "root")
	cleaned := strings.Map(func(r rune) rune {
		if r < 0x21 || r > 0x7e {
			return -1
		}
		return r
	}, name)
	if len(cleaned) > 64 {
		cleaned = cleaned[:64]
	}
	return orText(cleaned, "root")
}

func (c *cli) adminReset(args []string) error {
	flags := newFlags("admin reset")
	assumeYes := flags.Bool("yes", false, "do not ask for confirmation")
	noWait := flags.Bool("no-wait", false, "return after queueing the request")
	// The control API checks for the request every 5 seconds.
	timeout := flags.Duration("timeout", 15*time.Second, "how long to wait for the control API")
	positional, err := parseFlags("admin", flags, args)
	if err != nil {
		return err
	}
	if err := expectArgs("admin", positional, 0, 0); err != nil {
		return err
	}
	if c.geteuid() != 0 {
		return withHints("admin reset must run as root", "Run `sudo shakerproxy admin reset`.")
	}
	requestPath := envOr("SHAKERPROXY_ADMIN_RESET_REQUEST", defaultAdminResetRequest)
	directory := filepath.Dir(requestPath)
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() {
		return withHints(fmt.Sprintf("the control API state directory %s was not found", directory), "Is ShakerProxy installed? Check with `sudo shakerproxy status`.")
	}
	pending := false
	if existing, err := os.Lstat(requestPath); err == nil {
		if !existing.Mode().IsRegular() {
			return fmt.Errorf("%s exists and is not a regular file; remove it and retry", requestPath)
		}
		pending = true
	}
	requestedAt := c.now().UTC()
	if !pending {
		if !*assumeYes {
			if !c.stdinTTY {
				return usagef("admin", "admin reset asks for confirmation; run it in a terminal or add --yes.")
			}
			fmt.Fprintln(c.stderr, "This removes the admin password and signs everyone out.")
			fmt.Fprintln(c.stderr, "You will then set ShakerProxy up again with a new one-time setup token.")
			fmt.Fprint(c.stderr, "Type RESET to continue: ")
			answer, err := readLine(c.stdin, 64)
			if err != nil || !strings.EqualFold(strings.TrimSpace(answer), "reset") {
				fmt.Fprintln(c.stderr, "Cancelled; nothing was changed.")
				return &silentFailure{code: exitFailure}
			}
		}
		payload, _ := json.Marshal(map[string]string{"requested_at": requestedAt.Format(time.RFC3339), "requested_by": requesterName()})
		if err := writeRequestExclusive(requestPath, append(payload, '\n')); err != nil {
			return err
		}
	} else {
		c.println("An admin reset is already waiting; checking on it.")
	}
	if *noWait {
		c.printf("Reset requested (%s). The control API applies it within a few seconds.\n", requestPath)
		return nil
	}
	deadline := c.now().Add(*timeout)
	for polls := 0; ; polls++ {
		if _, err := os.Lstat(requestPath); errors.Is(err, os.ErrNotExist) {
			break
		}
		if c.now().After(deadline) || (c.maxPolls > 0 && polls >= c.maxPolls) {
			// Withdraw the request so a control API started much later does
			// not reset the administrator unexpectedly.
			if info, err := os.Lstat(requestPath); err == nil && info.Mode().IsRegular() {
				_ = os.Remove(requestPath)
			}
			return withHints("the control API did not pick up the reset request in time, so nothing was reset (the request was withdrawn)", "Is the app running? sudo shakerproxy app status", "Start it and run `sudo shakerproxy admin reset` again.", "Logs: sudo shakerproxy logs control-api")
		}
		c.sleep(500 * time.Millisecond)
	}
	c.println("Admin account reset: the password was cleared and all sessions were signed out.")
	tokenPath := envOr("SHAKERPROXY_SETUP_TOKEN_PATH", filepath.Join(directory, "setup-token"))
	if token, err := readSetupToken(tokenPath); err == nil {
		c.printf("\nNew one-time setup token: %s\n\n", c.bold(token))
	} else {
		c.printf("The new one-time setup token could not be read from %s (%v); see: sudo shakerproxy logs control-api\n", tokenPath, err)
	}
	c.printf("Finish setup: open %s and create the admin account with this token.\n", managementURLForOperators)
	c.printf("From another computer, tunnel first: %s\n", managementTunnelForRemotes)
	c.println("Then sign the CLI in again: sudo shakerproxy login")
	c.println("API tokens were NOT revoked. Review them with `sudo shakerproxy token list --password-file FILE`")
	c.println("and revoke any you no longer trust with `sudo shakerproxy token revoke`.")
	return nil
}

// readSetupToken reads the one-time setup token written by the control API.
func readSetupToken(path string) (string, error) {
	data, err := readBoundedRegularFile(path, 1024, true)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(data))
	if token == "" || strings.ContainsFunc(token, func(r rune) bool { return r < 0x21 || r > 0x7e }) {
		return "", errors.New("the file does not contain one token")
	}
	return token, nil
}

func writeRequestExclusive(path string, data []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".admin-reset-*")
	if err != nil {
		return fmt.Errorf("create reset request: %w", err)
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Link(name, path); err != nil {
		return fmt.Errorf("queue reset request without overwrite: %w", err)
	}
	return nil
}

func (c *cli) requireRoot(command string) error {
	if c.geteuid() != 0 {
		return withHints(fmt.Sprintf("%s changes the appliance and must run as root", command), fmt.Sprintf("Run `sudo shakerproxy %s`.", command))
	}
	return nil
}

func (c *cli) execLifecycle(executable string, arguments []string) error {
	if c.findExecutable(executable) == "" {
		return withHints(fmt.Sprintf("the ShakerProxy host package is not installed (missing %s)", executable), "Install ShakerProxy first: see docs/installation.md")
	}
	if err := c.execProgram(executable, append([]string{executable}, arguments...), lifecycleEnvironment); err != nil {
		return fmt.Errorf("start %s: %w", filepath.Base(executable), err)
	}
	return nil
}

func (c *cli) updateCommand(args []string) error {
	if err := c.noArgs("update", args); err != nil {
		return err
	}
	if err := c.requireRoot("update"); err != nil {
		return err
	}
	return c.execLifecycle(installerExecutable, []string{"--yes"})
}

func (c *cli) repairCommand(args []string) error {
	if err := c.noArgs("repair", args); err != nil {
		return err
	}
	if err := c.requireRoot("repair"); err != nil {
		return err
	}
	return c.execLifecycle(installerExecutable, []string{"--repair", "--yes"})
}

func (c *cli) rollbackCommand(args []string) error {
	if err := c.noArgs("rollback", args); err != nil {
		return err
	}
	if err := c.requireRoot("rollback"); err != nil {
		return err
	}
	return c.execLifecycle(installerExecutable, []string{"--rollback", "--yes"})
}

func (c *cli) uninstallCommand(args []string) error {
	flags := newFlags("uninstall")
	purge := flags.Bool("purge-data", false, "also delete configuration, secrets and recorded data")
	assumeYes := flags.Bool("yes", false, "do not ask for confirmation")
	positional, err := parseFlags("uninstall", flags, args)
	if err != nil {
		return err
	}
	if err := expectArgs("uninstall", positional, 0, 0); err != nil {
		return err
	}
	if *assumeYes && !*purge {
		return usagef("uninstall", "--yes only applies together with --purge-data.")
	}
	if err := c.requireRoot("uninstall"); err != nil {
		return err
	}
	var arguments []string
	if *purge {
		arguments = append(arguments, "--purge-data")
	}
	if *assumeYes {
		arguments = append(arguments, "--yes")
	}
	return c.execLifecycle(uninstallExecutable, arguments)
}

func (c *cli) appCommand(args []string) error {
	positional, err := parseFlags("app", newFlags("app"), args)
	if err != nil {
		return err
	}
	if len(positional) == 0 || positional[0] != "status" {
		name := ""
		if len(positional) > 0 {
			name = positional[0]
		}
		return unknownSubcommand("app", name, []string{"status"})
	}
	if err := expectArgs("app", positional[1:], 0, 0); err != nil {
		return err
	}
	if c.geteuid() != 0 {
		return withHints("app status reads root-only configuration", "Run `sudo shakerproxy app status`.")
	}
	if c.findExecutable(appLifecycleExecutable) == "" {
		return withHints(fmt.Sprintf("the ShakerProxy host package is not installed (missing %s)", appLifecycleExecutable), "Install ShakerProxy first: see docs/installation.md")
	}
	output, err := c.outputProgram(appLifecycleExecutable, []string{"status"}, lifecycleEnvironment)
	if err != nil {
		return withHints("could not read the application status: "+err.Error(), "Check the service: systemctl status shakerproxy-app", "Logs: sudo shakerproxy logs app-service")
	}
	containers, err := parseComposeStatus(output)
	if err != nil {
		return fmt.Errorf("unexpected application status output: %w", err)
	}
	if c.jsonOutput {
		return c.printJSON(map[string]any{"services": containers})
	}
	if len(containers) == 0 {
		return withHints("no application containers are running", "Start them: sudo systemctl start shakerproxy-app", "Or repair the installation: sudo shakerproxy repair")
	}
	width := len("Service")
	for _, container := range containers {
		width = max(width, len(container.Service))
	}
	c.printf("  %-*s  %-10s  %s\n", width, "Service", "State", "Health")
	var attention []string
	for _, container := range containers {
		health := orText(container.Health, "-")
		// Pad before styling so colour codes do not shift the columns.
		state := fmt.Sprintf("%-10s", container.State)
		switch {
		case container.State != "running" || container.Health == "unhealthy":
			attention = append(attention, container.Service)
			state = c.style(styleRed, state)
		case container.Health == "starting":
			health = c.style(styleYellow, health)
		default:
			state = c.style(styleGreen, state)
		}
		c.printf("  %-*s  %s  %s\n", width, sanitize(container.Service), state, sanitize(health))
	}
	if len(attention) > 0 {
		c.printf("\n%d of %d services need attention: %s\n", len(attention), len(containers), strings.Join(attention, ", "))
		c.printf("Logs: sudo shakerproxy logs %s\n", attention[0])
		return &silentFailure{code: exitFailure}
	}
	c.printf("\nAll %d services are running.\n", len(containers))
	return nil
}

// appService is one line of `docker compose ps --format json`.
type appService struct {
	Service string `json:"Service"`
	State   string `json:"State"`
	Health  string `json:"Health"`
	Status  string `json:"Status"`
}

// parseComposeStatus reads Compose's JSON output: one object per line, or
// one array in older Compose releases. Other lines (warnings) are skipped.
func parseComposeStatus(output []byte) ([]appService, error) {
	trimmed := bytes.TrimSpace(output)
	if bytes.HasPrefix(trimmed, []byte("[")) {
		var services []appService
		return services, json.Unmarshal(trimmed, &services)
	}
	var services []appService
	for _, line := range bytes.Split(trimmed, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if !bytes.HasPrefix(line, []byte("{")) {
			continue
		}
		var service appService
		if err := json.Unmarshal(line, &service); err != nil {
			return nil, err
		}
		services = append(services, service)
	}
	sort.Slice(services, func(i, j int) bool { return services[i].Service < services[j].Service })
	return services, nil
}

func (c *cli) managementCACommand(args []string) error {
	positional, err := parseFlags("management-ca", newFlags("management-ca"), args)
	if err != nil {
		return err
	}
	subcommand := ""
	if len(positional) > 0 {
		subcommand = positional[0]
	}
	if subcommand != "status" && subcommand != "export" {
		return unknownSubcommand("management-ca", subcommand, []string{"status", "export"})
	}
	certificatePath := envOr("SHAKERPROXY_MANAGEMENT_CA_PATH", defaultManagementCA)
	statusPath := envOr("SHAKERPROXY_MANAGEMENT_PKI_STATUS_PATH", "/var/lib/shakerproxy/public/management-pki.json")
	certificate, status, err := managementpki.LoadPublic(certificatePath, statusPath)
	if err != nil {
		return err
	}
	if subcommand == "status" {
		if err := expectArgs("management-ca", positional[1:], 0, 0); err != nil {
			return err
		}
		return c.printJSON(status)
	}
	if err := expectArgs("management-ca", positional[1:], 1, 1, "destination file"); err != nil {
		return err
	}
	destination, err := filepath.Abs(positional[1])
	if err != nil {
		return fmt.Errorf("resolve management CA destination: %w", err)
	}
	if _, err := os.Lstat(destination); err == nil {
		return errors.New("refusing to overwrite an existing management CA export")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect management CA destination: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(destination), ".shakerproxy-management-ca-*")
	if err != nil {
		return fmt.Errorf("create management CA export: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o644); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(certificate); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Link(temporaryName, destination); err != nil {
		return fmt.Errorf("publish management CA without overwrite: %w", err)
	}
	if err := os.Remove(temporaryName); err != nil {
		return err
	}
	return c.printJSON(map[string]any{"destination": destination, "purpose": status.Purpose, "sha256_fingerprint": status.SHA256Fingerprint})
}

func (c *cli) rulesCommand(args []string) error {
	subcommand := ""
	if len(args) > 0 {
		subcommand = args[0]
	}
	switch subcommand {
	case "status", "preview", "update", "rollback", "pin":
	default:
		return unknownSubcommand("rules", subcommand, []string{"status", "preview", "update", "rollback", "pin"})
	}
	manager := signedcontent.Manager{
		Root:          envOr("SHAKERPROXY_SIGNED_CONTENT_ROOT", "/var/lib/shakerproxy/rulesets"),
		PublicKeyPath: envOr("SHAKERPROXY_RELEASE_PUBLIC_KEY", "/usr/libexec/shakerproxy/release-public.pem"),
	}
	rest := args[1:]
	if subcommand == "status" {
		if err := expectArgs("rules", rest, 0, 0); err != nil {
			return err
		}
		state, err := manager.Status()
		if err != nil {
			return err
		}
		return c.printJSON(state)
	}
	if c.geteuid() != 0 {
		return withHints("signed rules and catalog changes require root", fmt.Sprintf("Run `sudo shakerproxy rules %s ...`.", subcommand))
	}
	switch subcommand {
	case "preview", "update":
		if err := expectArgs("rules", rest, 1, 1, "signed bundle file"); err != nil {
			return err
		}
	case "rollback":
		if err := expectArgs("rules", rest, 1, 1, "content kind (suricata, zeek or resolver)"); err != nil {
			return err
		}
	case "pin":
		if err := expectArgs("rules", rest, 2, 2, "content kind (suricata, zeek or resolver)", "revision or none"); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	lock := configlock.Manager{Path: envOr("SHAKERPROXY_CONFIG_LOCK", configlock.DefaultPath)}
	guard, err := lock.Acquire(ctx, configlock.Request{OperationID: "rules-cli-" + randomHex(8), Category: configlock.CategoryRuleset, Actor: "local-cli"})
	if err != nil {
		return err
	}
	defer guard.Release()
	state, err := manager.Status()
	if err != nil {
		return err
	}
	var result any
	switch subcommand {
	case "preview":
		bundle, err := signedcontent.LoadBundle(rest[0])
		if err != nil {
			return err
		}
		result, err = manager.Preview(bundle)
		if err != nil {
			return err
		}
	case "update":
		bundle, err := signedcontent.LoadBundle(rest[0])
		if err != nil {
			return err
		}
		result, err = manager.Apply(bundle, state.Revision, "local-cli")
		if err != nil {
			return err
		}
	case "rollback":
		kind, err := parseSignedContentKind(rest[0])
		if err != nil {
			return usagef("rules", "%s.", capitalize(err.Error()))
		}
		result, err = manager.Rollback(kind, state.Revision, "local-cli")
		if err != nil {
			return err
		}
	case "pin":
		kind, err := parseSignedContentKind(rest[0])
		if err != nil {
			return usagef("rules", "%s.", capitalize(err.Error()))
		}
		revision := rest[1]
		if revision == "none" {
			revision = ""
		}
		result, err = manager.Pin(kind, revision, state.Revision, "local-cli")
		if err != nil {
			return err
		}
	}
	return c.printJSON(result)
}

func parseSignedContentKind(value string) (signedcontent.Kind, error) {
	switch value {
	case "suricata":
		return signedcontent.SuricataRules, nil
	case "zeek":
		return signedcontent.ZeekPackages, nil
	case "resolver":
		return signedcontent.ResolverCatalog, nil
	default:
		return "", errors.New("content kind must be suricata, zeek, or resolver")
	}
}
