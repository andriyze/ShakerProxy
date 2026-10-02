package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"shakerproxy.dev/shakerproxy/internal/capture"
	"shakerproxy.dev/shakerproxy/internal/gatewayclient"
	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/networkplan"
)

func (c *cli) gateway() gatewayclient.Client { return gatewayclient.Client{SocketPath: c.socket} }

// gatewayCall calls the privileged daemon with its per-method budget and
// explains socket problems.
func (c *cli) gatewayCall(method string, params, result any) error {
	return c.gatewayCallContext(context.Background(), method, params, result)
}

func (c *cli) gatewayCallContext(ctx context.Context, method string, params, result any) error {
	if err := c.gateway().Call(ctx, method, params, result); err != nil {
		return c.gatewayError(err)
	}
	return nil
}

func (c *cli) gatewayError(err error) error {
	socket := c.socket
	var netErr net.Error
	switch {
	case errors.Is(err, syscall.ENOENT):
		return withHints(fmt.Sprintf("the ShakerProxy gateway daemon is not running (no socket at %s)", socket), "Start it: sudo systemctl start shakerproxy-gatewayd", "Details: systemctl status shakerproxy-gatewayd")
	case errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM):
		return withHints(fmt.Sprintf("permission denied on %s", socket), "Run the command with sudo, or add your user to the shakerproxy-host group (sudo usermod -aG shakerproxy-host $USER, then log in again).")
	case errors.Is(err, syscall.ECONNREFUSED):
		return withHints(fmt.Sprintf("the gateway daemon socket %s is not accepting connections", socket), "Restart it: sudo systemctl restart shakerproxy-gatewayd", "Logs: sudo shakerproxy logs gatewayd")
	case errors.As(err, &netErr) && netErr.Timeout(), errors.Is(err, os.ErrDeadlineExceeded), errors.Is(err, context.DeadlineExceeded):
		return withHints("the gateway daemon did not answer in time", "Check it: systemctl status shakerproxy-gatewayd", "Logs: sudo shakerproxy logs gatewayd")
	}
	var remote *gatewayclient.RemoteError
	if errors.As(err, &remote) {
		return errors.New(sanitize(remote.Message))
	}
	return err
}

func (c *cli) noArgs(command string, args []string) error {
	positional, err := parseFlags(command, newFlags(command), args)
	if err != nil {
		return err
	}
	return expectArgs(command, positional, 0, 0)
}

func (c *cli) statusCommand(args []string) error {
	if err := c.noArgs("status", args); err != nil {
		return err
	}
	var status gatewayprotocol.Status
	if err := c.gatewayCall("GetManagedState", gatewayprotocol.EmptyParams{}, &status); err != nil {
		return err
	}
	if c.jsonOutput {
		return c.printJSON(status)
	}
	now := c.now()
	header := fmt.Sprintf("ShakerProxy gateway daemon %s (API %s)", status.DaemonVersion, status.APIVersion)
	if started, ok := parseTime(status.StartedAt); ok {
		header += ", running for " + humanDuration(now.Sub(started))
	}
	c.println(c.bold(header))
	c.println()
	rows := [][2]string{{"Mode", modeText(status.OperatingMode)}}
	bypass := "off"
	if status.EmergencyBypass {
		bypass = c.style(styleYellow, "ON — traffic passes without inspection (shakerproxy bypass disable)")
	}
	rows = append(rows, [2]string{"Emergency bypass", bypass})
	plan := "none applied yet"
	if staged := status.StagedNetworkPlan; staged != nil {
		plan = strings.ToLower(strings.ReplaceAll(staged.Status, "_", " "))
		if staged.ConfirmBy != nil && staged.Status != "CONFIRMED" {
			plan += fmt.Sprintf(" (confirm by %s)", staged.ConfirmBy.Local().Format("15:04:05"))
		}
		plan += " · " + shortHash(staged.PlanHash)
	}
	// A staged candidate does not replace the plan the host is running.
	if confirmed := status.ConfirmedNetworkPlan; confirmed != nil {
		plan = "confirmed · " + shortHash(confirmed.PlanHash) + "; new plan " + plan
	}
	rows = append(rows, [2]string{"Network plan", plan})
	lab := "-"
	if status.LabInterface != "" {
		lab = status.LabInterface
		if status.LabVLANID != nil {
			lab += fmt.Sprintf(" (VLAN %d)", *status.LabVLANID)
		}
	}
	rows = append(rows, [2]string{"Lab interface", lab})
	captureText := "not available in this daemon profile"
	if status.CaptureAvailable {
		captureText = "ready, nothing recording"
		if status.ActiveCaptureID != "" {
			captureText = c.style(styleGreen, "recording") + " " + status.ActiveCaptureID
		}
		if recording := status.LabRecording; recording != nil {
			captureText = labRecordingText(c, *recording)
		}
	}
	rows = append(rows, [2]string{"Capture", captureText})
	policy := "not available in this daemon profile"
	if status.TrafficPolicyAvailable {
		policy = "available"
	}
	rows = append(rows, [2]string{"DNS & HTTPS policy", policy})
	lock := "free"
	if status.ConfigurationLock != nil && status.ConfigurationLock.Active {
		lock = "held"
		if record := status.ConfigurationLock.Record; record != nil {
			lock = fmt.Sprintf("held by %s (%s)", record.Category, record.OperationID)
		}
	}
	rows = append(rows, [2]string{"Config lock", lock})
	for _, row := range rows {
		c.printf("  %-19s %s\n", row[0], row[1])
	}
	if len(status.Warnings) > 0 {
		c.println()
		for _, warning := range status.Warnings {
			c.printf("%s %s\n", c.style(styleYellow, "!"), warning)
		}
	}
	c.println()
	switch {
	case status.OperatingMode == gatewayprotocol.ModeSetupSafe && status.StagedNetworkPlan == nil:
		c.println("Next: open https://127.0.0.1:8443/ and finish Network setup, or run `shakerproxy doctor`.")
	case status.EmergencyBypass:
		c.println("Next: fix the problem, then `sudo shakerproxy bypass disable`.")
	default:
		c.println("Next: shakerproxy devices · shakerproxy watch · shakerproxy doctor")
	}
	return nil
}

func modeText(mode string) string {
	switch mode {
	case gatewayprotocol.ModeSetupSafe:
		return "setup (safe) — ShakerProxy is not routing lab traffic yet"
	case gatewayprotocol.ModeRouted:
		return "routing lab traffic"
	case gatewayprotocol.ModeEmergency:
		return "emergency bypass"
	default:
		return orDash(mode)
	}
}

func shortHash(value string) string {
	value = strings.TrimPrefix(value, "sha256:")
	if len(value) > 12 {
		return value[:12]
	}
	return orDash(value)
}

func (c *cli) doctorCommand(args []string) error {
	flags := newFlags("doctor")
	verbose := flags.Bool("verbose", false, "show observations for passing checks too")
	flags.BoolVar(verbose, "v", false, "show observations for passing checks too")
	positional, err := parseFlags("doctor", flags, args)
	if err != nil {
		return err
	}
	if err := expectArgs("doctor", positional, 0, 0); err != nil {
		return err
	}
	var report gatewayprotocol.DiagnosticReport
	if err := c.gatewayCall("GetDiagnostics", gatewayprotocol.EmptyParams{}, &report); err != nil {
		return err
	}
	failed := report.Overall == gatewayprotocol.DiagnosticFail
	if c.jsonOutput {
		if err := c.printJSON(report); err != nil {
			return err
		}
		if failed {
			return &silentFailure{code: exitFailure}
		}
		return nil
	}
	c.printf("%s overall %s\n\n", c.bold("ShakerProxy doctor:"), c.statusWord(string(report.Overall)))
	nameWidth := 8
	for _, check := range report.Checks {
		nameWidth = max(nameWidth, len(check.Name))
	}
	counts := map[gatewayprotocol.DiagnosticStatus]int{}
	for _, check := range report.Checks {
		counts[check.Status]++
		label := string(check.Status)
		if check.Status == gatewayprotocol.DiagnosticWarning {
			label = "WARN"
		}
		c.printf("  %s  %-*s  %s\n", padStatus(c, label), nameWidth, check.Name, sanitize(check.Summary))
		if check.Status != gatewayprotocol.DiagnosticPass || *verbose {
			for _, observation := range check.Observations {
				c.printf("  %s  %-*s  %s\n", strings.Repeat(" ", 7), nameWidth, "", c.dim("• "+sanitize(observation)))
			}
		}
	}
	c.printf("\n%d passed, %d warnings, %d failed, %d unknown.\n", counts[gatewayprotocol.DiagnosticPass], counts[gatewayprotocol.DiagnosticWarning], counts[gatewayprotocol.DiagnosticFail], counts[gatewayprotocol.DiagnosticUnknown])
	if failed {
		c.println("Fix the FAIL items above; `shakerproxy logs` shows service logs.")
		return &silentFailure{code: exitFailure}
	}
	return nil
}

func padStatus(c *cli, label string) string {
	padded := fmt.Sprintf("%-7s", label)
	return strings.Replace(padded, label, c.statusWord(label), 1)
}

func (c *cli) portsCommand(args []string) error {
	if err := c.noArgs("ports", args); err != nil {
		return err
	}
	var plan gatewayprotocol.ServicePortPlan
	if err := c.gatewayCall("GetServicePortPlan", gatewayprotocol.EmptyParams{}, &plan); err != nil {
		return err
	}
	if c.jsonOutput {
		return c.printJSON(plan)
	}
	listing := newTable("PORT", "PURPOSE", "STATE", "LISTENING NOW", "ACTION")
	for _, reservation := range plan.Reservations {
		var listeners []string
		for _, listener := range reservation.Listeners {
			entry := fmt.Sprintf("%s:%d", listener.Address, listener.Port)
			if listener.Process != "" {
				entry += " (" + listener.Process + ")"
			}
			listeners = append(listeners, entry)
		}
		listing.add(fmt.Sprintf("%d/%s", reservation.Port, reservation.Transport), reservation.Purpose, c.statusWord(reservation.State), joinLimited(listeners, 2), orDash(reservation.Action))
	}
	listing.render(c.stdout, c)
	if plan.ResolverHandling != "" {
		c.printf("\nResolver: %s\n", plan.ResolverHandling)
	}
	return nil
}

func (c *cli) probeCommand(args []string) error {
	if err := c.noArgs("probe-connectivity", args); err != nil {
		return err
	}
	var report gatewayprotocol.ConnectivityReport
	if err := c.gatewayCall("ProbeConnectivity", gatewayprotocol.EmptyParams{}, &report); err != nil {
		return err
	}
	if c.jsonOutput {
		return c.printJSON(report)
	}
	listing := newTable("PROBE", "TARGET", "RESULT", "LATENCY", "DETAIL")
	for _, probe := range report.Probes {
		latency := "-"
		if probe.LatencyMillis > 0 {
			latency = fmt.Sprintf("%d ms", probe.LatencyMillis)
		}
		listing.add(probe.Name, probe.Target, c.statusWord(string(probe.Status)), latency, sanitize(probe.Detail))
	}
	listing.render(c.stdout, c)
	c.println()
	switch {
	case report.RestrictedPort53:
		c.println("HTTPS works but plain DNS (TCP/UDP 53) is blocked upstream — use an upstream resolver the network allows.")
	case report.DNSIndependentHTTPS && report.PlainDNSPort53:
		c.println("Internet reachable over HTTPS and plain DNS.")
	case !report.DNSIndependentHTTPS:
		c.println("HTTPS to fixed internet addresses failed — check the WAN link and upstream firewall.")
	}
	return nil
}

func bypassMethod(action string) string {
	if action == "enable" {
		return "EnableEmergencyBypass"
	}
	return "DisableEmergencyBypass"
}

func (c *cli) bypassCommand(args []string) error {
	positional, err := parseFlags("bypass", newFlags("bypass"), args)
	if err != nil {
		return err
	}
	if len(positional) == 0 || (positional[0] != "enable" && positional[0] != "disable" && positional[0] != "on" && positional[0] != "off") {
		name := ""
		if len(positional) > 0 {
			name = positional[0]
		}
		return unknownSubcommand("bypass", name, []string{"enable", "disable"})
	}
	if err := expectArgs("bypass", positional, 1, 1); err != nil {
		return err
	}
	action := positional[0]
	if action == "on" {
		action = "enable"
	} else if action == "off" {
		action = "disable"
	}
	var result map[string]any
	if err := c.gatewayCall(bypassMethod(action), gatewayprotocol.EmptyParams{}, &result); err != nil {
		return err
	}
	if c.jsonOutput {
		return c.printJSON(result)
	}
	if action == "enable" {
		c.println("Emergency bypass is ON: lab traffic passes without inspection or policy. Turn it off with `sudo shakerproxy bypass disable`.")
	} else {
		c.println("Emergency bypass is off: inspection and policy are active again.")
	}
	return nil
}

func readPlan(path string) (networkplan.Plan, error) {
	data, err := readBoundedRegularFile(path, 1<<20, false)
	if err != nil {
		return networkplan.Plan{}, fmt.Errorf("read network plan %s: %w", path, err)
	}
	var plan networkplan.Plan
	if err := gatewayprotocol.DecodeStrict(bytes.NewReader(data), &plan, 1<<20); err != nil {
		return networkplan.Plan{}, withHints(fmt.Sprintf("network plan %s is not valid JSON for this version: %v", path, err), "The format is described by schemas/network-plan/network-plan.schema.json.")
	}
	return plan, nil
}

func (c *cli) printValidation(validation networkplan.ValidationResult) {
	if validation.Valid {
		c.printf("%s plan is valid for this host (hash %s).\n", c.style(styleGreen, "✓"), shortHash(validation.PlanHash))
	} else {
		c.printf("%s plan is not valid for this host.\n", c.style(styleRed, "✗"))
	}
	for _, issue := range validation.Errors {
		c.printf("  %s %s: %s\n", c.statusWord("FAIL"), orDash(issue.Path), sanitize(issue.Message))
	}
	for _, issue := range validation.Warnings {
		c.printf("  %s %s: %s\n", c.statusWord("WARN"), orDash(issue.Path), sanitize(issue.Message))
	}
}

func (c *cli) configCommand(args []string) error {
	positional, err := parseFlags("config", newFlags("config"), args)
	if err != nil {
		return err
	}
	if len(positional) == 0 || positional[0] != "validate" {
		name := ""
		if len(positional) > 0 {
			name = positional[0]
		}
		return unknownSubcommand("config", name, []string{"validate"})
	}
	if err := expectArgs("config", positional[1:], 1, 1, "plan file"); err != nil {
		return err
	}
	plan, err := readPlan(positional[1])
	if err != nil {
		return err
	}
	var validation networkplan.ValidationResult
	if err := c.gatewayCall("ValidateNetworkPlan", gatewayprotocol.ValidateNetworkPlanParams{Plan: plan}, &validation); err != nil {
		return err
	}
	if c.jsonOutput {
		if err := c.printJSON(validation); err != nil {
			return err
		}
	} else {
		c.printValidation(validation)
	}
	if !validation.Valid {
		return &silentFailure{code: exitFailure}
	}
	return nil
}

func (c *cli) planCommand(args []string) error {
	positional, err := parseFlags("plan", newFlags("plan"), args)
	if err != nil {
		return err
	}
	if len(positional) == 2 && positional[0] == "preview" {
		positional = positional[1:]
	}
	if err := expectArgs("plan", positional, 1, 1, "plan file"); err != nil {
		return err
	}
	plan, err := readPlan(positional[0])
	if err != nil {
		return err
	}
	var preview networkplan.Preview
	if err := c.gatewayCall("PreviewNetworkPlan", gatewayprotocol.PreviewNetworkPlanParams{Plan: plan}, &preview); err != nil {
		return err
	}
	if c.jsonOutput {
		return c.printJSON(preview)
	}
	c.printValidation(preview.Validation)
	if len(preview.Impact) > 0 {
		c.printf("\n%s\n", c.bold("Impact"))
		for _, impact := range preview.Impact {
			c.printf("  • %s\n", sanitize(impact))
		}
	}
	if len(preview.ChangedObjects) > 0 {
		c.printf("\n%s\n", c.bold("Would change"))
		for _, object := range preview.ChangedObjects {
			c.printf("  • %s\n", sanitize(object))
		}
	}
	c.printf("\nFirewall backend: %s. Nothing was changed; apply plans from the web UI (Network).\n", orDash(preview.FirewallBackend))
	c.println("Full preview (netplan, DHCP, firewall rules): shakerproxy plan " + positional[0] + " --json")
	return nil
}

func newCaptureIdempotencyKey() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", errors.New("could not generate capture request identity")
	}
	return fmt.Sprintf("capture-cli-%x", value), nil
}

func (c *cli) captureCommand(args []string) error {
	subcommand := ""
	if len(args) > 0 {
		subcommand = args[0]
	}
	switch subcommand {
	case "start":
		return c.captureStart(args[1:])
	case "stop":
		return c.captureStop(args[1:])
	case "list", "ls":
		return c.captureList(args[1:])
	case "stats", "show", "info":
		return c.captureStats(args[1:])
	case "export":
		return c.captureExport(args[1:])
	case "auto":
		return c.captureAuto(args[1:])
	default:
		return unknownSubcommand("capture", subcommand, []string{"start", "stop", "list", "stats", "export", "auto"})
	}
}

// captureAuto shows or changes automatic lab recording: gatewayd records the
// lab whenever a confirmed lab plan routes, unless it is turned off.
func (c *cli) captureAuto(args []string) error {
	if err := expectArgs("capture", args, 0, 1, "on|off"); err != nil {
		return err
	}
	var recording gatewayprotocol.LabRecordingStatus
	switch {
	case len(args) == 0:
		var status gatewayprotocol.Status
		if err := c.gatewayCall("GetManagedState", gatewayprotocol.EmptyParams{}, &status); err != nil {
			return err
		}
		if status.LabRecording == nil {
			return withHints("automatic lab recording is not available in this daemon profile", "Check the gateway: shakerproxy status")
		}
		recording = *status.LabRecording
	case args[0] == "on" || args[0] == "off":
		if err := c.gatewayCall("SetLabRecording", gatewayprotocol.SetLabRecordingParams{Enabled: args[0] == "on"}, &recording); err != nil {
			return err
		}
	default:
		return usagef("capture", "capture auto takes on or off.")
	}
	if c.jsonOutput {
		return c.printJSON(recording)
	}
	c.println("Automatic lab recording: " + labRecordingText(c, recording))
	return nil
}

func labRecordingText(c *cli, recording gatewayprotocol.LabRecordingStatus) string {
	switch {
	case recording.Recording && recording.Manual:
		return c.style(styleGreen, "recording") + " " + recording.SessionID + " (manual capture; automatic recording resumes when it ends)"
	case recording.Recording:
		return c.style(styleGreen, "recording lab traffic") + " " + recording.SessionID
	case !recording.Enabled:
		return "off. Turn it on: sudo shakerproxy capture auto on"
	default:
		return "not recording. " + recording.Reason
	}
}

func (c *cli) captureStart(args []string) error {
	flags := newFlags("capture start")
	name := flags.String("name", "", "capture name")
	description := flags.String("description", "", "capture description")
	deviceRef := flags.String("device", "", "label the capture with this device")
	mode := flags.String("mode", "full", "full (default; shows domains) or headers")
	full := flags.Bool("full", false, "keep whole packets (the default)")
	headersOnly := flags.Bool("headers-only", false, "keep only the first 256 bytes of each packet (no domains)")
	minutes := flags.Int("minutes", 0, "stop automatically after this many minutes (default 60)")
	snapLength := flags.Int("snap-length", 0, "captured bytes per packet; zero selects the profile default")
	segmentSize := flags.Int("segment-size-mib", capture.DefaultSegmentSizeMiB, "rotated segment size")
	segmentSeconds := flags.Int("segment-seconds", capture.DefaultSegmentSeconds, "rotated segment duration")
	maxFiles := flags.Int("max-files", capture.DefaultMaxFiles, "ring file count")
	stopAfter := flags.Int("stop-after-seconds", capture.DefaultStopAfterSeconds, "absolute session duration")
	caseID := flags.String("case-id", "", "optional case identifier")
	reason := flags.String("reason", "local administrator requested capture", "capture start reason")
	retentionLock := flags.Bool("retention-lock", false, "protect the session from automatic retention")
	positional, err := parseFlags("capture", flags, args)
	if err != nil {
		return err
	}
	if err := expectArgs("capture", positional, 0, 0); err != nil {
		return err
	}
	// Whole packets by default: TLS and QUIC handshakes, which carry the
	// domain a device connects to, span 500-1800 bytes and often two packets.
	captureMode := capture.ModeFull
	switch {
	case *headersOnly || *mode == "headers":
		if *full {
			return usagef("capture", "--full and --headers-only cannot be combined.")
		}
		captureMode = capture.ModeHeaders
	case *mode != "full":
		return usagef("capture", "--mode must be full or headers.")
	}
	if *minutes != 0 {
		if *minutes < 1 || *minutes > 24*60 {
			return usagef("capture", "--minutes must be between 1 and 1440.")
		}
		*stopAfter = *minutes * 60
	}
	label := strings.TrimSpace(*deviceRef)
	if label != "" {
		if err := checkRef("capture", label); err != nil {
			return err
		}
		// Use the device's friendly name when the API is reachable; the
		// capture itself always covers the whole lab network.
		if session, err := c.openAPI(); err == nil {
			if match, err := c.resolveDevice(session, "capture", label); err == nil {
				label = orText(sanitize(match.FriendlyName), match.DeviceID)
				if *description == "" {
					*description = fmt.Sprintf("Device under test: %s (%s)", label, match.DeviceID)
				}
			}
		}
		if *description == "" {
			*description = "Device under test: " + label
		}
	}
	if *name == "" {
		base := "capture"
		if label != "" {
			base = label
		}
		*name = fmt.Sprintf("%s %s", base, c.now().Format("2006-01-02 15:04"))
	}
	key, err := newCaptureIdempotencyKey()
	if err != nil {
		return err
	}
	request := capture.StartRequest{
		Name: *name, Description: *description, Mode: captureMode, SnapLength: *snapLength,
		SegmentSizeMiB: *segmentSize, SegmentSeconds: *segmentSeconds, MaxFiles: *maxFiles,
		StopAfterSeconds: *stopAfter, RetentionLock: *retentionLock, CaseID: *caseID,
		IdempotencyKey: key, Administrator: "local-cli", StartReason: *reason,
	}
	if err := request.WithDefaults().Validate(); err != nil {
		return usagef("capture", "%s.", capitalize(err.Error()))
	}
	var view capture.View
	if err := c.gatewayCall("StartCapture", gatewayprotocol.StartCaptureParams{Request: request}, &view); err != nil {
		return err
	}
	if c.jsonOutput {
		return c.printJSON(view)
	}
	modeLabel := "headers-only"
	if view.Session.Request.Mode == capture.ModeFull {
		modeLabel = "full-packet"
	}
	c.printf("Recording %q (%s), %s, stops automatically after %s.\n", sanitize(view.Session.Request.Name), view.Session.ID, modeLabel, humanDuration(time.Duration(view.Session.Request.StopAfterSeconds)*time.Second))
	c.println("Stop it:   " + commandHint("shakerproxy capture stop --wait"))
	c.printf("Export it: sudo shakerproxy capture export %s --all ./pcaps\n", view.Session.ID)
	return nil
}

func (c *cli) listCaptures() ([]capture.View, error) {
	var views []capture.View
	if err := c.gatewayCall("ListCaptures", gatewayprotocol.EmptyParams{}, &views); err != nil {
		return nil, err
	}
	return views, nil
}

func (c *cli) captureStop(args []string) error {
	flags := newFlags("capture stop")
	wait := flags.Bool("wait", false, "wait until the capture files are sealed")
	timeout := flags.Duration("timeout", 2*time.Minute, "how long --wait waits")
	positional, err := parseFlags("capture", flags, args)
	if err != nil {
		return err
	}
	if err := expectArgs("capture", positional, 0, 1); err != nil {
		return err
	}
	var sessionID string
	if len(positional) == 1 {
		if !capture.ValidSessionID(positional[0]) {
			return usagef("capture", "%q is not a capture ID (see `shakerproxy capture list`).", positional[0])
		}
		sessionID = positional[0]
	} else {
		views, err := c.listCaptures()
		if err != nil {
			return err
		}
		for _, view := range views {
			if view.Active {
				sessionID = view.Session.ID
				break
			}
		}
		if sessionID == "" {
			c.println("No capture is running.")
			return nil
		}
	}
	var view capture.View
	if err := c.gatewayCall("StopCapture", gatewayprotocol.StopCaptureParams{SessionID: sessionID}, &view); err != nil {
		return err
	}
	if *wait {
		deadline := c.now().Add(*timeout)
		for polls := 1; view.Active || view.Manifest == nil; polls++ {
			if c.now().After(deadline) || (c.maxPolls > 0 && polls > c.maxPolls) {
				return withHints(fmt.Sprintf("capture %s is still finishing", sessionID), "Check again: shakerproxy capture stats "+sessionID)
			}
			c.sleep(time.Second)
			if err := c.gatewayCall("GetCaptureStats", gatewayprotocol.GetCaptureStatsParams{SessionID: sessionID}, &view); err != nil {
				return err
			}
		}
	}
	if c.jsonOutput {
		return c.printJSON(view)
	}
	if view.Session.Request.Automatic {
		c.println("Automatic lab recording is now off. Turn it back on: sudo shakerproxy capture auto on")
	}
	if view.Manifest != nil {
		c.printf("Stopped %s: %s in %s, %s packets.\n", sessionID, humanBytes(view.Manifest.TotalSizeBytes), plural(len(view.Manifest.Files), "file", "files"), humanCount(int64(view.Manifest.PacketsCaptured)))
		c.printf("Export it: sudo shakerproxy capture export %s --all ./pcaps\n", sessionID)
		return nil
	}
	c.printf("Stopping %s; its files are being sealed. Use --wait to wait for them.\n", sessionID)
	return nil
}

func (c *cli) captureList(args []string) error {
	if err := c.noArgs("capture", args); err != nil {
		return err
	}
	views, err := c.listCaptures()
	if err != nil {
		return err
	}
	if c.jsonOutput {
		return c.printJSON(views)
	}
	if len(views) == 0 {
		c.println("No captures yet. Start one: sudo shakerproxy capture start")
		return nil
	}
	listing := newTable("ID", "NAME", "STATE", "STARTED", "SIZE", "FILES")
	for _, view := range views {
		size, files := view.CurrentBytes, view.CurrentFiles
		if view.Manifest != nil {
			size, files = view.Manifest.TotalSizeBytes, len(view.Manifest.Files)
		}
		state := string(view.State)
		if view.Active {
			state = "RUNNING"
		}
		listing.add(view.Session.ID, sanitize(view.Session.Request.Name), c.statusWord(state), view.Session.StartedAt.Local().Format("2006-01-02 15:04"), humanBytes(size), fmt.Sprint(files))
	}
	listing.render(c.stdout, c)
	return nil
}

func (c *cli) captureStats(args []string) error {
	positional, err := parseFlags("capture", newFlags("capture stats"), args)
	if err != nil {
		return err
	}
	if err := expectArgs("capture", positional, 1, 1, "capture ID"); err != nil {
		return err
	}
	if !capture.ValidSessionID(positional[0]) {
		return usagef("capture", "%q is not a capture ID (see `shakerproxy capture list`).", positional[0])
	}
	var view capture.View
	if err := c.gatewayCall("GetCaptureStats", gatewayprotocol.GetCaptureStatsParams{SessionID: positional[0]}, &view); err != nil {
		return err
	}
	if c.jsonOutput {
		return c.printJSON(view)
	}
	c.printf("%s  %s\n", c.bold(view.Session.ID), c.statusWord(string(view.State)))
	c.printf("  Name      %s\n", sanitize(view.Session.Request.Name))
	if view.Session.Request.Description != "" {
		c.printf("  About     %s\n", sanitize(view.Session.Request.Description))
	}
	c.printf("  Interface %s\n", view.Session.Source.InterfaceName)
	c.printf("  Started   %s, stops by %s\n", view.Session.StartedAt.Local().Format("2006-01-02 15:04:05"), view.Session.StopAt.Local().Format("15:04:05"))
	if view.Manifest != nil {
		c.printf("  Sealed    %s in %s, %s packets (%d kernel drops)\n", humanBytes(view.Manifest.TotalSizeBytes), plural(len(view.Manifest.Files), "file", "files"), humanCount(int64(view.Manifest.PacketsCaptured)), view.Manifest.KernelDrops)
		for _, file := range view.Manifest.Files {
			c.printf("            %s  %s\n", file.Name, humanBytes(file.SizeBytes))
		}
	} else {
		c.printf("  So far    %s in %s\n", humanBytes(view.CurrentBytes), plural(view.CurrentFiles, "file", "files"))
	}
	return nil
}

func (c *cli) captureExport(args []string) error {
	flags := newFlags("capture export")
	allDirectory := flags.String("all", "", "export every file into this directory")
	positional, err := parseFlags("capture", flags, args)
	if err != nil {
		return err
	}
	if len(positional) == 0 {
		return usagef("capture", "Missing capture ID (see `shakerproxy capture list`).")
	}
	if !capture.ValidSessionID(positional[0]) {
		return usagef("capture", "%q is not a capture ID (see `shakerproxy capture list`).", positional[0])
	}
	sessionID := positional[0]
	switch {
	case len(positional) == 3 && *allDirectory == "":
		result, err := exportCaptureFile(context.Background(), c.gateway(), sessionID, positional[1], positional[2])
		if err != nil {
			return c.explainExportError(err)
		}
		if c.jsonOutput {
			return c.printJSON(result)
		}
		c.printf("Exported %s → %s (%s, SHA-256 verified).\n", result.FileName, result.Destination, humanBytes(result.SizeBytes))
		return nil
	case len(positional) == 1:
		directory := *allDirectory
		if directory == "" {
			directory = "."
		}
		results, err := exportCaptureAll(context.Background(), c.gateway(), sessionID, directory)
		if err != nil {
			return c.explainExportError(err)
		}
		if c.jsonOutput {
			return c.printJSON(results)
		}
		var total int64
		for _, result := range results {
			total += result.SizeBytes
			c.printf("  %s  %s\n", result.Destination, humanBytes(result.SizeBytes))
		}
		c.printf("Exported %s (%s, SHA-256 verified). Open them in Wireshark.\n", plural(len(results), "file", "files"), humanBytes(total))
		return nil
	default:
		return usagef("capture", "Use `capture export <id> [--all DIR]` or `capture export <id> <file-name> <destination>`.")
	}
}

func (c *cli) explainExportError(err error) error {
	var hinted *hintError
	if errors.As(err, &hinted) {
		return err
	}
	var netErr net.Error
	if errors.Is(err, syscall.ENOENT) && strings.Contains(err.Error(), "connect to gateway daemon") || errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.ECONNREFUSED) || errors.As(err, &netErr) {
		return c.gatewayError(err)
	}
	return err
}

type exportResult struct {
	SessionID   string `json:"session_id"`
	FileName    string `json:"file_name"`
	Destination string `json:"destination"`
	SizeBytes   int64  `json:"size_bytes"`
	SHA256      string `json:"sha256"`
	Verified    bool   `json:"verified"`
}

func finalizedCaptureView(ctx context.Context, client gatewayclient.Client, sessionID string) (capture.View, error) {
	var view capture.View
	if err := gatewayCall(ctx, client, "GetCaptureStats", gatewayprotocol.GetCaptureStatsParams{SessionID: sessionID}, &view); err != nil {
		return capture.View{}, err
	}
	if view.Active || view.Manifest == nil {
		return capture.View{}, withHints("capture must be finalized before export", "Stop it first: sudo shakerproxy capture stop "+sessionID+" --wait")
	}
	return view, nil
}

// exportCaptureAll exports every sealed file into directory, refusing to
// overwrite anything.
func exportCaptureAll(ctx context.Context, client gatewayclient.Client, sessionID, directory string) ([]exportResult, error) {
	view, err := finalizedCaptureView(ctx, client, sessionID)
	if err != nil {
		return nil, err
	}
	directory, err = filepath.Abs(directory)
	if err != nil {
		return nil, err
	}
	if err := createExportDirectory(directory); err != nil {
		return nil, err
	}
	results := make([]exportResult, 0, len(view.Manifest.Files))
	for _, file := range view.Manifest.Files {
		if strings.ContainsAny(file.Name, `/\`) || file.Name == "" || file.Name == "." || file.Name == ".." {
			return results, fmt.Errorf("capture manifest contains an unsafe file name %q", file.Name)
		}
		result, err := exportCaptureFile(ctx, client, sessionID, file.Name, filepath.Join(directory, file.Name))
		if err != nil {
			return results, err
		}
		results = append(results, result)
	}
	return results, nil
}

// createExportDirectory creates every missing level of directory. Under sudo
// each new level belongs to the invoking user, so they can reach the files.
func createExportDirectory(directory string) error {
	var missing []string
	for current := directory; ; {
		_, err := os.Lstat(current)
		if err == nil {
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect export directory: %w", err)
		}
		missing = append(missing, current)
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	uid, gid, handOver := invokingUser()
	for index := len(missing) - 1; index >= 0; index-- {
		if err := os.Mkdir(missing[index], 0o750); err != nil && !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("create export directory: %w", err)
		}
		if handOver {
			if err := os.Lchown(missing[index], uid, gid); err != nil {
				return fmt.Errorf("hand export directory to the sudo user: %w", err)
			}
		}
	}
	if info, err := os.Stat(directory); err != nil || !info.IsDir() {
		return fmt.Errorf("export destination %s is not a directory", directory)
	}
	return nil
}

func exportCaptureFile(ctx context.Context, client gatewayclient.Client, sessionID, fileName, destination string) (exportResult, error) {
	if !capture.ValidSessionID(sessionID) || fileName == "" || destination == "" {
		return exportResult{}, errors.New("capture export arguments are invalid")
	}
	destination, err := filepath.Abs(destination)
	if err != nil {
		return exportResult{}, fmt.Errorf("resolve export destination: %w", err)
	}
	if _, err := os.Lstat(destination); err == nil {
		return exportResult{}, fmt.Errorf("refusing to overwrite an existing export destination %s", destination)
	} else if !errors.Is(err, os.ErrNotExist) {
		return exportResult{}, fmt.Errorf("inspect export destination: %w", err)
	}
	view, err := finalizedCaptureView(ctx, client, sessionID)
	if err != nil {
		return exportResult{}, err
	}
	var artifact *capture.CaptureFile
	for index := range view.Manifest.Files {
		if view.Manifest.Files[index].Name == fileName {
			artifact = &view.Manifest.Files[index]
			break
		}
	}
	if artifact == nil {
		return exportResult{}, errors.New("capture artifact is not present in the final manifest")
	}
	temporary, err := os.CreateTemp(filepath.Dir(destination), ".shakerproxy-capture-export-*")
	if err != nil {
		return exportResult{}, fmt.Errorf("create export destination: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return exportResult{}, err
	}
	// Under sudo, the private export belongs to the person who asked for it.
	if err := giveToInvokingUser(temporary); err != nil {
		temporary.Close()
		return exportResult{}, err
	}
	hasher := sha256.New()
	for offset := int64(0); offset < artifact.SizeBytes; {
		requested := min(int64(capture.MaxArtifactChunkBytes), artifact.SizeBytes-offset)
		var chunk capture.ArtifactChunk
		params := gatewayprotocol.ReadCaptureArtifactParams{SessionID: sessionID, FileName: fileName, Offset: offset, Length: int(requested)}
		if err := gatewayCall(ctx, client, "ReadCaptureArtifact", params, &chunk); err != nil {
			temporary.Close()
			return exportResult{}, err
		}
		if chunk.SessionID != sessionID || chunk.FileName != fileName || chunk.FileSHA256 != artifact.SHA256 || chunk.Offset != offset || chunk.TotalBytes != artifact.SizeBytes || int64(len(chunk.Data)) != requested {
			temporary.Close()
			return exportResult{}, errors.New("capture artifact integrity metadata changed during export")
		}
		if _, err := temporary.Write(chunk.Data); err != nil {
			temporary.Close()
			return exportResult{}, err
		}
		_, _ = hasher.Write(chunk.Data)
		offset += int64(len(chunk.Data))
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return exportResult{}, err
	}
	if err := temporary.Close(); err != nil {
		return exportResult{}, err
	}
	actualHash := fmt.Sprintf("%x", hasher.Sum(nil))
	if actualHash != artifact.SHA256 {
		return exportResult{}, fmt.Errorf("capture SHA-256 mismatch: manifest %s, received %s", artifact.SHA256, actualHash)
	}
	if err := os.Link(temporaryName, destination); err != nil {
		return exportResult{}, fmt.Errorf("publish export without overwrite: %w", err)
	}
	if err := os.Remove(temporaryName); err != nil {
		return exportResult{}, fmt.Errorf("remove temporary export link: %w", err)
	}
	if directory, err := os.Open(filepath.Dir(destination)); err == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
	return exportResult{SessionID: sessionID, FileName: fileName, Destination: destination, SizeBytes: artifact.SizeBytes, SHA256: actualHash, Verified: true}, nil
}

func gatewayCall(ctx context.Context, client gatewayclient.Client, method string, params, result any) error {
	requestContext, cancel := context.WithTimeout(ctx, gatewayprotocol.MethodTimeout(method))
	defer cancel()
	return client.Call(requestContext, method, params, result)
}

// networkCommand undoes the running network plan (shakerproxy network off).
func (c *cli) networkCommand(args []string) error {
	flags := newFlags("network")
	assumeYes := flags.Bool("yes", false, "do not ask for confirmation")
	positional, err := parseFlags("network", flags, args)
	if err != nil {
		return err
	}
	if len(positional) == 0 || positional[0] != "off" {
		name := ""
		if len(positional) > 0 {
			name = positional[0]
		}
		return unknownSubcommand("network", name, []string{"off"})
	}
	if err := expectArgs("network", positional, 1, 1); err != nil {
		return err
	}
	if !*assumeYes {
		if !c.stdinTTY {
			return usagef("network", "network off asks for confirmation; run it in a terminal or add --yes.")
		}
		fmt.Fprintln(c.stderr, "Lab devices will lose their connection through ShakerProxy, and the host's previous")
		fmt.Fprintln(c.stderr, "network settings (Netplan, DHCP, firewall, forwarding) will be restored.")
		fmt.Fprint(c.stderr, "Type OFF to continue: ")
		answer, err := readLine(c.stdin, 64)
		if err != nil || !strings.EqualFold(strings.TrimSpace(answer), "off") {
			fmt.Fprintln(c.stderr, "Cancelled; nothing was changed.")
			return &silentFailure{code: exitFailure}
		}
	}
	var result map[string]any
	if err := c.gatewayCall("RevertNetworkPlan", gatewayprotocol.EmptyParams{}, &result); err != nil {
		return err
	}
	if c.jsonOutput {
		return c.printJSON(result)
	}
	c.println("Lab routing is off: the previous network is restored and ShakerProxy is in setup mode.")
	c.println("To route a lab again, apply a network plan on the Network page of the web UI.")
	return nil
}
