package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

func (c *cli) testCommand(args []string) error {
	subcommand := ""
	if len(args) > 0 {
		subcommand = args[0]
	}
	switch subcommand {
	case "start", "begin":
		return c.testStart(args[1:])
	case "stop", "end", "finish":
		return c.testStop(args[1:])
	case "list", "ls":
		return c.testList(args[1:])
	default:
		return unknownSubcommand("test", subcommand, []string{"start", "stop", "list"})
	}
}

func (c *cli) testStart(args []string) error {
	flags := newFlags("test start")
	name := flags.String("name", "", "test run name")
	notes := flags.String("notes", "", "notes")
	record := flags.Bool("capture", false, "also record packets")
	full := flags.Bool("full", false, "record whole packets (implies --capture) so TLS server names and certificates are analyzed")
	positional, err := parseFlags("test", flags, args)
	if err != nil {
		return err
	}
	if err := expectArgs("test", positional, 1, 1, "device reference"); err != nil {
		return err
	}
	if err := checkRef("test", positional[0]); err != nil {
		return err
	}
	if len(*name) > 200 || len(*notes) > 4000 {
		return usagef("test", "--name must be at most 200 characters and --notes at most 4000.")
	}
	session, err := c.openAPI()
	if err != nil {
		return err
	}
	payload := map[string]any{"device": strings.TrimSpace(positional[0]), "capture": *record || *full}
	if *full {
		payload["full_capture"] = true
	}
	if *name != "" {
		payload["name"] = *name
	}
	if *notes != "" {
		payload["notes"] = *notes
	}
	raw, err := session.do(http.MethodPost, "/api/v1/test-sessions", payload)
	if err != nil {
		return err
	}
	if c.jsonOutput {
		return c.printRawJSON(raw)
	}
	var started testSession
	if err := json.Unmarshal(raw, &started); err != nil {
		return fmt.Errorf("control API returned an unexpected test session: %v", err)
	}
	device := orText(sanitize(started.DeviceName), positional[0])
	c.printf("Started test %q on %s (%s).\n", sanitize(started.Name), device, started.ID)
	if started.CaptureSessionID != nil && *started.CaptureSessionID != "" {
		c.printf("Recording packets: %s\n", *started.CaptureSessionID)
	}
	for _, warning := range started.Warnings {
		c.printf("%s %s\n", c.style(styleYellow, "!"), sanitize(warning))
	}
	ref := quoteRef(positional[0])
	c.printf("\nWatch it live:  shakerproxy watch %s\nStop it:        shakerproxy test stop %s\n", ref, ref)
	return nil
}

func (c *cli) listTests(session *apiSession, query url.Values) ([]testSession, []byte, error) {
	path := "/api/v1/test-sessions"
	if encoded := query.Encode(); encoded != "" {
		path += "?" + encoded
	}
	raw, err := session.do(http.MethodGet, path, nil)
	if err != nil {
		return nil, nil, err
	}
	var sessions []testSession
	if err := decodeListField(raw, &sessions, "sessions", "test_sessions", "items"); err != nil {
		return nil, nil, fmt.Errorf("control API returned an unexpected test session list: %v", err)
	}
	return sessions, raw, nil
}

func (c *cli) testStop(args []string) error {
	flags := newFlags("test stop")
	positional, err := parseFlags("test", flags, args)
	if err != nil {
		return err
	}
	if err := expectArgs("test", positional, 0, 1); err != nil {
		return err
	}
	session, err := c.openAPI()
	if err != nil {
		return err
	}
	var target testSession
	if len(positional) == 1 && testIDPattern.MatchString(positional[0]) {
		target.ID = positional[0]
	} else {
		query := url.Values{"state": {"RUNNING"}, "limit": {"50"}}
		if len(positional) == 1 {
			if err := checkRef("test", positional[0]); err != nil {
				return err
			}
			query.Set("device", strings.TrimSpace(positional[0]))
		}
		running, _, err := c.listTests(session, query)
		if err != nil {
			return err
		}
		switch len(running) {
		case 0:
			if len(positional) == 1 {
				c.printf("No test is running on %s.\n", positional[0])
			} else {
				c.println("No test is running.")
			}
			return nil
		case 1:
			target = running[0]
		default:
			listing := newTable("ID", "NAME", "DEVICE", "STARTED")
			for _, item := range running {
				listing.add(item.ID, sanitize(item.Name), sanitize(item.DeviceName), humanAgo(c.now(), item.StartedAt))
			}
			var buffer strings.Builder
			listing.render(&buffer, &cli{})
			return withHints(fmt.Sprintf("%d tests are running; say which one to stop:\n%s", len(running), strings.TrimRight(buffer.String(), "\n")), "shakerproxy test stop <device> or shakerproxy test stop <test-id>")
		}
	}
	raw, err := session.do(http.MethodPost, "/api/v1/test-sessions/"+url.PathEscape(target.ID)+"/stop", map[string]any{})
	if err != nil {
		return err
	}
	if c.jsonOutput {
		return c.printRawJSON(raw)
	}
	var stopped testSession
	if json.Unmarshal(raw, &stopped) != nil || stopped.ID == "" {
		stopped = target
	}
	duration := ""
	if started, ok := parseTime(stopped.StartedAt); ok {
		end := c.now()
		if stopped.EndedAt != nil {
			if ended, ok := parseTime(*stopped.EndedAt); ok {
				end = ended
			}
		}
		duration = fmt.Sprintf(" after %s", humanDuration(end.Sub(started)))
	}
	c.printf("Stopped test %q%s.\n", sanitize(orText(stopped.Name, stopped.ID)), duration)
	ref := stopped.DeviceID
	if len(positional) == 1 && !testIDPattern.MatchString(positional[0]) {
		ref = quoteRef(positional[0])
	}
	if ref != "" {
		c.printf("Report: shakerproxy report %s --session %s\n", ref, stopped.ID)
	}
	return nil
}

func (c *cli) testList(args []string) error {
	flags := newFlags("test list")
	deviceRef := flags.String("device", "", "only this device")
	running := flags.Bool("running", false, "only running tests")
	limit := flags.Int("limit", 50, "maximum results")
	positional, err := parseFlags("test", flags, args)
	if err != nil {
		return err
	}
	if len(positional) == 1 && *deviceRef == "" {
		*deviceRef = positional[0]
		positional = nil
	}
	if err := expectArgs("test", positional, 0, 0); err != nil {
		return err
	}
	if *limit < 1 || *limit > 500 {
		return usagef("test", "--limit must be between 1 and 500.")
	}
	query := url.Values{"limit": {fmt.Sprint(*limit)}}
	if *deviceRef != "" {
		if err := checkRef("test", *deviceRef); err != nil {
			return err
		}
		query.Set("device", strings.TrimSpace(*deviceRef))
	}
	if *running {
		query.Set("state", "RUNNING")
	}
	session, err := c.openAPI()
	if err != nil {
		return err
	}
	sessions, raw, err := c.listTests(session, query)
	if err != nil {
		return err
	}
	if c.jsonOutput {
		return c.printRawJSON(raw)
	}
	if len(sessions) == 0 {
		c.println("No test runs yet. Start one: shakerproxy test start <device>")
		return nil
	}
	now := c.now()
	listing := newTable("ID", "NAME", "DEVICE", "STATE", "STARTED", "DURATION")
	for _, item := range sessions {
		duration := "-"
		if started, ok := parseTime(item.StartedAt); ok {
			end := now
			if item.EndedAt != nil {
				if ended, ok := parseTime(*item.EndedAt); ok {
					end = ended
				}
			}
			duration = humanDuration(end.Sub(started))
		}
		listing.add(item.ID, sanitize(item.Name), orDash(sanitize(item.DeviceName)), c.statusWord(item.State), shortTime(item.StartedAt), duration)
	}
	listing.render(c.stdout, c)
	return nil
}

func (c *cli) reportCommand(args []string) error {
	flags := newFlags("report")
	window := flags.String("window", "", "time window, e.g. 1h, 24h, 7d (default 24h)")
	sessionID := flags.String("session", "", "test run ID")
	htmlPath := flags.String("html", "", "write an HTML report to this file")
	positional, err := parseFlags("report", flags, args)
	if err != nil {
		return err
	}
	if err := expectArgs("report", positional, 1, 1, "device reference"); err != nil {
		return err
	}
	if err := checkRef("report", positional[0]); err != nil {
		return err
	}
	if *window != "" && *sessionID != "" {
		return usagef("report", "Use either --window or --session, not both.")
	}
	if *window != "" && !windowPattern.MatchString(*window) {
		return usagef("report", "--window must look like 1h, 24h or 7d.")
	}
	if *sessionID != "" && !testIDPattern.MatchString(*sessionID) {
		return usagef("report", "--session must be a test run ID like ts-0123456789abcdef01234567 (see `shakerproxy test list`).")
	}
	if *htmlPath != "" && c.jsonOutput {
		return usagef("report", "Use either --html or --json, not both.")
	}
	query := url.Values{}
	if *sessionID != "" {
		query.Set("session", *sessionID)
	} else {
		query.Set("window", orText(*window, "24h"))
	}
	session, err := c.openAPI()
	if err != nil {
		return err
	}
	var report deviceReport
	raw, err := session.getJSON(devicePath(positional[0], "/report?"+query.Encode()), &report)
	if err != nil {
		return err
	}
	if c.jsonOutput {
		return c.printRawJSON(raw)
	}
	if *htmlPath != "" {
		var page strings.Builder
		if err := renderReportHTML(&page, report, c.now()); err != nil {
			return err
		}
		destination, err := writeFileAtomically(*htmlPath, []byte(page.String()), 0o644)
		if err != nil {
			return err
		}
		c.printf("Wrote %s (%s, %s).\n", destination, plural(len(report.Findings), "finding", "findings"), humanBytes(int64(page.Len())))
		return nil
	}
	c.renderReportText(report)
	return nil
}

func (c *cli) renderReportText(report deviceReport) {
	device := report.Device
	name := orText(sanitize(device.FriendlyName), device.DeviceID)
	facts := []string{}
	if device.Vendor != "" {
		facts = append(facts, sanitize(device.Vendor))
	}
	if len(device.Addresses) > 0 {
		facts = append(facts, joinLimited(device.Addresses, 2))
	}
	c.printf("%s %s", c.bold("Device report:"), c.bold(name))
	if len(facts) > 0 {
		c.printf(" (%s)", strings.Join(facts, ", "))
	}
	c.println()
	c.printf("Window: %s → %s", shortTime(report.WindowStart), shortTime(report.WindowEnd))
	if report.Session != nil && report.Session.ID != "" {
		c.printf("   Test: %s (%s)", sanitize(report.Session.Name), report.Session.ID)
	}
	c.println()
	if report.CATrust != "" {
		c.printf("ShakerProxy CA: %s\n", caTrustText(report.CATrust))
	}
	c.println()
	findings := sortedFindings(report.Findings)
	if len(findings) == 0 {
		c.println(c.bold("Findings: none") + " — nothing suspicious was observed in this window.")
	} else {
		c.println(c.bold(fmt.Sprintf("Findings (%d)", len(findings))))
		for _, item := range findings {
			c.printf("  %-9s %s\n", c.statusWord(strings.ToUpper(item.Severity)), c.bold(sanitize(item.Title)))
			if item.Detail != "" {
				c.printf("            %s\n", sanitize(item.Detail))
			}
			if item.Recommendation != "" {
				c.printf("            → %s\n", sanitize(item.Recommendation))
			}
			for index, evidence := range item.Evidence {
				if index == 3 {
					c.printf("            %s\n", c.dim(fmt.Sprintf("… %d more", len(item.Evidence)-3)))
					break
				}
				c.printf("            %s\n", c.dim("• "+sanitize(evidence)))
			}
		}
	}
	totals := report.Totals
	c.printf("\n%s %s events · %s flows · %s · %s DNS lookups · %s TLS · %s HTTP · %s alerts\n", c.bold("Activity:"),
		humanCount(totals.Events), humanCount(totals.Flows), humanBytes(totals.Bytes), humanCount(totals.DNSQueries), humanCount(totals.TLSConnections), humanCount(totals.HTTPRequests), humanCount(totals.Alerts))
	// Headers-only captures cut TLS handshakes short: the flows are counted,
	// but no server name or certificate can be analyzed.
	if totals.TLSConnections == 0 {
		for _, protocol := range report.Protocols {
			if protocol.Protocol == "TLS" && protocol.Flows > 0 {
				c.printf("%s %s TLS flows, but no handshake details: the capture kept only packet headers.\n", c.style(styleYellow, "!"), humanCount(protocol.Flows))
				c.printf("  For TLS server names and certificates: shakerproxy test start %s --full\n", quoteRef(orText(report.Device.FriendlyName, report.Device.DeviceID)))
				break
			}
		}
	}
	tlsInfo := report.TLS
	if tlsInfo.Intercepted+tlsInfo.Bypassed+tlsInfo.Failed > 0 {
		c.printf("%s %d decrypted, %d not decrypted, %d failed", c.bold("TLS:"), tlsInfo.Intercepted, tlsInfo.Bypassed, tlsInfo.Failed)
		if tlsInfo.PinningSuspected > 0 {
			c.printf(" (pinning suspected on %d)", tlsInfo.PinningSuspected)
		}
		c.println()
		if len(tlsInfo.FailedHosts) > 0 {
			c.printf("     failed: %s\n", joinLimited(tlsInfo.FailedHosts, 5))
		}
		for _, old := range tlsInfo.OldVersions {
			c.printf("     %s: %s\n", sanitize(old.Version), joinLimited(old.Hosts, 5))
		}
	}
	if report.HTTP.Requests > 0 {
		c.printf("%s %s requests to %s hosts, %s in cleartext", c.bold("HTTP:"), humanCount(report.HTTP.Requests), humanCount(report.HTTP.Hosts), humanCount(report.HTTP.CleartextRequests))
		var classes []string
		for _, class := range []string{"2xx", "3xx", "4xx", "5xx"} {
			if count := report.HTTP.StatusClasses[class]; count > 0 {
				classes = append(classes, fmt.Sprintf("%s %d", class, count))
			}
		}
		if len(classes) > 0 {
			c.printf(" (%s)", strings.Join(classes, " · "))
		}
		c.println()
	}
	if len(report.Domains) > 0 {
		shown := report.Domains
		if len(shown) > 15 {
			shown = shown[:15]
		}
		c.printf("\n%s\n", c.bold(fmt.Sprintf("Domains (%d of %d)", len(shown), len(report.Domains))))
		listing := newTable("DOMAIN", "ORGANIZATION", "CATEGORY", "SEEN VIA", "EVENTS")
		for _, domain := range shown {
			listing.add(sanitize(domain.Domain), orDash(sanitize(domain.Organization)), orDash(sanitize(domain.Category)), joinLimited(domain.Sources, 3), humanCount(domain.Events))
		}
		listing.render(c.stdout, c)
	}
	if report.Truncated {
		c.println("\nSome lists were shortened; use --json or --html for everything.")
	}
	c.printf("\nShare it: shakerproxy report %s --html report.html\n", quoteRef(orText(device.DeviceID, name)))
}

// writeFileAtomically writes data through a temporary file and rename, so an
// existing symlink at the destination is replaced rather than followed.
func writeFileAtomically(path string, data []byte, mode os.FileMode) (string, error) {
	destination, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if info, err := os.Lstat(destination); err == nil && info.IsDir() {
		return "", fmt.Errorf("%s is a directory", destination)
	}
	temporary, err := os.CreateTemp(filepath.Dir(destination), ".shakerproxy-report-*")
	if err != nil {
		return "", fmt.Errorf("create %s: %w", destination, err)
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return "", err
	}
	if err := giveToInvokingUser(temporary); err != nil {
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
	if err := os.Rename(name, destination); err != nil {
		return "", fmt.Errorf("write %s: %w", destination, err)
	}
	return destination, nil
}

func (c *cli) compareCommand(args []string) error {
	flags := newFlags("compare")
	deviceRef := flags.String("device", "", "device (found from the first test run when omitted)")
	positional, err := parseFlags("compare", flags, args)
	if err != nil {
		return err
	}
	if err := expectArgs("compare", positional, 2, 2, "first test run ID", "second test run ID"); err != nil {
		return err
	}
	for _, id := range positional {
		if !testIDPattern.MatchString(id) {
			return usagef("compare", "%q is not a test run ID. Find IDs with `shakerproxy test list`.", id)
		}
	}
	session, err := c.openAPI()
	if err != nil {
		return err
	}
	device := strings.TrimSpace(*deviceRef)
	if device == "" {
		var base testSession
		if _, err := session.getJSON("/api/v1/test-sessions/"+url.PathEscape(positional[0]), &base); err != nil {
			return err
		}
		device = base.DeviceID
		if device == "" {
			return withHints("the first test run has no device", "Pass the device explicitly: --device <ref>")
		}
	} else if err := checkRef("compare", device); err != nil {
		return err
	}
	var result compareResult
	query := url.Values{"base": {positional[0]}, "compare": {positional[1]}}
	raw, err := session.getJSON(devicePath(device, "/compare?"+query.Encode()), &result)
	if err != nil {
		return err
	}
	if c.jsonOutput {
		return c.printRawJSON(raw)
	}
	c.printf("%s %s (before) → %s (after)\n\n", c.bold("Comparing"), positional[0], positional[1])
	listing := newTable("", "BEFORE", "AFTER")
	listing.add("Events", humanCount(result.Base.Totals.Events), humanCount(result.Compare.Totals.Events))
	listing.add("Bytes", humanBytes(result.Base.Totals.Bytes), humanBytes(result.Compare.Totals.Bytes))
	listing.add("DNS lookups", humanCount(result.Base.Totals.DNSQueries), humanCount(result.Compare.Totals.DNSQueries))
	listing.add("TLS connections", humanCount(result.Base.Totals.TLSConnections), humanCount(result.Compare.Totals.TLSConnections))
	listing.add("Alerts", humanCount(result.Base.Totals.Alerts), humanCount(result.Compare.Totals.Alerts))
	listing.render(c.stdout, c)
	section := func(title string, added, removed []string) {
		if len(added) == 0 && len(removed) == 0 {
			c.printf("\n%s no change\n", c.bold(title+":"))
			return
		}
		c.printf("\n%s\n", c.bold(title+":"))
		for _, value := range added {
			c.printf("  %s %s\n", c.style(styleYellow, "+"), sanitize(value))
		}
		for _, value := range removed {
			c.printf("  %s %s\n", c.style(styleGreen, "-"), sanitize(value))
		}
	}
	section("Domains", result.Domains.Added, result.Domains.Removed)
	section("Protocols", result.Protocols.Added, result.Protocols.Removed)
	if len(result.Findings.New)+len(result.Findings.Resolved) == 0 {
		c.printf("\n%s no change\n", c.bold("Findings:"))
	} else {
		c.printf("\n%s\n", c.bold("Findings:"))
		for _, item := range sortedFindings(result.Findings.New) {
			c.printf("  %s %-9s %s\n", c.style(styleRed, "new"), c.statusWord(strings.ToUpper(item.Severity)), sanitize(item.Title))
		}
		for _, item := range sortedFindings(result.Findings.Resolved) {
			c.printf("  %s %-9s %s\n", c.style(styleGreen, "fixed"), strings.ToUpper(item.Severity), sanitize(item.Title))
		}
	}
	if len(result.TLS.NewlyFailedHosts) > 0 {
		c.printf("\n%s %s\n", c.bold("TLS newly failing:"), joinLimited(result.TLS.NewlyFailedHosts, 8))
	}
	if len(result.TLS.NewlyInterceptedHosts) > 0 {
		c.printf("%s %s\n", c.bold("TLS newly decrypted:"), joinLimited(result.TLS.NewlyInterceptedHosts, 8))
	}
	return nil
}

// updateControls reads the device's lab controls, applies change, and writes
// the full desired state back.
func (c *cli) updateControls(command, ref string, change func(*deviceControls) error) (deviceControls, []byte, error) {
	if err := checkRef(command, ref); err != nil {
		return deviceControls{}, nil, err
	}
	session, err := c.openAPI()
	if err != nil {
		return deviceControls{}, nil, err
	}
	var current deviceControls
	if _, err := session.getJSON(devicePath(ref, "/controls"), &current); err != nil {
		return deviceControls{}, nil, err
	}
	if err := change(&current); err != nil {
		return deviceControls{}, nil, err
	}
	if current.Internet == "" {
		current.Internet = "ALLOW"
	}
	if current.BlockedDomains == nil {
		current.BlockedDomains = []string{}
	}
	payload := map[string]any{"decrypt_https": current.DecryptHTTPS, "internet": current.Internet, "blocked_domains": current.BlockedDomains}
	raw, err := session.do(http.MethodPut, devicePath(ref, "/controls"), payload)
	if err != nil {
		return deviceControls{}, nil, err
	}
	var updated deviceControls
	if err := json.Unmarshal(raw, &updated); err != nil {
		return deviceControls{}, nil, fmt.Errorf("control API returned unexpected device controls: %v", err)
	}
	return updated, raw, nil
}

func (c *cli) printControlsOutcome(updated deviceControls, raw []byte, message string) error {
	if c.jsonOutput {
		return c.printRawJSON(raw)
	}
	c.println(message)
	if updated.Effective != nil && !*updated.Effective {
		c.println(c.style(styleYellow, "Not fully in effect yet:"))
	}
	for _, note := range updated.Notes {
		c.printf("  %s %s\n", c.dim("•"), sanitize(note))
	}
	return nil
}

func (c *cli) decryptCommand(args []string) error {
	positional, err := parseFlags("decrypt", newFlags("decrypt"), args)
	if err != nil {
		return err
	}
	if err := expectArgs("decrypt", positional, 2, 2, "device reference", "on or off"); err != nil {
		return err
	}
	var enable bool
	switch strings.ToLower(positional[1]) {
	case "on", "enable", "yes", "true":
		enable = true
	case "off", "disable", "no", "false":
	default:
		return usagef("decrypt", "Say on or off, e.g. shakerproxy decrypt %s on", quoteRef(positional[0]))
	}
	updated, raw, err := c.updateControls("decrypt", positional[0], func(controls *deviceControls) error {
		controls.DecryptHTTPS = enable
		return nil
	})
	if err != nil {
		return err
	}
	state := "off"
	if updated.DecryptHTTPS {
		state = "on"
	}
	if err := c.printControlsOutcome(updated, raw, fmt.Sprintf("HTTPS decryption is %s for %s.", state, positional[0])); err != nil {
		return err
	}
	if enable && !c.jsonOutput {
		c.println("The device must trust the ShakerProxy CA; if it does not yet: shakerproxy ca")
		c.printf("See what gets decrypted: shakerproxy watch %s\n", quoteRef(positional[0]))
	}
	return nil
}

func normalizeDomain(command, value string) (string, error) {
	domain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	domain = strings.TrimPrefix(domain, "*.")
	if !domainNamePattern.MatchString(domain) {
		return "", usagef(command, "%q is not a domain name. Use `internet` or a domain like ads.example.com.", value)
	}
	return domain, nil
}

func (c *cli) blockCommand(args []string) error {
	positional, err := parseFlags("block", newFlags("block"), args)
	if err != nil {
		return err
	}
	if err := expectArgs("block", positional, 2, 2, "device reference", "`internet` or a domain"); err != nil {
		return err
	}
	target := strings.ToLower(positional[1])
	var domain string
	if target != "internet" {
		if domain, err = normalizeDomain("block", positional[1]); err != nil {
			return err
		}
	}
	updated, raw, err := c.updateControls("block", positional[0], func(controls *deviceControls) error {
		if domain == "" {
			controls.Internet = "BLOCK"
			return nil
		}
		for _, existing := range controls.BlockedDomains {
			if strings.EqualFold(existing, domain) {
				return nil
			}
		}
		if len(controls.BlockedDomains) >= 256 {
			return withHints("this device already has 256 blocked domains", "Remove some with `shakerproxy unblock`.")
		}
		controls.BlockedDomains = append(controls.BlockedDomains, domain)
		return nil
	})
	if err != nil {
		return err
	}
	message := fmt.Sprintf("Blocked internet access for %s (local network still works).", positional[0])
	if domain != "" {
		message = fmt.Sprintf("Blocked %s and its subdomains for %s.", domain, positional[0])
	}
	return c.printControlsOutcome(updated, raw, message)
}

func (c *cli) unblockCommand(args []string) error {
	flags := newFlags("unblock")
	all := flags.Bool("all", false, "remove every block")
	positional, err := parseFlags("unblock", flags, args)
	if err != nil {
		return err
	}
	if *all {
		if err := expectArgs("unblock", positional, 1, 1, "device reference"); err != nil {
			return err
		}
	} else if err := expectArgs("unblock", positional, 2, 2, "device reference", "`internet`, a domain, or --all"); err != nil {
		return err
	}
	var domain string
	target := ""
	if len(positional) == 2 {
		target = strings.ToLower(positional[1])
		if target != "internet" {
			if domain, err = normalizeDomain("unblock", positional[1]); err != nil {
				return err
			}
		}
	}
	updated, raw, err := c.updateControls("unblock", positional[0], func(controls *deviceControls) error {
		switch {
		case *all:
			controls.Internet = "ALLOW"
			controls.BlockedDomains = []string{}
		case target == "internet":
			controls.Internet = "ALLOW"
		default:
			kept := make([]string, 0, len(controls.BlockedDomains))
			for _, existing := range controls.BlockedDomains {
				if !strings.EqualFold(existing, domain) {
					kept = append(kept, existing)
				}
			}
			controls.BlockedDomains = kept
		}
		return nil
	})
	if err != nil {
		return err
	}
	message := fmt.Sprintf("Removed all blocks for %s.", positional[0])
	switch {
	case *all:
	case target == "internet":
		message = fmt.Sprintf("Internet access is allowed again for %s.", positional[0])
	default:
		message = fmt.Sprintf("Unblocked %s for %s.", domain, positional[0])
	}
	return c.printControlsOutcome(updated, raw, message)
}

func (c *cli) caCommand(args []string) error {
	flags := newFlags("ca")
	platform := flags.String("platform", "", "show full steps for one platform")
	positional, err := parseFlags("ca", flags, args)
	if err != nil {
		return err
	}
	if len(positional) > 0 {
		return c.caTrustCommand(positional)
	}
	session, err := c.openAPI()
	if err != nil {
		return err
	}
	var onboarding caOnboarding
	raw, err := session.getJSON("/api/v1/interception-ca/onboarding", &onboarding)
	if err != nil {
		return err
	}
	if c.jsonOutput {
		return c.printRawJSON(raw)
	}
	if !onboarding.Available {
		return withHints("the ShakerProxy CA is not ready yet: "+orText(sanitize(onboarding.Reason), "no reason given"), "Check the Policy (DNS & HTTPS) page in the web UI, or run `shakerproxy status`.")
	}
	if *platform != "" {
		for _, instruction := range onboarding.Instructions {
			if strings.EqualFold(instruction.Platform, *platform) {
				c.println(c.bold(sanitize(instruction.Title)))
				for index, step := range instruction.Steps {
					c.printf("  %d. %s\n", index+1, sanitize(step))
				}
				for _, limitation := range instruction.Limitations {
					c.printf("  %s %s\n", c.style(styleYellow, "!"), sanitize(limitation))
				}
				c.printf("\nFingerprint (SHA-256): %s\n", sanitize(onboarding.SHA256Fingerprint))
				return nil
			}
		}
		var platforms []string
		for _, instruction := range onboarding.Instructions {
			platforms = append(platforms, instruction.Platform)
		}
		return usagef("ca", "No instructions for %q. Available: %s.", *platform, strings.Join(platforms, ", "))
	}
	c.println(c.bold("Install the ShakerProxy CA on the device you are testing"))
	c.println()
	if len(onboarding.URLs) > 0 {
		primary := onboarding.URLs[0].URL
		c.println("  1. Connect the device to the lab network.")
		c.printf("  2. On the device, open %s — or scan:\n\n", c.bold(sanitize(primary)))
		if code, err := encodeQR([]byte(primary)); err == nil {
			code.render(c.stdout, c.color, "     ")
		}
		c.println()
		for _, other := range onboarding.URLs[1:] {
			c.printf("  Also: %s (%s)\n", sanitize(other.URL), sanitize(other.Label))
		}
	}
	c.printf("  Fingerprint (SHA-256): %s\n", sanitize(onboarding.SHA256Fingerprint))
	if onboarding.CommonName != "" {
		c.printf("  Certificate: %s", sanitize(onboarding.CommonName))
		if notAfter, ok := parseTime(onboarding.NotAfter); ok {
			c.printf(", valid until %s", notAfter.Format("2006-01-02"))
		}
		c.println()
	}
	if len(onboarding.Instructions) > 0 {
		c.println()
		for _, instruction := range onboarding.Instructions {
			first := ""
			if len(instruction.Steps) > 0 {
				first = sanitize(instruction.Steps[0])
			}
			c.printf("  %-22s %s\n", sanitize(instruction.Title), truncate(first, 70))
		}
		c.println("\nFull steps: shakerproxy ca --platform ios|android|android-tv|macos|windows|linux|smart-tv|other")
	}
	c.println("Then turn on decryption: shakerproxy decrypt <device> on")
	c.println("Record the result per device: shakerproxy ca <device> installed|not-installed")
	return nil
}

// caTrustCommand records whether a device trusts the ShakerProxy CA, which
// decides whether decrypted traffic means "accepts untrusted certificates".
func (c *cli) caTrustCommand(positional []string) error {
	if err := expectArgs("ca", positional, 2, 2, "device reference", "installed, not-installed or unknown"); err != nil {
		return err
	}
	if err := checkRef("ca", positional[0]); err != nil {
		return err
	}
	var state, message string
	switch strings.ToLower(strings.ReplaceAll(positional[1], "_", "-")) {
	case "installed", "trusted", "yes":
		state, message = "INSTALLED", "%s trusts the ShakerProxy CA; decrypted traffic is expected."
	case "not-installed", "untrusted", "removed", "no":
		state, message = "NOT_INSTALLED", "%s does not trust the ShakerProxy CA; if its traffic still gets decrypted, the report flags that it accepts untrusted certificates."
	case "unknown":
		state, message = "UNKNOWN", "CA trust for %s is now unknown."
	default:
		return usagef("ca", "Say installed, not-installed or unknown, e.g. shakerproxy ca %s not-installed", quoteRef(positional[0]))
	}
	session, err := c.openAPI()
	if err != nil {
		return err
	}
	raw, err := session.do(http.MethodPut, devicePath(positional[0], "/ca-trust"), map[string]string{"state": state})
	if err != nil {
		return err
	}
	if c.jsonOutput {
		return c.printRawJSON(raw)
	}
	c.printf("Recorded: "+message+"\n", positional[0])
	return nil
}
