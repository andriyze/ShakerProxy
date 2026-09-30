package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
)

var (
	deviceIDPattern   = regexp.MustCompile(`^device-[a-f0-9]{32}$`)
	testIDPattern     = regexp.MustCompile(`^ts-[a-f0-9]{24}$`)
	windowPattern     = regexp.MustCompile(`^[1-9][0-9]{0,3}[smhd]$`)
	domainNamePattern = regexp.MustCompile(`^(\*\.)?([A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)+[A-Za-z]{2,63}\.?$`)
)

// checkRef rejects references that cannot be a device and would change the
// meaning of an API path.
func checkRef(command, ref string) error {
	trimmed := strings.TrimSpace(ref)
	if trimmed == "" || trimmed == "." || trimmed == ".." || len(trimmed) > 256 || strings.ContainsAny(trimmed, "\x00\r\n") {
		return usagef(command, "%q is not a valid device reference. Use a name, IP address, MAC address or device ID.", ref)
	}
	return nil
}

func devicePath(ref, suffix string) string {
	return "/api/v1/devices/" + url.PathEscape(strings.TrimSpace(ref)) + suffix
}

// ambiguousDeviceError lists the candidates of an ambiguous reference.
func ambiguousDeviceError(message string, candidates []deviceMatch) error {
	var buffer bytes.Buffer
	if message == "" {
		message = fmt.Sprintf("that reference matches %d devices", len(candidates))
	}
	buffer.WriteString(strings.TrimRight(message, ".") + ":\n")
	listing := newTable("NAME", "VENDOR", "IP", "MAC", "ID")
	for _, candidate := range candidates {
		listing.add(orDash(sanitize(candidate.FriendlyName)), orDash(sanitize(candidate.Vendor)), joinLimited(candidate.Addresses, 2), joinLimited(candidate.HardwareAddresses, 1), candidate.DeviceID)
	}
	listing.render(&buffer, &cli{})
	hint := "Use the IP address, MAC address or full name to pick one."
	if len(candidates) > 0 && len(candidates[0].Addresses) > 0 {
		hint = fmt.Sprintf("Use the IP address, MAC address or full name, e.g. %s", candidates[0].Addresses[0])
	}
	return withHints(strings.TrimRight(buffer.String(), "\n"), hint)
}

func notFoundDeviceError(ref string) error {
	return withHints(fmt.Sprintf("no device matches %q", ref), "List devices: "+commandHint("shakerproxy devices"))
}

// resolveDevice turns any reference into one device using the server's
// resolver, falling back to matching the device list locally when the
// control API predates /devices/resolve.
func (c *cli) resolveDevice(session *apiSession, command, ref string) (deviceMatch, error) {
	if err := checkRef(command, ref); err != nil {
		return deviceMatch{}, err
	}
	ref = strings.TrimSpace(ref)
	var resolved resolveResponse
	_, err := session.getJSON("/api/v1/devices/resolve?q="+url.QueryEscape(ref), &resolved)
	if err == nil {
		switch {
		case len(resolved.Matches) == 0:
			return deviceMatch{}, notFoundDeviceError(ref)
		case len(resolved.Matches) == 1 || resolved.Unique:
			return resolved.Matches[0], nil
		default:
			return deviceMatch{}, ambiguousDeviceError(fmt.Sprintf("%q matches %d devices", ref, len(resolved.Matches)), resolved.Matches)
		}
	}
	// Without the resolver, /devices/resolve lands on /devices/{deviceID},
	// which rejects "resolve" as an invalid device ID.
	var api *apiError
	resolverMissing := isUnsupported(err) || errors.As(err, &api) && api.status == http.StatusBadRequest && api.code == "invalid_device_id"
	if !resolverMissing {
		return deviceMatch{}, err
	}
	var list deviceList
	if _, err := session.getJSON("/api/v1/devices", &list); err != nil {
		return deviceMatch{}, err
	}
	matches := matchDevicesLocally(list.Devices, ref)
	switch len(matches) {
	case 0:
		return deviceMatch{}, notFoundDeviceError(ref)
	case 1:
		return matches[0], nil
	default:
		return deviceMatch{}, ambiguousDeviceError(fmt.Sprintf("%q matches %d devices", ref, len(matches)), matches)
	}
}

// matchDevicesLocally follows the contract's resolution order: exact ID, MAC,
// current IP, exact name, unique name prefix, unique substring.
func matchDevicesLocally(devices []inventoryDevice, ref string) []deviceMatch {
	lower := strings.ToLower(ref)
	normalizedMAC := normalizeMAC(ref)
	var stages [6][]deviceMatch
	for _, device := range devices {
		match := device.toMatch()
		name := strings.ToLower(device.FriendlyName)
		switch {
		case device.ID == ref:
			stages[0] = append(stages[0], match)
		case normalizedMAC != "" && containsFold(normalizeMACs(device.macAddresses()), normalizedMAC):
			stages[1] = append(stages[1], match)
		case net.ParseIP(ref) != nil && containsFold(device.ipAddresses(true), ref):
			stages[2] = append(stages[2], match)
		case name != "" && name == lower:
			stages[3] = append(stages[3], match)
		case name != "" && strings.HasPrefix(name, lower):
			stages[4] = append(stages[4], match)
		case name != "" && strings.Contains(name, lower):
			stages[5] = append(stages[5], match)
		}
	}
	for _, stage := range stages {
		if len(stage) > 0 {
			if len(stage) > 20 {
				stage = stage[:20]
			}
			return stage
		}
	}
	return nil
}

func normalizeMAC(value string) string {
	cleaned := strings.NewReplacer(":", "", "-", "", ".", "").Replace(strings.ToLower(strings.TrimSpace(value)))
	if len(cleaned) != 12 {
		return ""
	}
	for _, r := range cleaned {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return ""
		}
	}
	return cleaned
}

func normalizeMACs(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, normalizeMAC(value))
	}
	return result
}

func containsFold(values []string, target string) bool {
	for _, value := range values {
		if strings.EqualFold(value, target) {
			return true
		}
	}
	return false
}

func (c *cli) devicesCommand(args []string) error {
	flags := newFlags("devices")
	online := flags.Bool("online", false, "only devices online now")
	search := flags.String("search", "", "filter by name, vendor or address")
	positional, err := parseFlags("devices", flags, args)
	if err != nil {
		return err
	}
	if err := expectArgs("devices", positional, 0, 0); err != nil {
		return err
	}
	session, err := c.openAPI()
	if err != nil {
		return err
	}
	query := url.Values{}
	if *online {
		query.Set("view", "online")
	}
	if *search != "" {
		query.Set("q", *search)
	}
	path := "/api/v1/devices"
	if encoded := query.Encode(); encoded != "" {
		path += "?" + encoded
	}
	var list deviceList
	raw, err := session.getJSON(path, &list)
	if err != nil {
		return err
	}
	if c.jsonOutput {
		return c.printRawJSON(raw)
	}
	if len(list.Devices) == 0 {
		c.println("No devices yet. Connect a device to the lab network (Wi-Fi or LAN port) and it will appear here.")
		return nil
	}
	now := c.now()
	listing := newTable("NAME", "VENDOR", "IP", "MAC", "STATUS", "LAST SEEN")
	for _, device := range list.Devices {
		status := c.statusWord("offline")
		if device.Online {
			status = c.statusWord("online")
		}
		addresses := device.ipAddresses(true)
		if len(addresses) == 0 {
			addresses = device.ipAddresses(false)
		}
		listing.add(device.name(), orDash(device.vendor()), joinLimited(addresses, 1), joinLimited(device.macAddresses(), 1), status, humanAgo(now, device.LastSeen))
	}
	listing.render(c.stdout, c)
	c.printf("\n%s. Details: shakerproxy device <name|ip|mac>\n", plural(len(list.Devices), "device", "devices"))
	return nil
}

func (c *cli) deviceCommand(args []string) error {
	flags := newFlags("device")
	window := flags.String("window", "24h", "findings window")
	positional, err := parseFlags("device", flags, args)
	if err != nil {
		return err
	}
	if err := expectArgs("device", positional, 1, 1, "device reference"); err != nil {
		return err
	}
	if !windowPattern.MatchString(*window) {
		return usagef("device", "--window must look like 1h, 24h or 7d.")
	}
	if err := checkRef("device", positional[0]); err != nil {
		return err
	}
	session, err := c.openAPI()
	if err != nil {
		return err
	}
	match, err := c.resolveDevice(session, "device", positional[0])
	if err != nil {
		return err
	}
	var device inventoryDevice
	deviceRaw, err := session.getJSON("/api/v1/devices/"+url.PathEscape(match.DeviceID), &device)
	if err != nil {
		return err
	}
	// Optional sections: an older control API may not have them yet.
	var controls deviceControls
	controlsRaw, controlsErr := session.getJSON(devicePath(match.DeviceID, "/controls"), &controls)
	var report deviceReport
	reportRaw, reportErr := session.getJSON(devicePath(match.DeviceID, "/report?window="+url.QueryEscape(*window)), &report)
	var running []testSession
	sessionsRaw, sessionsErr := session.do(http.MethodGet, "/api/v1/test-sessions?state=RUNNING&device="+url.QueryEscape(match.DeviceID), nil)
	if sessionsErr == nil {
		sessionsErr = decodeListField(sessionsRaw, &running, "sessions", "test_sessions", "items")
	}
	if c.jsonOutput {
		combined := map[string]any{"device": jsonRaw(deviceRaw)}
		if controlsErr == nil {
			combined["controls"] = jsonRaw(controlsRaw)
		}
		if reportErr == nil {
			combined["report"] = jsonRaw(reportRaw)
		}
		if sessionsErr == nil {
			combined["running_tests"] = running
		}
		return c.printJSON(combined)
	}
	now := c.now()
	status := c.statusWord("offline")
	if device.Online {
		status = c.statusWord("online")
	}
	c.printf("%s  %s\n", c.bold(device.name()), status)
	rows := [][2]string{
		{"Vendor", orDash(device.vendor())},
		{"Category", orDash(sanitize(device.Category))},
		{"IP addresses", joinLimited(device.ipAddresses(false), 4)},
		{"MAC addresses", joinLimited(device.macAddresses(), 4)},
		{"First seen", shortTime(device.FirstSeen)},
		{"Last seen", fmt.Sprintf("%s (%s)", shortTime(device.LastSeen), humanAgo(now, device.LastSeen))},
		{"Device ID", device.ID},
	}
	if controlsErr == nil {
		decrypt := "off"
		if controls.DecryptHTTPS {
			decrypt = "on"
		}
		rows = append(rows, [2]string{"Decrypt HTTPS", decrypt}, [2]string{"Internet", strings.ToLower(orText(controls.Internet, "ALLOW"))}, [2]string{"Blocked domains", joinLimited(controls.BlockedDomains, 5)})
	}
	if reportErr == nil && report.CATrust != "" {
		rows = append(rows, [2]string{"ShakerProxy CA", caTrustText(report.CATrust)})
	}
	if sessionsErr == nil {
		if len(running) == 0 {
			rows = append(rows, [2]string{"Test run", "none running"})
		} else {
			rows = append(rows, [2]string{"Test run", fmt.Sprintf("%s (%s, started %s)", sanitize(running[0].Name), running[0].ID, humanAgo(now, running[0].StartedAt))})
		}
	}
	c.println()
	for _, row := range rows {
		c.printf("  %-16s %s\n", row[0], row[1])
	}
	for _, warning := range device.AttributionWarnings {
		c.printf("  %s %s\n", c.style(styleYellow, "!"), sanitize(warning))
	}
	c.println()
	switch {
	case reportErr != nil:
		c.printf("Findings: unavailable (%v)\n", reportErr)
	case len(report.Findings) == 0:
		c.printf("Findings (last %s): none. Activity: %s events, %s.\n", *window, humanCount(report.Totals.Events), humanBytes(report.Totals.Bytes))
	default:
		c.printf("%s\n", c.bold(fmt.Sprintf("Findings (last %s)", *window)))
		for index, item := range sortedFindings(report.Findings) {
			if index == 5 {
				c.printf("  … and %d more. Full report: shakerproxy report %s\n", len(report.Findings)-5, quoteRef(positional[0]))
				break
			}
			c.printf("  %-9s %s\n", c.statusWord(strings.ToUpper(item.Severity)), sanitize(item.Title))
		}
	}
	ref := quoteRef(positional[0])
	c.printf("\nNext: shakerproxy watch %s · shakerproxy test start %s · shakerproxy report %s\n", ref, ref, ref)
	return nil
}

func quoteRef(ref string) string {
	if strings.ContainsAny(ref, " \t'\"$`\\") {
		return fmt.Sprintf("%q", ref)
	}
	return ref
}

func caTrustText(state string) string {
	switch strings.ToUpper(state) {
	case "INSTALLED":
		return "installed on the device"
	case "NOT_INSTALLED":
		return "not installed (testing certificate validation)"
	default:
		return "unknown"
	}
}

var severityRank = map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

func sortedFindings(findings []finding) []finding {
	sorted := append([]finding(nil), findings...)
	sort.SliceStable(sorted, func(i, j int) bool {
		left, ok := severityRank[strings.ToUpper(sorted[i].Severity)]
		if !ok {
			left = 5
		}
		right, ok := severityRank[strings.ToUpper(sorted[j].Severity)]
		if !ok {
			right = 5
		}
		return left < right
	})
	return sorted
}

type jsonRaw []byte

func (raw jsonRaw) MarshalJSON() ([]byte, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return []byte("null"), nil
	}
	return raw, nil
}

func (c *cli) renameCommand(args []string) error {
	flags := newFlags("rename")
	passwordFile := flags.String("password-file", "", "administrator password file")
	user := flags.String("user", envOr("SHAKERPROXY_API_USERNAME", "admin"), "administrator username")
	positional, err := parseFlags("rename", flags, args)
	if err != nil {
		return err
	}
	if len(positional) > 2 {
		// Allow an unquoted multi-word name: shakerproxy rename tv Living room TV
		positional = []string{positional[0], strings.Join(positional[1:], " ")}
	}
	if err := expectArgs("rename", positional, 2, 2, "device reference", "new name"); err != nil {
		return err
	}
	newName := strings.TrimSpace(positional[1])
	if newName == "" || len(newName) > 128 || strings.ContainsAny(newName, "\x00\r\n") {
		return usagef("rename", "The new name must be 1-128 characters on one line.")
	}
	if err := checkRef("rename", positional[0]); err != nil {
		return err
	}
	session, err := c.openAPI()
	if err != nil {
		return err
	}
	match, err := c.resolveDevice(session, "rename", positional[0])
	if err != nil {
		return err
	}
	var device inventoryDevice
	if _, err := session.getJSON("/api/v1/devices/"+url.PathEscape(match.DeviceID), &device); err != nil {
		return err
	}
	fmt.Fprintf(c.stderr, "Renaming %s (%s) to %q.\n", device.name(), joinLimited(device.ipAddresses(false), 2), newName)
	password, err := c.obtainPassword(*passwordFile, false, "Admin password (to rename the device): ")
	if err != nil {
		return err
	}
	admin, err := c.adminSession(*user, password)
	if err != nil {
		return err
	}
	defer admin.close()
	payload := map[string]any{"password": password, "friendly_name": newName, "reason": "renamed with shakerproxy CLI", "expected_revision": device.AliasRevision}
	if _, err := admin.doWithHeaders(http.MethodPut, "/api/v1/devices/"+url.PathEscape(match.DeviceID)+"/alias", payload, map[string]string{"Idempotency-Key": "cli-rename-" + randomHex(12)}); err != nil {
		return err
	}
	if c.jsonOutput {
		return c.printJSON(map[string]any{"device_id": match.DeviceID, "friendly_name": newName, "previous_name": device.FriendlyName})
	}
	c.printf("Renamed %s to %q.\n", orText(sanitize(device.FriendlyName), match.DeviceID), newName)
	return nil
}

func (c *cli) watchCommand(args []string) error {
	flags := newFlags("watch")
	interval := flags.Duration("interval", 2*time.Second, "poll interval")
	positional, err := parseFlags("watch", flags, args)
	if err != nil {
		return err
	}
	if err := expectArgs("watch", positional, 0, 1); err != nil {
		return err
	}
	if *interval < 500*time.Millisecond || *interval > time.Minute {
		return usagef("watch", "--interval must be between 500ms and 1m.")
	}
	if len(positional) == 1 {
		if err := checkRef("watch", positional[0]); err != nil {
			return err
		}
	}
	session, err := c.openAPI()
	if err != nil {
		return err
	}
	query := url.Values{"limit": {"50"}}
	label := "all devices"
	if len(positional) == 1 {
		match, err := c.resolveDevice(session, "watch", positional[0])
		if err != nil {
			return err
		}
		query.Set("device_id", match.DeviceID)
		label = orText(sanitize(match.FriendlyName), match.DeviceID)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if !c.jsonOutput {
		fmt.Fprintf(c.stderr, "Watching %s. Press Ctrl-C to stop.\n", label)
	}
	seen := make(map[string]bool)
	var order []string
	first := true
	for polls := 0; ; polls++ {
		var page eventPage
		if _, err := session.getJSON("/api/v1/events?"+query.Encode(), &page); err != nil {
			return err
		}
		events := page.Events
		sort.SliceStable(events, func(i, j int) bool { return eventBefore(events[i], events[j]) })
		if first && len(events) > 10 {
			// Show a little recent context, then only new activity.
			for _, event := range events[:len(events)-10] {
				seen[event.RecordID] = true
				order = append(order, event.RecordID)
			}
			events = events[len(events)-10:]
		}
		for _, event := range events {
			if event.RecordID == "" || seen[event.RecordID] {
				continue
			}
			seen[event.RecordID] = true
			order = append(order, event.RecordID)
			c.printEventLine(event, len(positional) == 0)
		}
		if len(order) > 5000 {
			for _, id := range order[:len(order)-2000] {
				delete(seen, id)
			}
			order = append([]string(nil), order[len(order)-2000:]...)
		}
		first = false
		if c.maxPolls > 0 && polls+1 >= c.maxPolls {
			return nil
		}
		select {
		case <-ctx.Done():
			if !c.jsonOutput {
				fmt.Fprintln(c.stderr, "Stopped.")
			}
			return nil
		case <-time.After(*interval):
		}
	}
}

// eventBefore orders events by occurrence time; timestamps with different
// fractional precision do not sort correctly as strings.
func eventBefore(left, right eventRecord) bool {
	leftTime, leftOK := parseTime(left.OccurredAt)
	rightTime, rightOK := parseTime(right.OccurredAt)
	if leftOK && rightOK && !leftTime.Equal(rightTime) {
		return leftTime.Before(rightTime)
	}
	return left.OccurredAt < right.OccurredAt
}

func (c *cli) printEventLine(event eventRecord, showDevice bool) {
	if c.jsonOutput {
		_ = c.printCompactJSON(event)
		return
	}
	summary := event.summaryLine()
	switch {
	case event.DetectionSummary != "" || strings.HasPrefix(summary, "Alert"):
		summary = c.style(styleRed, summary)
	case strings.Contains(summary, "failed") || strings.Contains(summary, "not decrypted") || strings.Contains(summary, "NXDOMAIN") || strings.Contains(summary, "Unidentified"):
		summary = c.style(styleYellow, summary)
	case strings.Contains(summary, "decrypted"):
		summary = c.style(styleGreen, summary)
	}
	if showDevice {
		device := orText(sanitize(event.DeviceFriendlyName), orText(event.SourceIP, "unknown device"))
		c.printf("%s  %-20s %s\n", c.dim(clockTime(event.OccurredAt)), truncate(device, 20), summary)
		return
	}
	c.printf("%s  %s\n", c.dim(clockTime(event.OccurredAt)), summary)
}

func (c *cli) searchCommand(args []string) error {
	flags := newFlags("search")
	window := flags.String("window", "1h", "how far back to search, e.g. 1h, 24h, 7d")
	deviceRef := flags.String("device", "", "only this device")
	limit := flags.Int("limit", 50, "maximum results (1-100)")
	positional, err := parseFlags("search", flags, args)
	if err != nil {
		return err
	}
	if len(positional) == 0 {
		return usagef("search", "Missing search query, e.g. shakerproxy search dns.query:*.example.com")
	}
	if !windowPattern.MatchString(*window) {
		return usagef("search", "--window must look like 15m, 1h, 24h or 7d.")
	}
	if *limit < 1 || *limit > 100 {
		return usagef("search", "--limit must be between 1 and 100.")
	}
	userQuery := strings.TrimSpace(strings.Join(positional, " "))
	if len(userQuery) > 2048 {
		return usagef("search", "The search query is too long.")
	}
	if *deviceRef != "" {
		if err := checkRef("search", *deviceRef); err != nil {
			return err
		}
	}
	session, err := c.openAPI()
	if err != nil {
		return err
	}
	query := url.Values{"limit": {fmt.Sprint(*limit)}, "q": {fmt.Sprintf("(%s) AND time:last_%s", userQuery, *window)}}
	if *deviceRef != "" {
		match, err := c.resolveDevice(session, "search", *deviceRef)
		if err != nil {
			return err
		}
		query.Set("device_id", match.DeviceID)
	}
	var page eventPage
	raw, err := session.getJSON("/api/v1/events?"+query.Encode(), &page)
	if err != nil {
		var api *apiError
		if errors.As(err, &api) && api.code == "invalid_query" {
			return withHints(api.message, "Run `shakerproxy help search` for query examples.")
		}
		return err
	}
	if c.jsonOutput {
		return c.printRawJSON(raw)
	}
	if len(page.Events) == 0 {
		c.printf("No matches in the last %s. Try a longer --window.\n", *window)
		return nil
	}
	listing := newTable("TIME", "DEVICE", "WHAT HAPPENED")
	listing.max = 96
	for _, event := range page.Events {
		listing.add(shortTime(event.OccurredAt), orDash(sanitize(firstNonEmpty(event.DeviceFriendlyName, event.SourceIP))), event.summaryLine())
	}
	listing.render(c.stdout, c)
	if page.NextCursor != "" {
		c.printf("\nShowing the newest %d matches. Narrow the query or use --limit 100 for more.\n", len(page.Events))
	}
	return nil
}

func (c *cli) protocolsCommand(args []string) error {
	flags := newFlags("protocols")
	exotic := flags.Bool("exotic", false, "only unusual protocols")
	window := flags.String("window", "24h", "1h, 24h, 7d or 30d")
	positional, err := parseFlags("protocols", flags, args)
	if err != nil {
		return err
	}
	if err := expectArgs("protocols", positional, 0, 1); err != nil {
		return err
	}
	switch *window {
	case "1h", "24h", "7d", "30d":
	default:
		return usagef("protocols", "--window must be 1h, 24h, 7d or 30d.")
	}
	query := url.Values{"window": {*window}}
	if *exotic {
		query.Set("exotic", "true")
	}
	if len(positional) == 1 {
		if err := checkRef("protocols", positional[0]); err != nil {
			return err
		}
	}
	session, err := c.openAPI()
	if err != nil {
		return err
	}
	if len(positional) == 1 {
		match, err := c.resolveDevice(session, "protocols", positional[0])
		if err != nil {
			return err
		}
		query.Set("device", match.DeviceID)
	}
	var result protocolReport
	raw, err := session.getJSON("/api/v1/protocols?"+query.Encode(), &result)
	if err != nil {
		return err
	}
	if c.jsonOutput {
		return c.printRawJSON(raw)
	}
	if len(result.Protocols) == 0 {
		if *exotic {
			c.printf("No unusual protocols in the last %s.\n", *window)
		} else {
			c.printf("No traffic in the last %s.\n", *window)
		}
		return nil
	}
	listing := newTable("PROTOCOL", "CATEGORY", "VISIBILITY", "FLOWS", "BYTES", "DEVICES", "NOTE")
	for _, item := range result.Protocols {
		var notes []string
		if item.Novel {
			notes = append(notes, c.style(styleYellow, "new"))
		}
		if item.Exotic {
			notes = append(notes, "unusual")
		}
		devices := fmt.Sprint(item.DeviceCount)
		if len(positional) == 0 && len(item.Devices) > 0 && len(item.Devices) <= 2 {
			names := make([]string, 0, len(item.Devices))
			for _, device := range item.Devices {
				names = append(names, orText(device.DeviceName, device.DeviceID))
			}
			devices = joinLimited(names, 2)
		}
		listing.add(sanitize(orText(item.Label, item.Protocol)), orDash(sanitize(item.Category)), visibilityText(item.Visibility), humanCount(item.Flows), humanBytes(item.Bytes), devices, strings.Join(notes, ", "))
	}
	listing.render(c.stdout, c)
	coverage := result.Coverage
	if coverage.TotalBytes > 0 {
		c.printf("\nOf %s: %s decrypted, %s cleartext, %s encrypted (metadata only), %s unidentified (%.0f%%).\n",
			humanBytes(coverage.TotalBytes), humanBytes(coverage.DecryptedBytes), humanBytes(coverage.CleartextBytes), humanBytes(coverage.EncryptedMetadataBytes), humanBytes(coverage.OpaqueBytes), coverage.OpaquePercent)
	}
	if result.Truncated {
		c.println("The list was shortened; use --json for everything.")
	}
	return nil
}

func visibilityText(value string) string {
	switch strings.ToUpper(value) {
	case "DECRYPTED":
		return "decrypted"
	case "CLEARTEXT":
		return "cleartext"
	case "ENCRYPTED_METADATA":
		return "encrypted"
	case "OPAQUE":
		return "unidentified"
	default:
		return orDash(strings.ToLower(value))
	}
}

func randomHex(bytesCount int) string {
	value := make([]byte, bytesCount)
	if _, err := rand.Read(value); err != nil {
		return fmt.Sprintf("%016x", time.Now().UnixNano())
	}
	return fmt.Sprintf("%x", value)
}
