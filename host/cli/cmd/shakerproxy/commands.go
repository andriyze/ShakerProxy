package main

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

type command struct {
	name     string
	aliases  []string
	group    string
	summary  string
	usage    []string
	details  string
	examples []string
	run      func(c *cli, args []string) error
}

const (
	groupDevices  = "Devices & testing"
	groupTraffic  = "Traffic"
	groupSystem   = "Setup & system"
	groupAdvanced = "Advanced"
)

var groupOrder = []string{groupDevices, groupTraffic, groupSystem, groupAdvanced}

// featured is the short overview printed by a bare `shakerproxy`.
var featured = []struct{ group, usage, summary string }{
	{groupDevices, "devices", "List devices and whether they are online"},
	{groupDevices, "device <ref>", "Details, controls and quick findings for one device"},
	{groupDevices, "test start <ref>", "Start a named test run (stop it with `shakerproxy test stop`)"},
	{groupDevices, "report <ref>", "Security findings (add --html report.html to share)"},
	{groupDevices, "decrypt <ref> on", "Decrypt a device's HTTPS (install the CA first: `shakerproxy ca`)"},
	{groupTraffic, "watch [<ref>]", "Live activity in plain language"},
	{groupTraffic, "search <query>", "Search recorded traffic, e.g. dns.query:*.example.com"},
	{groupTraffic, "capture start", "Record packets to PCAP files"},
	{groupSystem, "status", "Health and operating mode at a glance"},
	{groupSystem, "login", "Sign in once so the device commands can use the API"},
}

const refNote = "<ref> is a device's friendly name, IP address, MAC address or device ID."

var commands []*command

func init() {
	commands = []*command{
		// Devices & testing
		{name: "devices", group: groupDevices, summary: "List devices on the lab network",
			usage:    []string{"devices [--online] [--search TEXT]"},
			details:  "Shows every device ShakerProxy has seen, newest activity first. Needs `shakerproxy login` once.",
			examples: []string{"shakerproxy devices", "shakerproxy devices --online", "shakerproxy devices --search samsung --json"},
			run:      (*cli).devicesCommand},
		{name: "device", aliases: []string{"show"}, group: groupDevices, summary: "Show one device: addresses, controls, running test, findings",
			usage:    []string{"device <ref> [--window 24h]"},
			details:  refNote,
			examples: []string{`shakerproxy device "Living room TV"`, "shakerproxy device 10.77.0.23", "shakerproxy device aa:bb:cc:dd:ee:ff --json"},
			run:      (*cli).deviceCommand},
		{name: "rename", group: groupDevices, summary: "Give a device a friendly name",
			usage:    []string{"rename <ref> <new name> [--password-file FILE]"},
			details:  refNote + "\nRenaming changes the audited device alias, so ShakerProxy asks for the admin password.",
			examples: []string{`shakerproxy rename 10.77.0.23 "Living room TV"`},
			run:      (*cli).renameCommand},
		{name: "test", aliases: []string{"tests"}, group: groupDevices, summary: "Start, stop and list named test runs",
			usage: []string{
				"test start <ref> [--name NAME] [--notes TEXT] [--capture | --headers-only]",
				"test stop [<ref> | <test-id>]",
				"test list [--device <ref>] [--running]",
			},
			details: "A test run marks a time window for one device (\"Firmware 2.1 first boot\"), so reports and\n" +
				"comparisons cover exactly that run. --capture also records packet headers while the test runs;\n" +
				"--capture records whole packets, so domains, TLS server names and certificates are analyzed; --headers-only keeps 256 bytes per packet.\n" + refNote,
			examples: []string{`shakerproxy test start "Living room TV" --name "Firmware 2.1 first boot" --capture`, `shakerproxy test stop "Living room TV"`, "shakerproxy test list --running"},
			run:      (*cli).testCommand},
		{name: "report", group: groupDevices, summary: "Security report for a device (findings, domains, TLS, HTTP)",
			usage:    []string{"report <ref> [--window 24h | --session TEST-ID] [--html FILE | --json]"},
			details:  "Defaults to the last 24 hours. --html writes a self-contained page you can attach to a ticket.\n" + refNote,
			examples: []string{`shakerproxy report "Living room TV"`, "shakerproxy report 10.77.0.23 --session ts-0123456789abcdef01234567 --html tv-report.html", "shakerproxy report tv --window 7d --json"},
			run:      (*cli).reportCommand},
		{name: "compare", aliases: []string{"diff"}, group: groupDevices, summary: "Compare two test runs of the same device",
			usage:    []string{"compare <test-id-a> <test-id-b> [--device <ref>]"},
			details:  "Shows new and removed domains, protocols, findings and TLS changes between run A (before) and run B (after).",
			examples: []string{"shakerproxy compare ts-aaaaaaaaaaaaaaaaaaaaaaaa ts-bbbbbbbbbbbbbbbbbbbbbbbb"},
			run:      (*cli).compareCommand},
		{name: "decrypt", group: groupDevices, summary: "Turn HTTPS decryption on or off for a device",
			usage:    []string{"decrypt <ref> on|off"},
			details:  "The device must trust the ShakerProxy CA for decryption to work; run `shakerproxy ca` to install it.\n" + refNote,
			examples: []string{`shakerproxy decrypt "Living room TV" on`, "shakerproxy decrypt 10.77.0.23 off"},
			run:      (*cli).decryptCommand},
		{name: "block", group: groupDevices, summary: "Block a device's internet access or a domain",
			usage:    []string{"block <ref> internet", "block <ref> <domain>"},
			details:  "Blocking a domain also blocks its subdomains. Local network and ShakerProxy services keep working.\n" + refNote,
			examples: []string{`shakerproxy block "Living room TV" internet`, "shakerproxy block tv ads.example.com"},
			run:      (*cli).blockCommand},
		{name: "unblock", group: groupDevices, summary: "Undo a block",
			usage:    []string{"unblock <ref> internet", "unblock <ref> <domain>", "unblock <ref> --all"},
			examples: []string{`shakerproxy unblock "Living room TV" internet`, "shakerproxy unblock tv --all"},
			run:      (*cli).unblockCommand},

		// Traffic
		{name: "watch", aliases: []string{"live", "tail"}, group: groupTraffic, summary: "Follow live activity in plain language",
			usage:    []string{"watch [<ref>] [--interval 2s]"},
			details:  "Prints one line per event, e.g. \"DNS lookup api.example.com (A) → 3 answers\". Press Ctrl-C to stop.\n" + refNote,
			examples: []string{"shakerproxy watch", `shakerproxy watch "Living room TV"`},
			run:      (*cli).watchCommand},
		{name: "search", aliases: []string{"find"}, group: groupTraffic, summary: "Search recorded traffic",
			usage: []string{"search <query> [--window 1h] [--device <ref>] [--limit 50]"},
			details: "Query examples:\n" +
				"  dns.query:*.example.com          DNS lookups for a domain\n" +
				"  tls.sni:api.example.com          TLS connections to a host\n" +
				"  tls.state:FAILED                 TLS connections that failed (pinning?)\n" +
				"  http.status:>=400                HTTP errors\n" +
				"  dst.port:1883 AND protocol:tcp   Combine with AND, OR, NOT and ( )\n" +
				`  device.name:"Living room TV"     One device by name`,
			examples: []string{"shakerproxy search dns.query:*.samsungcloud.com", "shakerproxy search 'tls.state:FAILED' --window 24h --device tv"},
			run:      (*cli).searchCommand},
		{name: "protocols", aliases: []string{"protocol", "proto"}, group: groupTraffic, summary: "Which protocols devices speak (MQTT, RTSP, QUIC, ...)",
			usage:    []string{"protocols [<ref>] [--exotic] [--window 24h]"},
			details:  "--exotic shows only unusual protocols worth a closer look.\n" + refNote,
			examples: []string{"shakerproxy protocols", `shakerproxy protocols "Bench camera" --exotic`},
			run:      (*cli).protocolsCommand},
		{name: "capture", aliases: []string{"captures", "pcap"}, group: groupTraffic, summary: "Record packets to PCAP files and export them",
			usage: []string{
				"capture start [--device <ref>] [--name NAME] [--minutes 60] [--headers-only]",
				"capture stop [<capture-id>] [--wait]",
				"capture list",
				"capture stats <capture-id>",
				"capture export <capture-id> [--all DIR]",
				"capture export <capture-id> <file-name> <destination>",
				"capture auto [on|off]",
			},
			details: "ShakerProxy records lab traffic automatically while a confirmed lab routes (a 24-hour full-packet ring,\n" +
				"restarted on its own; the last two finished recordings are kept). capture auto shows it, capture auto off stops it.\n" +
				"A manual capture replaces the automatic recording until it ends.\n" +
				"Captures record the whole lab network; --device only labels the capture with the device.\n" +
				"Whole packets are recorded by default, so domains are visible; --headers-only keeps the first 256 bytes of each packet.\n" +
				"stop without an ID stops the running capture; --wait waits until its files are sealed.\n" +
				"export copies the sealed files (verified by SHA-256) into DIR, or the current directory.",
			examples: []string{`shakerproxy capture start --device "Living room TV"`, "shakerproxy capture stop --wait", "shakerproxy capture list", "shakerproxy capture auto", "shakerproxy capture export capture-0123456789abcdef0123456789abcdef --all ./pcaps"},
			run:      (*cli).captureCommand},

		// Setup & system
		{name: "status", group: groupSystem, summary: "Health and operating mode at a glance",
			usage:    []string{"status"},
			examples: []string{"shakerproxy status", "shakerproxy status --json"},
			run:      (*cli).statusCommand},
		{name: "doctor", aliases: []string{"diagnose", "check"}, group: groupSystem, summary: "Run host diagnostics (exits 1 when a check fails)",
			usage:    []string{"doctor [--verbose]"},
			details:  "Checks interfaces, routes, DNS, firewall, Docker, disk, time, capture and service ports.",
			examples: []string{"sudo shakerproxy doctor", "shakerproxy doctor --json"},
			run:      (*cli).doctorCommand},
		{name: "coverage", group: groupSystem, summary: "What traffic ShakerProxy is proven to see, and every way around it",
			usage: []string{"coverage", "coverage run --password-file FILE"},
			details: "Shows the last visibility coverage check (DNS, DoH, DoT, DoQ, HTTP, HTTPS, QUIC, TCP, UDP, ICMP, SSH, NTP, mDNS, SSDP, IPv6:\n" +
				"seen or not, as what, and how fast) and how devices could bypass ShakerProxy in this lab. `coverage run` sends one of\n" +
				"each from the virtual test lab through the real capture and analyzers; it needs the administrator password.",
			examples: []string{"shakerproxy coverage", "shakerproxy coverage run --password-file pw", "shakerproxy coverage --json"},
			run:      (*cli).coverageCommand},
		{name: "login", group: groupSystem, summary: "Sign in and store an API token for the device commands",
			usage:    []string{"login [--user admin] [--password-file FILE | --password-stdin]"},
			details:  "Creates a 90-day API token and stores it privately: in your own config directory (~/.config/shakerproxy), or for root in /etc/shakerproxy/secrets when run with sudo. Run once per user.",
			examples: []string{"shakerproxy login", "sudo shakerproxy login --password-file /root/shakerproxy-admin-password"},
			run:      (*cli).loginCommand},
		{name: "logout", group: groupSystem, summary: "Remove the stored API token",
			usage:    []string{"logout [--revoke] [--password-file FILE]"},
			details:  "--revoke also revokes the token on the appliance (asks for the admin password).",
			examples: []string{"shakerproxy logout", "shakerproxy logout --revoke"},
			run:      (*cli).logoutCommand},
		{name: "ca", aliases: []string{"certificate", "onboard"}, group: groupSystem, summary: "How to install the ShakerProxy CA on a device (QR code)",
			usage: []string{"ca [--platform ios|android|android-tv|macos|windows|linux|smart-tv|other]", "ca <ref> installed|not-installed|unknown"},
			details: "Shows the lab-network URL as a QR code, the CA fingerprint and per-platform steps.\n" +
				"`ca <ref> not-installed` records that a device does NOT trust the CA, so decrypted traffic\n" +
				"from it is reported as \"accepts untrusted certificates\".",
			examples: []string{"shakerproxy ca", "shakerproxy ca --platform android", `shakerproxy ca "Living room TV" not-installed`},
			run:      (*cli).caCommand},
		{name: "logs", aliases: []string{"log"}, group: groupSystem, summary: "Show service logs",
			usage: []string{"logs [service] [-f] [-n 200]"},
			details: "Services: gatewayd, dns, dhcp, wifi, ipv6, traffic-policy, testlab, pki, cloud, capture [<capture-id>],\n" +
				"app (all containers), or one container: control-api, web-ui, edge, ingestd, zeek, suricata, postgres, mitmproxy.\n" +
				"Without a service, shows all ShakerProxy host services.",
			examples: []string{"sudo shakerproxy logs", "sudo shakerproxy logs gatewayd -f", "sudo shakerproxy logs control-api -n 50"},
			run:      (*cli).logsCommand},
		{name: "version", group: groupSystem, summary: "Show CLI, daemon and installed release versions",
			usage:    []string{"version"},
			examples: []string{"shakerproxy version", "shakerproxy --version"},
			run:      (*cli).versionCommand},
		{name: "admin", group: groupSystem, summary: "Recover access: reset the admin account",
			usage: []string{"admin reset [--yes] [--no-wait] [--timeout 15s]"},
			details: "For a forgotten password without a recovery code. Clears the admin account and all sessions and\n" +
				"prints a new one-time setup token so you can set up again in the web UI. API tokens stay valid;\n" +
				"revoke them with `shakerproxy token revoke`. Root only.",
			examples: []string{"sudo shakerproxy admin reset"},
			run:      (*cli).adminCommand},

		// Advanced
		{name: "ports", group: groupAdvanced, summary: "Show which services own ports 53, 443, 853 and 8443",
			usage: []string{"ports"}, examples: []string{"shakerproxy ports"}, run: (*cli).portsCommand},
		{name: "probe-connectivity", aliases: []string{"probe"}, group: groupAdvanced, summary: "Test internet reachability without DNS",
			usage: []string{"probe-connectivity"}, examples: []string{"shakerproxy probe"}, run: (*cli).probeCommand},
		{name: "network", group: groupSystem, summary: "Stop routing the lab and restore the previous network",
			usage: []string{"network off [--yes]"},
			details: "Undoes the running network plan the way the watchdog would: ShakerProxy stops routing lab\n" +
				"devices and restores the host's previous Netplan, DHCP, firewall and forwarding settings.\n" +
				"Do this before uninstalling or to start over with a different plan on the Network page.",
			examples: []string{"sudo shakerproxy network off"}, run: (*cli).networkCommand},
		{name: "bypass", group: groupAdvanced, summary: "Emergency bypass: pass traffic without inspection",
			usage: []string{"bypass enable|disable"}, examples: []string{"sudo shakerproxy bypass enable"}, run: (*cli).bypassCommand},
		{name: "plan", group: groupAdvanced, summary: "Preview a network plan file",
			usage: []string{"plan <plan.json>"},
			details: "Most people build plans on the Network page of the web UI. The file format is\n" +
				"schemas/network-plan/network-plan.schema.json; see docs/networking.md.",
			examples: []string{"shakerproxy plan my-plan.json", "shakerproxy plan my-plan.json --json"}, run: (*cli).planCommand},
		{name: "config", group: groupAdvanced, summary: "Validate a network plan file",
			usage:    []string{"config validate <plan.json>"},
			details:  "Checks a plan against this host without changing anything. Format: schemas/network-plan/network-plan.schema.json.",
			examples: []string{"shakerproxy config validate my-plan.json"}, run: (*cli).configCommand},
		{name: "api", group: groupAdvanced, summary: "Call the local control API directly",
			usage: []string{"api", "api [--data FILE] METHOD /api/v1/path"},
			details: "Without arguments, lists the API's resources. Otherwise calls one route with the token stored by\n" +
				"`shakerproxy login`. METHOD is GET, POST, PUT, PATCH or DELETE.",
			examples: []string{"shakerproxy api", "sudo shakerproxy api GET /api/v1/devices", "sudo shakerproxy api GET /api/v1/openapi.yaml", "sudo shakerproxy api --data body.json POST /api/v1/test-sessions"},
			run:      (*cli).apiCommand},
		{name: "token", group: groupAdvanced, summary: "Create, list and revoke scoped API tokens",
			usage: []string{
				"token create --name NAME --scopes SCOPE[,SCOPE] [--expires 24h] --password-file FILE [--acknowledge-sensitive-scopes] [--device-ids IDS | --case-ids IDS] [--output FILE]",
				"token list --password-file FILE",
				"token revoke --password-file FILE --reason REASON TOKEN_ID",
			},
			examples: []string{"shakerproxy token create --name siem --scopes traffic:read --expires 720h --password-file pw --output siem.token"},
			run:      (*cli).tokenCommand},
		{name: "rules", group: groupAdvanced, summary: "Signed detection rules and catalogs",
			usage:    []string{"rules status", "rules preview <signed-bundle.json>", "rules update <signed-bundle.json>", "rules rollback <suricata|zeek|resolver>", "rules pin <suricata|zeek|resolver> <revision|none>"},
			examples: []string{"shakerproxy rules status", "sudo shakerproxy rules update bundle.json"},
			run:      (*cli).rulesCommand},
		{name: "management-ca", group: groupAdvanced, summary: "Show or export the management HTTPS CA",
			usage:    []string{"management-ca status", "management-ca export <destination>"},
			examples: []string{"shakerproxy management-ca export ~/shakerproxy-management-ca.crt"},
			run:      (*cli).managementCACommand},
		{name: "app", group: groupAdvanced, summary: "Application container status",
			usage: []string{"app status"}, examples: []string{"sudo shakerproxy app status"}, run: (*cli).appCommand},
		{name: "update", aliases: []string{"upgrade"}, group: groupAdvanced, summary: "Install the latest signed release",
			usage: []string{"update"}, examples: []string{"sudo shakerproxy update"}, run: (*cli).updateCommand},
		{name: "repair", group: groupAdvanced, summary: "Re-provision host services and the current release",
			usage: []string{"repair"}, examples: []string{"sudo shakerproxy repair"}, run: (*cli).repairCommand},
		{name: "rollback", group: groupAdvanced, summary: "Return to the previous application release",
			usage: []string{"rollback"}, examples: []string{"sudo shakerproxy rollback"}, run: (*cli).rollbackCommand},
		{name: "uninstall", group: groupAdvanced, summary: "Remove ShakerProxy (keeps data unless --purge-data)",
			usage:    []string{"uninstall [--purge-data [--yes]]"},
			details:  "--purge-data also deletes configuration, secrets and all recorded data and asks you to type a confirmation.",
			examples: []string{"sudo shakerproxy uninstall", "sudo shakerproxy uninstall --purge-data"},
			run:      (*cli).uninstallCommand},
	}
}

func lookupCommand(name string) *command {
	for _, candidate := range commands {
		if candidate.name == name {
			return candidate
		}
		for _, alias := range candidate.aliases {
			if alias == name {
				return candidate
			}
		}
	}
	return nil
}

func commandNames() []string {
	names := make([]string, 0, len(commands)*2)
	for _, candidate := range commands {
		names = append(names, candidate.name)
	}
	for _, candidate := range commands {
		names = append(names, candidate.aliases...)
	}
	return names
}

func unknownCommandError(name string) error {
	message := fmt.Sprintf("Unknown command %q.", name)
	if suggestion := suggest(name, commandNames()); suggestion != "" {
		message += fmt.Sprintf(" Did you mean %q?", canonicalName(suggestion))
	}
	return &usageError{message: message + "\nRun `shakerproxy help` to see all commands.", plain: true}
}

func canonicalName(name string) string {
	if command := lookupCommand(name); command != nil {
		return command.name
	}
	return name
}

// unknownSubcommand reports a typo in a subcommand ("shakerproxy capture strat").
func unknownSubcommand(parent, name string, options []string) error {
	if name == "" {
		return usagef(parent, "Missing %s command. Choose one of: %s.", parent, strings.Join(options, ", "))
	}
	message := fmt.Sprintf("Unknown %s command %q.", parent, name)
	if suggestion := suggest(name, options); suggestion != "" {
		message += fmt.Sprintf(" Did you mean %q?", suggestion)
	}
	return usagef(parent, "%s", message)
}

// suggest returns the closest candidate within a small edit distance, or a
// unique prefix match.
func suggest(input string, candidates []string) string {
	input = strings.ToLower(strings.TrimSpace(input))
	if input == "" {
		return ""
	}
	best, bestDistance := "", 1<<30
	for _, candidate := range candidates {
		if distance := editDistance(input, candidate); distance < bestDistance {
			best, bestDistance = candidate, distance
		}
	}
	limit := 2
	if len(input) <= 3 {
		limit = 1
	}
	if bestDistance <= limit {
		return best
	}
	var prefixed []string
	seen := map[string]bool{}
	for _, candidate := range candidates {
		if len(input) >= 2 && strings.HasPrefix(candidate, input) && !seen[canonicalName(candidate)] {
			seen[canonicalName(candidate)] = true
			prefixed = append(prefixed, candidate)
		}
	}
	if len(prefixed) == 1 {
		return prefixed[0]
	}
	return ""
}

// editDistance is the optimal-string-alignment distance, so a swapped pair
// of letters ("stauts") counts as one edit.
func editDistance(left, right string) int {
	a, b := []rune(left), []rune(right)
	rows := make([][]int, len(a)+1)
	for index := range rows {
		rows[index] = make([]int, len(b)+1)
		rows[index][0] = index
	}
	for column := range rows[0] {
		rows[0][column] = column
	}
	for i := 1; i <= len(a); i++ {
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			rows[i][j] = min(rows[i-1][j]+1, rows[i][j-1]+1, rows[i-1][j-1]+cost)
			if i > 1 && j > 1 && a[i-1] == b[j-2] && a[i-2] == b[j-1] {
				rows[i][j] = min(rows[i][j], rows[i-2][j-2]+1)
			}
		}
	}
	return rows[len(a)][len(b)]
}

func (c *cli) printOverview(w io.Writer) {
	fmt.Fprintln(w, c.bold("ShakerProxy")+" watches, records and tests what your devices do on the network.")
	fmt.Fprintln(w, refNote)
	for _, group := range groupOrder[:3] {
		fmt.Fprintln(w)
		fmt.Fprintln(w, c.bold(group))
		for _, item := range featured {
			if item.group == group {
				fmt.Fprintf(w, "  %-20s %s\n", item.usage, item.summary)
			}
		}
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "More: `shakerproxy help` lists every command; `shakerproxy help <command>` shows examples.")
}

func (c *cli) printFullHelp(w io.Writer) {
	fmt.Fprintln(w, "Usage: shakerproxy <command> [arguments] [--json] [--no-color] [--socket PATH]")
	fmt.Fprintln(w, refNote)
	for _, group := range groupOrder {
		fmt.Fprintln(w)
		fmt.Fprintln(w, c.bold(group))
		var names []*command
		for _, candidate := range commands {
			if candidate.group == group {
				names = append(names, candidate)
			}
		}
		for _, candidate := range names {
			fmt.Fprintf(w, "  %-20s %s\n", candidate.name, candidate.summary)
		}
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, c.bold("Options (work with every command)"))
	fmt.Fprintln(w, "  --json               Machine-readable output for scripts")
	fmt.Fprintln(w, "  --no-color           Plain output (also honours NO_COLOR)")
	fmt.Fprintln(w, "  --socket PATH        Gateway daemon socket (default /run/shakerproxy/gatewayd.sock)")
	fmt.Fprintln(w, "  -h, --help           Help for a command")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Exit codes: 0 success, 1 failure, 2 wrong usage.")
	fmt.Fprintln(w, "Run `shakerproxy help <command>` for details and examples.")
}

func (c *cli) printCommandHelp(w io.Writer, command *command) {
	fmt.Fprintf(w, "%s — %s\n\n", c.bold("shakerproxy "+command.name), command.summary)
	fmt.Fprintln(w, "Usage:")
	for _, line := range command.usage {
		fmt.Fprintf(w, "  shakerproxy %s\n", line)
	}
	if command.details != "" {
		fmt.Fprintln(w)
		fmt.Fprintln(w, command.details)
	}
	if len(command.examples) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Examples:")
		for _, example := range command.examples {
			fmt.Fprintf(w, "  %s\n", example)
		}
	}
	if len(command.aliases) > 0 {
		aliases := append([]string(nil), command.aliases...)
		sort.Strings(aliases)
		fmt.Fprintf(w, "\nAlso works as: %s\n", strings.Join(aliases, ", "))
	}
	fmt.Fprintln(w, "\nOptions for every command: --json, --no-color, --socket PATH")
}

func (c *cli) helpCommand(args []string) error {
	if len(args) == 0 {
		c.printFullHelp(c.stdout)
		return nil
	}
	if args[0] == "help" {
		fmt.Fprintln(c.stdout, "Usage: shakerproxy help [command]")
		return nil
	}
	command := lookupCommand(args[0])
	if command == nil {
		return unknownCommandError(args[0])
	}
	c.printCommandHelp(c.stdout, command)
	return nil
}
