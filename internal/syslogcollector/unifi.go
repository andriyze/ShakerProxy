package syslogcollector

import (
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"shakerproxy.dev/shakerproxy/internal/ingest"
)

// Record is one normalized event the UniFi layer recognized. Kind is an
// ingest.NetworkGear* kind; Payload is the bounded field set for that kind.
type Record struct {
	Kind    string
	Payload map[string]any
}

// The parsers below recognize the log formats a UniFi gateway (UDM/UXG/USG,
// UniFi OS 3.x / Network 8.x) emits over remote syslog. UniFi does not publish
// a stable log schema, so every pattern here is ASSUMED from observed output
// and dnsmasq/hostapd/iptables conventions, and is commented so it can be
// corrected against a real device. Unrecognized lines return nil and are
// counted as unparsed, never executed.

var (
	// dnsmasq-dhcp: "DHCPACK(br0) 192.168.1.50 aa:bb:cc:dd:ee:ff hostname".
	// The hostname is optional. ASSUMED: UniFi runs dnsmasq for DHCP.
	reDHCPACK = regexp.MustCompile(`^DHCPACK\((?P<iface>[^)]*)\)\s+(?P<ip>[0-9a-fA-F.:]+)\s+(?P<mac>[0-9a-fA-F:]{17})(?:\s+(?P<host>\S.*))?$`)

	// hostapd / UniFi station daemon association and departure. ASSUMED forms:
	//   "ath0: STA aa:bb:cc:dd:ee:ff IEEE 802.11: associated"
	//   "ath0: STA aa:bb:cc:dd:ee:ff IEEE 802.11: disassociated"
	//   "ath0: AP-STA-CONNECTED aa:bb:cc:dd:ee:ff"
	//   "ath0: AP-STA-DISCONNECTED aa:bb:cc:dd:ee:ff"
	reHostapdSTA     = regexp.MustCompile(`^(?P<iface>\S+): STA (?P<mac>[0-9a-fA-F:]{17}) IEEE 802\.11: (?P<state>associated|disassociated|deauthenticated|authenticated)`)
	reHostapdConnect = regexp.MustCompile(`^(?P<iface>\S+): AP-STA-(?P<state>CONNECTED|DISCONNECTED) (?P<mac>[0-9a-fA-F:]{17})`)

	// iptables/kernel firewall log. UniFi prefixes the rule set and action,
	// e.g. "[WAN_LOCAL-default-D]" (D = drop) or "...-A" (accept), followed by
	// the standard "IN= OUT= SRC= DST= PROTO= SPT= DPT=" key/value fields.
	reFirewallPrefix = regexp.MustCompile(`\[(?P<prefix>[A-Za-z0-9_.-]+)\]`)

	// IDS/IPS (Suricata on UniFi): a bracketed signature id and name, then
	// "{PROTO} src:sport -> dst:dport". ASSUMED from Suricata fast-log form.
	reIDS = regexp.MustCompile(`\[\d+:\d+:\d+\]\s+(?P<sig>.+?)\s+\[\*\*\].*?\{(?P<proto>\w+)\}\s+(?P<src>[0-9a-fA-F.:]+):(?P<sport>\d+)\s+->\s+(?P<dst>[0-9a-fA-F.:]+):(?P<dport>\d+)`)

	keyValuePattern = regexp.MustCompile(`([A-Z][A-Z0-9_]*)=(\S*)`)
)

// Parse turns one syslog message into zero or one network-gear records. It
// dispatches on the program tag first, then the content, so a line is only
// ever matched by the parser for its program.
func Parse(message Message) (Record, bool) {
	app := strings.ToLower(message.App)
	content := strings.TrimSpace(message.Content)
	switch {
	case strings.Contains(app, "dnsmasq"), strings.HasPrefix(content, "DHCPACK"):
		return parseDHCP(content)
	case strings.Contains(app, "hostapd"), strings.Contains(app, "stad"), strings.Contains(app, "stahtd"):
		return parseWiFi(content)
	case strings.Contains(app, "suricata"), strings.Contains(app, "ips"), strings.Contains(app, "ids"):
		return parseIDS(content)
	case strings.Contains(app, "kernel"), reFirewallPrefix.MatchString(content) && strings.Contains(content, "SRC="):
		if record, ok := parseFirewall(content); ok {
			return record, true
		}
		return parseSystem(app, content)
	default:
		return parseSystem(app, content)
	}
}

func parseDHCP(content string) (Record, bool) {
	match := submatch(reDHCPACK, content)
	if match == nil {
		return Record{}, false
	}
	ip, err := netip.ParseAddr(match["ip"])
	if err != nil {
		return Record{}, false
	}
	payload := map[string]any{
		"mac":           strings.ToLower(match["mac"]),
		"assigned_addr": ip.String(),
	}
	if host := cleanHostname(match["host"]); host != "" {
		payload["host_name"] = host
	}
	if iface := bounded(match["iface"], 32); iface != "" {
		payload["interface"] = iface
	}
	return Record{Kind: ingest.NetworkGearDHCPKind, Payload: payload}, true
}

func parseWiFi(content string) (Record, bool) {
	var iface, mac, state string
	if match := submatch(reHostapdSTA, content); match != nil {
		iface, mac, state = match["iface"], match["mac"], match["state"]
	} else if match := submatch(reHostapdConnect, content); match != nil {
		iface, mac = match["iface"], match["mac"]
		if match["state"] == "CONNECTED" {
			state = "associated"
		} else {
			state = "disassociated"
		}
	} else {
		return Record{}, false
	}
	event := "assoc"
	switch state {
	case "disassociated", "deauthenticated":
		event = "leave"
	case "authenticated":
		event = "auth"
	}
	payload := map[string]any{"mac": strings.ToLower(mac), "event": event}
	if iface := bounded(iface, 32); iface != "" {
		payload["access_point"] = iface
	}
	return Record{Kind: ingest.NetworkGearWiFiKind, Payload: payload}, true
}

func parseFirewall(content string) (Record, bool) {
	if !strings.Contains(content, "SRC=") {
		return Record{}, false
	}
	fields := map[string]string{}
	for _, pair := range keyValuePattern.FindAllStringSubmatch(content, -1) {
		fields[pair[1]] = pair[2]
	}
	src, srcOK := parseAddr(fields["SRC"])
	dst, dstOK := parseAddr(fields["DST"])
	if !srcOK && !dstOK {
		return Record{}, false
	}
	payload := map[string]any{}
	if srcOK {
		payload["source_ip"] = src
	}
	if dstOK {
		payload["destination_ip"] = dst
	}
	if port := parsePort(fields["SPT"]); port > 0 {
		payload["source_port"] = port
	}
	if port := parsePort(fields["DPT"]); port > 0 {
		payload["destination_port"] = port
	}
	if proto := strings.ToLower(bounded(fields["PROTO"], 16)); proto != "" {
		payload["protocol"] = proto
	}
	chain, action := firewallChainAction(content)
	if chain != "" {
		payload["chain"] = chain
	}
	payload["action"] = action
	return Record{Kind: ingest.NetworkGearFirewallKind, Payload: payload}, true
}

// firewallChainAction reads the bracketed UniFi rule prefix. ASSUMED: a
// trailing "-D"/"-R" means a drop/reject and "-A" an accept; a prefix
// containing DROP/REJECT/BLOCK (case-insensitive) is a block.
func firewallChainAction(content string) (string, string) {
	match := submatch(reFirewallPrefix, content)
	if match == nil {
		return "", "unknown"
	}
	prefix := bounded(match["prefix"], 64)
	upper := strings.ToUpper(prefix)
	action := "unknown"
	switch {
	case strings.Contains(upper, "DROP"), strings.Contains(upper, "REJECT"), strings.Contains(upper, "BLOCK"), strings.HasSuffix(upper, "-D"), strings.HasSuffix(upper, "-R"):
		action = "drop"
	case strings.Contains(upper, "ACCEPT"), strings.Contains(upper, "ALLOW"), strings.HasSuffix(upper, "-A"):
		action = "accept"
	}
	return prefix, action
}

func parseIDS(content string) (Record, bool) {
	match := submatch(reIDS, content)
	if match == nil {
		return Record{}, false
	}
	payload := map[string]any{"signature": bounded(match["sig"], 200)}
	if proto := strings.ToLower(bounded(match["proto"], 16)); proto != "" {
		payload["protocol"] = proto
	}
	if src, ok := parseAddr(match["src"]); ok {
		payload["source_ip"] = src
	}
	if dst, ok := parseAddr(match["dst"]); ok {
		payload["destination_ip"] = dst
	}
	if port := parsePort(match["sport"]); port > 0 {
		payload["source_port"] = port
	}
	if port := parsePort(match["dport"]); port > 0 {
		payload["destination_port"] = port
	}
	return Record{Kind: ingest.NetworkGearIDSKind, Payload: payload}, true
}

// parseSystem keeps a bounded record of WAN/link/system lines so they are
// visible, without trying to structure every message. ASSUMED: only lines
// mentioning WAN or an interface link change are worth an event; everything
// else is dropped as noise.
func parseSystem(app, content string) (Record, bool) {
	lower := strings.ToLower(content)
	if !strings.Contains(lower, "wan") && !strings.Contains(lower, "link up") && !strings.Contains(lower, "link down") {
		return Record{}, false
	}
	payload := map[string]any{"message": bounded(content, 480)}
	if app = bounded(app, 48); app != "" {
		payload["program"] = app
	}
	switch {
	case strings.Contains(lower, "down"):
		payload["event"] = "link_down"
	case strings.Contains(lower, "up"):
		payload["event"] = "link_up"
	default:
		payload["event"] = "system"
	}
	return Record{Kind: ingest.NetworkGearSystemKind, Payload: payload}, true
}

func submatch(pattern *regexp.Regexp, text string) map[string]string {
	match := pattern.FindStringSubmatch(text)
	if match == nil {
		return nil
	}
	result := map[string]string{}
	for index, name := range pattern.SubexpNames() {
		if name != "" {
			result[name] = match[index]
		}
	}
	return result
}

func parseAddr(value string) (string, bool) {
	address, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil {
		return "", false
	}
	return address.String(), true
}

func parsePort(value string) int {
	port, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || port < 1 || port > 65535 {
		return 0
	}
	return port
}

func cleanHostname(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, "\"")
	if value == "" || value == "*" || strings.EqualFold(value, "unknown") {
		return ""
	}
	return bounded(value, 253)
}

// bounded trims control characters and caps length, so a log line can never
// smuggle control bytes or an oversized field into a payload.
func bounded(value string, limit int) string {
	value = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.TrimSpace(value))
	if len(value) > limit {
		value = value[:limit]
	}
	return value
}
