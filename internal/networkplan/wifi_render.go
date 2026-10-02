package networkplan

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// ManagedHostapdPath is the only hostapd configuration ShakerProxy writes.
const ManagedHostapdPath = "/etc/shakerproxy/hostapd/shakerproxy.conf"

// HostapdUnit is the systemd unit that runs the lab access point.
const HostapdUnit = "shakerproxy-hostapd.service"

// HostapdControlDirectory is the root-only hostapd_cli control socket directory
// created by the unit's RuntimeDirectory.
const HostapdControlDirectory = "/run/shakerproxy-hostapd"

const redactedSecret = "<redacted>"

var hostapdSecretKeys = []string{"wpa_passphrase=", "sae_password="}

// RenderHostapdConf renders the complete hostapd configuration, including the
// Wi-Fi password. Only the apply path writes it, to a 0600 root-owned file; the
// preview carries RedactHostapdConf of the same text.
//
// Every value is typed and validated before it reaches this renderer. The SSID
// is additionally hex-encoded through ssid2= so no byte of it can terminate the
// line, and the password is restricted to printable ASCII, so neither can
// inject another configuration directive.
func RenderHostapdConf(plan Plan) (string, error) {
	ap, ok := WiFiAccessPoint(plan)
	if !ok {
		return "", errors.New("plan does not enable a Wi-Fi access point")
	}
	config := *plan.WiFi
	if !safeLinuxInterfaceName(ap.CurrentName) || len(config.SSID) == 0 || len(config.SSID) > maxWiFiSSIDBytes || !validCountryCode(config.CountryCode) {
		return "", errors.New("Wi-Fi access point configuration is not validated")
	}
	if strings.ContainsAny(config.Passphrase, "\r\n\x00") {
		return "", errors.New("Wi-Fi password contains a line break")
	}
	band := EffectiveWiFiBand(config)
	channel := EffectiveWiFiChannel(config)

	var b strings.Builder
	line := func(key, value string) {
		b.WriteString(key)
		b.WriteByte('=')
		b.WriteString(value)
		b.WriteByte('\n')
	}
	b.WriteString("# Managed by ShakerProxy. The next network apply replaces this file.\n")
	line("interface", ap.CurrentName)
	if bridge := AccessPointBridgeName(plan); bridge != "" {
		line("bridge", bridge)
	}
	line("driver", "nl80211")
	line("ctrl_interface", HostapdControlDirectory)
	line("logger_syslog", "0")
	line("logger_stdout", "-1")
	line("logger_stdout_level", "2")
	line("ssid2", hex.EncodeToString([]byte(config.SSID)))
	if !isASCII(config.SSID) && utf8.ValidString(config.SSID) {
		line("utf8_ssid", "1")
	}
	line("ignore_broadcast_ssid", boolDigit(config.Hidden))
	line("country_code", config.CountryCode)
	line("ieee80211d", "1")
	if band == WiFiBand5GHz {
		line("hw_mode", "a")
	} else {
		line("hw_mode", "g")
	}
	line("channel", fmt.Sprintf("%d", channel))
	line("ieee80211n", "1")
	if band == WiFiBand5GHz {
		line("ieee80211ac", "1")
	}
	line("wmm_enabled", "1")
	line("auth_algs", "1")
	line("macaddr_acl", "0")
	line("ap_isolate", boolDigit(config.ClientIsolation))
	switch config.Security {
	case WiFiSecurityWPA2PSK:
		line("wpa", "2")
		line("wpa_key_mgmt", "WPA-PSK")
		line("rsn_pairwise", "CCMP")
		line("wpa_passphrase", config.Passphrase)
	case WiFiSecurityWPA3SAE:
		line("wpa", "2")
		line("wpa_key_mgmt", "SAE")
		line("rsn_pairwise", "CCMP")
		line("ieee80211w", "2")
		line("sae_pwe", "2")
		// hostapd treats "|" in sae_password as a parameter separator, so the
		// password is supplied through wpa_passphrase, which SAE also uses.
		line("wpa_passphrase", config.Passphrase)
	case WiFiSecurityWPA2WPA3:
		line("wpa", "2")
		line("wpa_key_mgmt", "WPA-PSK SAE")
		line("rsn_pairwise", "CCMP")
		line("ieee80211w", "1")
		line("sae_require_mfp", "1")
		line("sae_pwe", "2")
		line("wpa_passphrase", config.Passphrase)
	case WiFiSecurityOpen:
		line("wpa", "0")
	default:
		return "", errors.New("Wi-Fi security mode is not validated")
	}
	return b.String(), nil
}

// RedactHostapdConf replaces every secret value with a fixed marker.
func RedactHostapdConf(config string) string {
	lines := strings.SplitAfter(config, "\n")
	for index, current := range lines {
		for _, key := range hostapdSecretKeys {
			if strings.HasPrefix(current, key) {
				suffix := ""
				if strings.HasSuffix(current, "\n") {
					suffix = "\n"
				}
				lines[index] = key + redactedSecret + suffix
			}
		}
	}
	return strings.Join(lines, "")
}

// addWiFiPreview renders the redacted access point configuration and describes
// its effect in plain language.
func addWiFiPreview(preview *Preview, plan Plan) {
	ap, ok := WiFiAccessPoint(plan)
	if !ok {
		return
	}
	config, err := RenderHostapdConf(plan)
	if err != nil {
		return
	}
	preview.HostapdConf = RedactHostapdConf(config)
	preview.ChangedObjects = append(preview.ChangedObjects, ManagedHostapdPath, HostapdUnit)
	wifi := *plan.WiFi
	if InlineBridge(plan) {
		_, device, _ := BridgePorts(plan)
		preview.ChangedObjects = append(preview.ChangedObjects, "bridge port "+ap.CurrentName)
		preview.Impact = append(preview.Impact,
			fmt.Sprintf("ShakerProxy would broadcast the Wi-Fi network %q from %s (%s, %s channel %d); devices that join get their address, gateway and DNS from your router, through the bridge", wifi.SSID, ap.CurrentName, securityLabel(wifi.Security), bandLabel(EffectiveWiFiBand(wifi)), EffectiveWiFiChannel(wifi)),
			fmt.Sprintf("Wi-Fi %s would join bridge %s beside the device port %s: Wi-Fi devices are recorded and get the same DNS forcing and device rules as wired ones", ap.CurrentName, InlineBridgeName, device.CurrentName),
		)
	} else {
		preview.Impact = append(preview.Impact, fmt.Sprintf("ShakerProxy would broadcast the Wi-Fi network %q from %s (%s, %s channel %d); devices that join get lab addresses from ShakerProxy", wifi.SSID, ap.CurrentName, securityLabel(wifi.Security), bandLabel(EffectiveWiFiBand(wifi)), EffectiveWiFiChannel(wifi)))
	}
	if InlineBridge(plan) {
		// Described above.
	} else if WiFiBridged(plan) {
		wired, _ := InterfaceForRole(plan, RoleLab)
		preview.ChangedObjects = append(preview.ChangedObjects, "bridge "+LabBridgeName)
		preview.Impact = append(preview.Impact, fmt.Sprintf("Wired lab port %s and Wi-Fi %s would share one lab network through bridge %s, which takes over the lab gateway address", wired.CurrentName, ap.CurrentName, LabBridgeName))
	} else {
		preview.Impact = append(preview.Impact, fmt.Sprintf("The Wi-Fi network on %s would be the whole lab network", ap.CurrentName))
	}
	if wifi.Security == WiFiSecurityOpen {
		preview.Impact = append(preview.Impact, "The Wi-Fi network would be open: anyone in range could join the lab network")
	}
	if wifi.Hidden {
		preview.Impact = append(preview.Impact, "The Wi-Fi network name would not be broadcast; enter it manually on each device")
	}
	if wifi.ClientIsolation {
		preview.Impact = append(preview.Impact, "Wi-Fi devices would not be able to reach each other directly")
	}
	preview.Impact = append(preview.Impact, "The access point starts only after the rollback deadline is armed and stops if the change is rolled back")
}

// renderWiFiLabNetplan renders the lab segment of a Wi-Fi plan. The access
// point is never declared as a Wi-Fi client: in bridged mode hostapd alone owns
// it and adds it to lgbr0; otherwise it is a plain networkd link so that
// Netplan also marks it unmanaged for NetworkManager.
func renderWiFiLabNetplan(b *strings.Builder, plan Plan, lab Interface) {
	address := labNetplanAddresses(plan)
	if WiFiBridged(plan) {
		wired, _ := InterfaceForRole(plan, RoleLab)
		if wired.MTU != 0 {
			fmt.Fprintf(b, "    %s:\n      mtu: %d\n", wired.CurrentName, wired.MTU)
		} else {
			fmt.Fprintf(b, "    %s: {}\n", wired.CurrentName)
		}
		b.WriteString("  bridges:\n")
		fmt.Fprintf(b, "    %s:\n", LabBridgeName)
		fmt.Fprintf(b, "      interfaces: [%s]\n", wired.CurrentName)
		fmt.Fprintf(b, "      addresses: [%s]\n", address)
		renderLabIPv6Netplan(b, plan.IPv6.Strategy, 6)
		b.WriteString("      parameters:\n        stp: false\n")
		b.WriteString("      optional: true\n")
		return
	}
	fmt.Fprintf(b, "    %s:\n", lab.CurrentName)
	b.WriteString("      renderer: networkd\n")
	fmt.Fprintf(b, "      addresses: [%s]\n", address)
	renderLabIPv6Netplan(b, plan.IPv6.Strategy, 6)
	b.WriteString("      ignore-carrier: true\n")
	b.WriteString("      optional: true\n")
}

// wifiBridgeForwardRules keeps the shared wired/Wi-Fi lab segment behaving like
// one switch. Docker enables br_netfilter, so frames bridged between the wired
// port and the access point traverse FORWARD; without this rule, discovery
// multicast (mDNS, SSDP) between a phone and a TV would reach Docker's DROP
// policy. With lab client isolation the rule is omitted and the existing
// lab-to-lab DROP applies.
func wifiBridgeForwardRules(plan Plan, lab Interface) string {
	if !IsLabBridge(lab) || !WiFiBridged(plan) || plan.IPv4.ClientIsolation {
		return ""
	}
	return fmt.Sprintf("-A SHAKERPROXY-FORWARD -i %[1]s -o %[1]s -j ACCEPT\n", LabBridgeName)
}

func securityLabel(security WiFiSecurity) string {
	switch security {
	case WiFiSecurityWPA2PSK:
		return "WPA2 password"
	case WiFiSecurityWPA3SAE:
		return "WPA3 password"
	case WiFiSecurityWPA2WPA3:
		return "WPA2/WPA3 password"
	default:
		return "no password"
	}
}

func boolDigit(value bool) string {
	if value {
		return "1"
	}
	return "0"
}

func isASCII(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] >= 0x80 {
			return false
		}
	}
	return true
}
