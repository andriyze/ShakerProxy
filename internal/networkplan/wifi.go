package networkplan

import (
	"crypto/pbkdf2"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
)

// RoleWiFiAP marks the wireless adapter that broadcasts the lab Wi-Fi network.
const RoleWiFiAP InterfaceRole = "WIFI_AP"

// LabBridgeName is the Linux bridge that joins a wired lab port and the Wi-Fi
// access point into one lab segment when bridge_with_lab is selected.
const LabBridgeName = "lgbr0"

// labBridgeStableID identifies the synthetic bridge returned by LabInterface.
// It is never compared with host evidence; capture and health match the bridge
// by its fixed, validated name instead.
const labBridgeStableID = "shakerproxy-bridge:" + LabBridgeName

type WiFiSecurity string

const (
	WiFiSecurityWPA2PSK  WiFiSecurity = "WPA2_PSK"
	WiFiSecurityWPA3SAE  WiFiSecurity = "WPA3_SAE"
	WiFiSecurityWPA2WPA3 WiFiSecurity = "WPA2_WPA3"
	WiFiSecurityOpen     WiFiSecurity = "OPEN"
)

type WiFiBand string

const (
	WiFiBand24GHz WiFiBand = "2.4GHZ"
	WiFiBand5GHz  WiFiBand = "5GHZ"
)

const (
	DefaultWiFiChannel24GHz = 6
	DefaultWiFiChannel5GHz  = 36
	maxWiFiSSIDBytes        = 32
	minWiFiPassphrase       = 8
	maxWiFiPassphrase       = 63
	maxLinuxInterfaceName   = 15
)

// WiFiConfiguration is the optional lab access point. It is omitted from the
// canonical plan JSON when absent so existing plan hashes are unchanged.
type WiFiConfiguration struct {
	Enabled         bool         `json:"enabled"`
	SSID            string       `json:"ssid,omitempty"`
	Security        WiFiSecurity `json:"security,omitempty"`
	Passphrase      string       `json:"passphrase,omitempty"`
	CountryCode     string       `json:"country_code,omitempty"`
	Band            WiFiBand     `json:"band,omitempty"`
	Channel         int          `json:"channel,omitempty"`
	Hidden          bool         `json:"hidden"`
	ClientIsolation bool         `json:"client_isolation"`
	BridgeWithLab   bool         `json:"bridge_with_lab"`
}

// NonDFS5GHzChannels are the only 5 GHz channels ShakerProxy offers. They never
// require radar detection, so the access point starts immediately.
var NonDFS5GHzChannels = []int{36, 40, 44, 48, 149, 153, 157, 161, 165}

// WiFiEnabled reports whether the plan asks ShakerProxy to run an access point.
func WiFiEnabled(plan Plan) bool {
	return plan.WiFi != nil && plan.WiFi.Enabled
}

// WiFiAccessPoint returns the WIFI_AP interface of an enabled Wi-Fi plan.
func WiFiAccessPoint(plan Plan) (Interface, bool) {
	if !WiFiEnabled(plan) {
		return Interface{}, false
	}
	return InterfaceForRole(plan, RoleWiFiAP)
}

// WiFiBridged reports whether the wired lab port and the access point share
// the lgbr0 bridge.
func WiFiBridged(plan Plan) bool {
	if !WiFiEnabled(plan) || !plan.WiFi.BridgeWithLab {
		return false
	}
	_, wired := InterfaceForRole(plan, RoleLab)
	return wired
}

// IsLabBridge reports whether an interface returned by LabInterface is the
// synthetic ShakerProxy bridge rather than a physical host interface.
func IsLabBridge(iface Interface) bool {
	return iface.StableID == labBridgeStableID && iface.CurrentName == LabBridgeName
}

// EffectiveWiFiBand applies the documented default band (2.4 GHz, the most
// widely supported by smart devices).
func EffectiveWiFiBand(config WiFiConfiguration) WiFiBand {
	if config.Band == "" {
		return WiFiBand24GHz
	}
	return config.Band
}

// EffectiveWiFiChannel applies the documented per-band channel default.
func EffectiveWiFiChannel(config WiFiConfiguration) int {
	if config.Channel != 0 {
		return config.Channel
	}
	if EffectiveWiFiBand(config) == WiFiBand5GHz {
		return DefaultWiFiChannel5GHz
	}
	return DefaultWiFiChannel24GHz
}

// wifiLabInterface returns the effective lab segment of a Wi-Fi plan: the
// lgbr0 bridge when a wired lab port is bridged, otherwise the access point.
func wifiLabInterface(plan Plan) (Interface, bool) {
	if !WiFiEnabled(plan) || plan.Topology == TopologySingleArm || plan.Topology == TopologyPassiveSensor {
		return Interface{}, false
	}
	if WiFiBridged(plan) {
		wired, _ := InterfaceForRole(plan, RoleLab)
		return Interface{StableID: labBridgeStableID, CurrentName: LabBridgeName, Role: RoleLab, MTU: wired.MTU}, true
	}
	if _, wired := InterfaceForRole(plan, RoleLab); wired {
		// Invalid combination (wired lab without bridging); keep the wired
		// port as the lab so an invalid plan never renders a Wi-Fi segment.
		return Interface{}, false
	}
	return InterfaceForRole(plan, RoleWiFiAP)
}

func wifiTopologySupported(topology Topology) bool {
	switch topology {
	case TopologyTwoNIC, TopologyThreeInterface, TopologyExistingRoutedVLAN, TopologyAdvancedCustom:
		return true
	}
	return false
}

func validateWiFi(plan Plan, roles map[InterfaceRole]int, addError, addWarning func(string, string, string)) {
	if !WiFiEnabled(plan) {
		if roles[RoleWiFiAP] != 0 {
			addError("WIFI_ROLE_WITHOUT_WIFI", "interfaces", "An interface has the WIFI_AP role but Wi-Fi is turned off. Turn Wi-Fi on, or set that interface to UNUSED.")
		}
		return
	}
	config := *plan.WiFi
	if !wifiTopologySupported(plan.Topology) {
		addError("WIFI_TOPOLOGY_UNSUPPORTED", "topology", "A Wi-Fi access point can be added to two-NIC, three-interface, existing-routed-VLAN, and advanced plans. Choose one of those topologies or turn Wi-Fi off.")
	}
	switch roles[RoleWiFiAP] {
	case 0:
		addError("WIFI_INTERFACE_MISSING", "interfaces", "Wi-Fi is turned on but no interface has the WIFI_AP role. Set the role of the Wi-Fi adapter that should broadcast the lab network to WIFI_AP.")
	case 1:
	default:
		addError("WIFI_INTERFACE_COUNT_INVALID", "interfaces", "Only one Wi-Fi access point is supported. Keep WIFI_AP on one adapter and set the others to UNUSED.")
	}
	for index, iface := range plan.Interfaces {
		path := fmt.Sprintf("interfaces[%d]", index)
		if iface.Role == RoleWiFiAP {
			if !safeLinuxInterfaceName(iface.CurrentName) {
				addError("WIFI_INTERFACE_NAME_INVALID", path+".current_name", "The Wi-Fi interface name must be a Linux interface name of at most 15 letters, digits, dots, dashes, or underscores.")
			}
			if iface.MTU != 0 {
				addError("WIFI_INTERFACE_MTU_UNSUPPORTED", path+".mtu", "ShakerProxy does not change the MTU of the Wi-Fi adapter. Set mtu to 0.")
			}
		}
		if iface.CurrentName == LabBridgeName {
			addError("WIFI_BRIDGE_NAME_RESERVED", path+".current_name", "The name lgbr0 is reserved for the ShakerProxy lab bridge. Remove that interface from the plan or rename it on the host.")
		}
	}
	if roles[RoleLab] > 0 && !config.BridgeWithLab {
		addError("WIFI_LAB_BRIDGE_REQUIRED", "wifi.bridge_with_lab", "This plan has both a wired lab port and a Wi-Fi access point. Turn on bridge_with_lab so wired and Wi-Fi devices share one lab network, or set the wired LAB interface to UNUSED.")
	}

	ssidLength := len(config.SSID)
	switch {
	case ssidLength == 0 || ssidLength > maxWiFiSSIDBytes:
		addError("WIFI_SSID_INVALID", "wifi.ssid", fmt.Sprintf("The Wi-Fi network name (SSID) must be 1 to 32 bytes long; this one is %d bytes. Accented letters and emoji use more than one byte each.", ssidLength))
	case !utf8.ValidString(config.SSID):
		addError("WIFI_SSID_INVALID", "wifi.ssid", "The Wi-Fi network name (SSID) must be valid UTF-8 text.")
	case strings.IndexFunc(config.SSID, isControlRune) >= 0:
		addError("WIFI_SSID_CONTROL_CHARACTER", "wifi.ssid", "The Wi-Fi network name (SSID) cannot contain control characters such as line breaks or tabs.")
	}

	switch config.Security {
	case WiFiSecurityWPA2PSK, WiFiSecurityWPA3SAE, WiFiSecurityWPA2WPA3:
		validateWiFiPassphrase(config.Passphrase, addError)
		if config.Security == WiFiSecurityWPA3SAE {
			addWarning("WIFI_WPA3_ONLY", "wifi.security", "WPA3-only networks cannot be joined by older phones, TVs, and IoT devices. Choose WPA2_WPA3 if a device does not see or cannot join the network.")
		}
	case WiFiSecurityOpen:
		addWarning("WIFI_OPEN_NETWORK", "wifi.security", "The Wi-Fi network is open: anyone in range can join the lab network and read unencrypted traffic. Use WPA2_PSK unless the device under test can only join open networks.")
		if config.Passphrase != "" {
			addWarning("WIFI_PASSPHRASE_IGNORED", "wifi.passphrase", "The Wi-Fi password is ignored because security is OPEN.")
		}
	default:
		addError("WIFI_SECURITY_INVALID", "wifi.security", "Choose Wi-Fi security: WPA2_PSK (works with almost every device), WPA2_WPA3 (WPA3 for new devices and WPA2 for older ones), WPA3_SAE (newest devices only), or OPEN (no password).")
	}

	switch {
	case config.CountryCode == "":
		addError("WIFI_COUNTRY_REQUIRED", "wifi.country_code", "Set country_code to the two-letter code of the country where ShakerProxy is used (for example US, GB, or DE). It selects the Wi-Fi channels and power that are legal there.")
	case !validCountryCode(config.CountryCode):
		addError("WIFI_COUNTRY_INVALID", "wifi.country_code", fmt.Sprintf("%q is not an ISO 3166 two-letter country code. Use uppercase letters, for example US, GB, or DE.", boundedIssueValue(config.CountryCode)))
	}

	band := EffectiveWiFiBand(config)
	channel := EffectiveWiFiChannel(config)
	switch band {
	case WiFiBand24GHz:
		if channel < 1 || channel > 13 {
			addError("WIFI_CHANNEL_INVALID", "wifi.channel", "On 2.4 GHz choose channel 1 to 13. Channels 1, 6, and 11 do not overlap each other.")
		} else if channel >= 12 {
			addWarning("WIFI_CHANNEL_REGULATORY", "wifi.channel", "Channels 12 and 13 are not allowed in some countries, including the US and Canada. If the access point does not start, choose channel 1, 6, or 11.")
		}
	case WiFiBand5GHz:
		if !containsInt(NonDFS5GHzChannels, channel) {
			addError("WIFI_CHANNEL_INVALID", "wifi.channel", "On 5 GHz choose a channel that does not need radar detection: 36, 40, 44, 48, 149, 153, 157, 161, or 165.")
		} else if channel >= 149 {
			addWarning("WIFI_CHANNEL_REGULATORY", "wifi.channel", "Channels 149 to 165 are not allowed for access points in some countries, including Japan and parts of Europe. If the access point does not start, choose channel 36, 40, 44, or 48.")
		}
	default:
		addError("WIFI_BAND_INVALID", "wifi.band", "Choose band 2.4GHZ (works with almost every device) or 5GHZ (faster, but not supported by many IoT devices).")
	}

	if config.Hidden {
		addWarning("WIFI_HIDDEN_NETWORK", "wifi.hidden", "A hidden network does not make the lab private, and some devices cannot join hidden networks. Enter the network name manually on each device.")
	}
	if WiFiBridged(plan) && config.ClientIsolation {
		addWarning("WIFI_ISOLATION_BRIDGED", "wifi.client_isolation", "Wi-Fi client isolation stops Wi-Fi devices from reaching each other, but they can still reach wired lab devices on the shared lab bridge.")
	}
	if plan.IPv4.ClientIsolation && !config.ClientIsolation {
		addWarning("WIFI_ISOLATION_NOT_ENABLED", "wifi.client_isolation", "Lab client isolation does not stop Wi-Fi devices from talking to each other directly. Turn on wifi.client_isolation to isolate Wi-Fi devices too.")
	}
}

// hashablePlan is the form of the plan covered by the canonical plan hash.
// The hash is shared widely (status, audit, agent overviews), so the Wi-Fi
// password is replaced by its WPA pre-shared key (PBKDF2-HMAC-SHA1, 4096
// rounds, SSID salt). The hash still binds the exact password, but guessing it
// from the hash is no easier than from a Wi-Fi handshake captured over the air.
func hashablePlan(plan Plan) Plan {
	if plan.WiFi == nil || plan.WiFi.Passphrase == "" {
		return plan
	}
	wifi := *plan.WiFi
	wifi.Passphrase = "wpa-psk:" + hex.EncodeToString(wpaPreSharedKey(wifi.Passphrase, wifi.SSID))
	plan.WiFi = &wifi
	return plan
}

func wpaPreSharedKey(passphrase, ssid string) []byte {
	key, err := pbkdf2.Key(sha1.New, passphrase, []byte(ssid), 4096, 32)
	if err == nil {
		return key
	}
	// A FIPS-only runtime refuses SHA-1 or short salts; keep an equally slow,
	// deterministic binding instead of hashing the password directly.
	digest := sha256.Sum256([]byte("shakerproxy-wifi-psk\x00" + ssid + "\x00" + passphrase))
	for round := 1; round < 4096; round++ {
		digest = sha256.Sum256(append(digest[:], passphrase...))
	}
	return digest[:]
}

func validateWiFiPassphrase(passphrase string, addError func(string, string, string)) {
	if passphrase == "" {
		addError("WIFI_PASSPHRASE_REQUIRED", "wifi.passphrase", "Enter a Wi-Fi password of 8 to 63 characters, or choose OPEN security for a network without a password.")
		return
	}
	for _, character := range []byte(passphrase) {
		if character < 0x20 || character > 0x7e {
			addError("WIFI_PASSPHRASE_CHARACTERS", "wifi.passphrase", "The Wi-Fi password can use only printable ASCII characters: letters, digits, spaces, and symbols. Remove accented letters, emoji, tabs, and line breaks.")
			return
		}
	}
	if len(passphrase) < minWiFiPassphrase || len(passphrase) > maxWiFiPassphrase {
		addError("WIFI_PASSPHRASE_LENGTH", "wifi.passphrase", fmt.Sprintf("The Wi-Fi password must be 8 to 63 characters long; this one has %d.", len(passphrase)))
	}
}

func isControlRune(character rune) bool {
	return character < 0x20 || (character >= 0x7f && character <= 0x9f)
}

func safeLinuxInterfaceName(name string) bool {
	if name == "" || len(name) > maxLinuxInterfaceName || name == "." || name == ".." {
		return false
	}
	for _, character := range name {
		if !(character >= 'a' && character <= 'z') && !(character >= 'A' && character <= 'Z') && !(character >= '0' && character <= '9') && character != '_' && character != '.' && character != '-' {
			return false
		}
	}
	return true
}

func containsInt(values []int, expected int) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func boundedIssueValue(value string) string {
	if len(value) > 8 {
		value = value[:8]
	}
	return strings.ToValidUTF8(value, "?")
}

// WirelessInterfaceEvidence is what the privileged daemon observed about one
// host interface's Wi-Fi capabilities.
type WirelessInterfaceEvidence struct {
	Wireless     bool
	APSupported  *bool
	Bands        []WiFiBand
	DefaultRoute bool
}

// WiFiHostEvidence is the host-level evidence needed to accept a Wi-Fi plan.
type WiFiHostEvidence struct {
	HostapdInstalled     bool
	NetworkManagerActive bool
	Interfaces           map[string]WirelessInterfaceEvidence
}

// ValidateWiFiHost adds host-aware Wi-Fi findings to a validation result. It is
// a no-op for plans without an access point.
func ValidateWiFiHost(result ValidationResult, plan Plan, host WiFiHostEvidence) ValidationResult {
	ap, ok := WiFiAccessPoint(plan)
	if !ok {
		return result
	}
	addError := func(code, path, message string) {
		result.Errors = append(result.Errors, Issue{Code: code, Path: path, Message: message})
	}
	addWarning := func(code, path, message string) {
		result.Warnings = append(result.Warnings, Issue{Code: code, Path: path, Message: message})
	}
	path := "interfaces"
	for index, iface := range plan.Interfaces {
		if iface.Role == RoleWiFiAP {
			path = fmt.Sprintf("interfaces[%d].current_name", index)
			break
		}
	}
	if !host.HostapdInstalled {
		addError("WIFI_HOSTAPD_MISSING", "wifi.enabled", "The Wi-Fi access point software is not installed. Run `sudo apt install hostapd iw` on the ShakerProxy host, then preview the plan again.")
	}
	if evidence, observed := host.Interfaces[ap.CurrentName]; observed {
		if evidence.DefaultRoute {
			addError("WIFI_INTERFACE_IN_USE", path, fmt.Sprintf("%s currently carries this host's default route, so it is probably connected to another Wi-Fi network. Disconnect it from that network (or give ShakerProxy a wired uplink) before turning it into the lab access point.", ap.CurrentName))
		}
		switch {
		case !evidence.Wireless:
			addError("WIFI_INTERFACE_NOT_WIRELESS", path, fmt.Sprintf("%s is not a Wi-Fi adapter. Choose an interface that preflight lists as wireless.", ap.CurrentName))
		case evidence.APSupported == nil:
			addWarning("WIFI_AP_SUPPORT_UNKNOWN", path, fmt.Sprintf("ShakerProxy could not check whether %s can run as an access point. Install iw (`sudo apt install iw`) and preview again to check before applying.", ap.CurrentName))
		case !*evidence.APSupported:
			addError("WIFI_AP_MODE_UNSUPPORTED", path, fmt.Sprintf("The Wi-Fi adapter %s cannot run as an access point because its driver does not offer AP mode. Use an adapter that supports AP mode; see the Wi-Fi access point guide.", ap.CurrentName))
		case len(evidence.Bands) != 0 && !containsBand(evidence.Bands, EffectiveWiFiBand(*plan.WiFi)):
			addError("WIFI_BAND_UNSUPPORTED", "wifi.band", fmt.Sprintf("The Wi-Fi adapter %s does not support the %s band. Choose %s.", ap.CurrentName, bandLabel(EffectiveWiFiBand(*plan.WiFi)), bandList(evidence.Bands)))
		}
	}
	if host.NetworkManagerActive && WiFiBridged(plan) {
		addWarning("WIFI_NETWORK_MANAGER_ACTIVE", path, fmt.Sprintf("NetworkManager is running and may take over %[1]s, which stops the access point. Run `sudo nmcli device set %[1]s managed no` and add `unmanaged-devices=interface-name:%[1]s` under [keyfile] in /etc/NetworkManager/conf.d/shakerproxy-wifi.conf.", ap.CurrentName))
	}
	sortIssues(result.Errors)
	sortIssues(result.Warnings)
	if len(result.Errors) != 0 {
		result.Valid = false
		result.PlanHash = ""
	}
	return result
}

func containsBand(values []WiFiBand, expected WiFiBand) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func bandLabel(band WiFiBand) string {
	if band == WiFiBand5GHz {
		return "5 GHz"
	}
	return "2.4 GHz"
}

func bandList(bands []WiFiBand) string {
	values := make([]string, 0, len(bands))
	for _, band := range bands {
		values = append(values, string(band))
	}
	sort.Strings(values)
	return strings.Join(values, " or ")
}

func validCountryCode(code string) bool {
	if len(code) != 2 || code[0] < 'A' || code[0] > 'Z' || code[1] < 'A' || code[1] > 'Z' {
		return false
	}
	return strings.Contains(iso3166Alpha2, " "+code+" ")
}

// iso3166Alpha2 lists every officially assigned ISO 3166-1 alpha-2 code.
const iso3166Alpha2 = " " +
	"AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ " +
	"BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ " +
	"CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ " +
	"DE DJ DK DM DO DZ " +
	"EC EE EG EH ER ES ET " +
	"FI FJ FK FM FO FR " +
	"GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY " +
	"HK HM HN HR HT HU " +
	"ID IE IL IM IN IO IQ IR IS IT " +
	"JE JM JO JP " +
	"KE KG KH KI KM KN KP KR KW KY KZ " +
	"LA LB LC LI LK LR LS LT LU LV LY " +
	"MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ " +
	"NA NC NE NF NG NI NL NO NP NR NU NZ " +
	"OM " +
	"PA PE PF PG PH PK PL PM PN PR PS PT PW PY " +
	"QA " +
	"RE RO RS RU RW " +
	"SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ " +
	"TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ " +
	"UA UG UM US UY UZ " +
	"VA VC VE VG VI VN VU " +
	"WF WS " +
	"YE YT " +
	"ZA ZM ZW "
