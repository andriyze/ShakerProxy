package networkplan

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

const testWiFiPassphrase = "correct horse battery"

// validWiFiPlan is a two-NIC plan whose only lab segment is the access point.
func validWiFiPlan() Plan {
	plan := validTwoNICPlan()
	plan.Interfaces = []Interface{
		{StableID: "pci-0000:01:00.0", CurrentName: "enp1s0", Role: RoleWAN},
		{StableID: "path:/sys/devices/pci0000:00/0000:00:14.3|mac:02:00:00:00:00:03", CurrentName: "wlan0", Role: RoleWiFiAP},
	}
	plan.IPv4.ClientIsolation = false
	plan.WiFi = &WiFiConfiguration{Enabled: true, SSID: "ShakerProxy", Security: WiFiSecurityWPA2PSK, Passphrase: testWiFiPassphrase, CountryCode: "US"}
	return plan
}

// validBridgedWiFiPlan joins a wired lab port and the access point in lgbr0.
func validBridgedWiFiPlan() Plan {
	plan := validTwoNICPlan()
	plan.Interfaces = append(plan.Interfaces, Interface{StableID: "path:/sys/devices/pci0000:00/0000:00:14.3|mac:02:00:00:00:00:03", CurrentName: "wlan0", Role: RoleWiFiAP})
	plan.IPv4.ClientIsolation = false
	plan.WiFi = &WiFiConfiguration{Enabled: true, SSID: "ShakerProxy 5G", Security: WiFiSecurityWPA2WPA3, Passphrase: testWiFiPassphrase, CountryCode: "DE", Band: WiFiBand5GHz, Channel: 44, BridgeWithLab: true}
	return plan
}

func TestWiFiPlansValidate(t *testing.T) {
	for name, plan := range map[string]Plan{"wifi only": validWiFiPlan(), "bridged": validBridgedWiFiPlan()} {
		t.Run(name, func(t *testing.T) {
			result := Validate(plan)
			if !result.Valid || len(result.PlanHash) != 64 {
				t.Fatalf("valid Wi-Fi plan was rejected: %+v", result.Errors)
			}
		})
	}
	for _, topology := range []Topology{TopologyThreeInterface, TopologyExistingRoutedVLAN, TopologyAdvancedCustom} {
		plan := validWiFiPlan()
		plan.Topology = topology
		if result := Validate(plan); !result.Valid {
			t.Fatalf("%s Wi-Fi plan was rejected: %+v", topology, result.Errors)
		}
	}
}

func TestPlanWithoutWiFiKeepsCanonicalJSON(t *testing.T) {
	encoded, err := json.Marshal(validTwoNICPlan())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "wifi") {
		t.Fatalf("absent Wi-Fi changed the canonical plan JSON: %s", encoded)
	}
	disabled := validTwoNICPlan()
	disabled.WiFi = &WiFiConfiguration{Enabled: false, SSID: "draft", Passphrase: "x"}
	if result := Validate(disabled); !result.Valid {
		t.Fatalf("a disabled Wi-Fi draft must not block the plan: %+v", result.Errors)
	}
	if preview := BuildPreview(disabled, time.Unix(1, 0)); preview.HostapdConf != "" || containsString(preview.ChangedObjects, ManagedHostapdPath) {
		t.Fatalf("disabled Wi-Fi reached the preview: %+v", preview)
	}
}

func TestPlanHashBindsWiFiPasswordWithoutExposingIt(t *testing.T) {
	// IEEE 802.11i-2004 Annex H.4 test vector.
	if got := hex.EncodeToString(wpaPreSharedKey("password", "IEEE")); got != "f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e" {
		t.Fatalf("WPA pre-shared key derivation is wrong: %s", got)
	}
	plan := validWiFiPlan()
	canonical, err := json.Marshal(hashablePlan(plan))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(canonical), testWiFiPassphrase) || !strings.Contains(string(canonical), `"passphrase":"wpa-psk:`) {
		t.Fatalf("canonical plan hash input exposes the password: %s", canonical)
	}
	if plan.WiFi.Passphrase != testWiFiPassphrase {
		t.Fatal("hashing mutated the caller's plan")
	}
	first := Validate(plan).PlanHash
	plan.WiFi.Passphrase = "another password"
	if second := Validate(plan).PlanHash; first == "" || second == "" || first == second {
		t.Fatalf("plan hash does not bind the Wi-Fi password: %q %q", first, second)
	}
	wired := validTwoNICPlan()
	legacy, _ := json.Marshal(wired)
	if hashed, _ := json.Marshal(hashablePlan(wired)); string(hashed) != string(legacy) {
		t.Fatal("wired plan hash input changed")
	}
}

func TestWiFiValidationRejectsUnsafeOrAmbiguousPlans(t *testing.T) {
	cases := []struct {
		name string
		edit func(*Plan)
		code string
	}{
		{name: "ssid empty", edit: func(p *Plan) { p.WiFi.SSID = "" }, code: "WIFI_SSID_INVALID"},
		{name: "ssid 33 bytes", edit: func(p *Plan) { p.WiFi.SSID = strings.Repeat("a", 33) }, code: "WIFI_SSID_INVALID"},
		{name: "ssid multibyte over 32 bytes", edit: func(p *Plan) { p.WiFi.SSID = strings.Repeat("é", 17) }, code: "WIFI_SSID_INVALID"},
		{name: "ssid invalid utf8", edit: func(p *Plan) { p.WiFi.SSID = "Lab\xffGate" }, code: "WIFI_SSID_INVALID"},
		{name: "ssid newline injection", edit: func(p *Plan) { p.WiFi.SSID = "Lab\nwpa=0" }, code: "WIFI_SSID_CONTROL_CHARACTER"},
		{name: "ssid tab", edit: func(p *Plan) { p.WiFi.SSID = "Lab\tGate" }, code: "WIFI_SSID_CONTROL_CHARACTER"},
		{name: "passphrase missing", edit: func(p *Plan) { p.WiFi.Passphrase = "" }, code: "WIFI_PASSPHRASE_REQUIRED"},
		{name: "passphrase short", edit: func(p *Plan) { p.WiFi.Passphrase = "short" }, code: "WIFI_PASSPHRASE_LENGTH"},
		{name: "passphrase long", edit: func(p *Plan) { p.WiFi.Passphrase = strings.Repeat("a", 64) }, code: "WIFI_PASSPHRASE_LENGTH"},
		{name: "passphrase newline injection", edit: func(p *Plan) { p.WiFi.Passphrase = "password1\nwpa=0" }, code: "WIFI_PASSPHRASE_CHARACTERS"},
		{name: "passphrase non ascii", edit: func(p *Plan) { p.WiFi.Passphrase = "pässword123" }, code: "WIFI_PASSPHRASE_CHARACTERS"},
		{name: "passphrase delete char", edit: func(p *Plan) { p.WiFi.Passphrase = "password\x7f1" }, code: "WIFI_PASSPHRASE_CHARACTERS"},
		{name: "security missing", edit: func(p *Plan) { p.WiFi.Security = "" }, code: "WIFI_SECURITY_INVALID"},
		{name: "security wep", edit: func(p *Plan) { p.WiFi.Security = "WEP" }, code: "WIFI_SECURITY_INVALID"},
		{name: "country missing", edit: func(p *Plan) { p.WiFi.CountryCode = "" }, code: "WIFI_COUNTRY_REQUIRED"},
		{name: "country lowercase", edit: func(p *Plan) { p.WiFi.CountryCode = "us" }, code: "WIFI_COUNTRY_INVALID"},
		{name: "country world domain", edit: func(p *Plan) { p.WiFi.CountryCode = "00" }, code: "WIFI_COUNTRY_INVALID"},
		{name: "country unassigned", edit: func(p *Plan) { p.WiFi.CountryCode = "XX" }, code: "WIFI_COUNTRY_INVALID"},
		{name: "country injection", edit: func(p *Plan) { p.WiFi.CountryCode = "US\nwpa=0" }, code: "WIFI_COUNTRY_INVALID"},
		{name: "band unknown", edit: func(p *Plan) { p.WiFi.Band = "6GHZ" }, code: "WIFI_BAND_INVALID"},
		{name: "2.4 channel 14", edit: func(p *Plan) { p.WiFi.Channel = 14 }, code: "WIFI_CHANNEL_INVALID"},
		{name: "2.4 channel negative", edit: func(p *Plan) { p.WiFi.Channel = -1 }, code: "WIFI_CHANNEL_INVALID"},
		{name: "5 GHz DFS channel", edit: func(p *Plan) { p.WiFi.Band, p.WiFi.Channel = WiFiBand5GHz, 52 }, code: "WIFI_CHANNEL_INVALID"},
		{name: "5 GHz 2.4 channel", edit: func(p *Plan) { p.WiFi.Band, p.WiFi.Channel = WiFiBand5GHz, 6 }, code: "WIFI_CHANNEL_INVALID"},
		{name: "no access point interface", edit: func(p *Plan) { p.Interfaces[1].Role = RoleUnused }, code: "WIFI_INTERFACE_MISSING"},
		{name: "two access points", edit: func(p *Plan) {
			p.Interfaces = append(p.Interfaces, Interface{StableID: "wlan1", CurrentName: "wlan1", Role: RoleWiFiAP})
		}, code: "WIFI_INTERFACE_COUNT_INVALID"},
		{name: "access point role without wifi", edit: func(p *Plan) { p.WiFi.Enabled = false }, code: "WIFI_ROLE_WITHOUT_WIFI"},
		{name: "access point role without wifi object", edit: func(p *Plan) { p.WiFi = nil }, code: "WIFI_ROLE_WITHOUT_WIFI"},
		{name: "long interface name", edit: func(p *Plan) { p.Interfaces[1].CurrentName = "wlan-name-too-long" }, code: "WIFI_INTERFACE_NAME_INVALID"},
		{name: "interface colon alias", edit: func(p *Plan) { p.Interfaces[1].CurrentName = "wlan0:1" }, code: "WIFI_INTERFACE_NAME_INVALID"},
		{name: "access point mtu", edit: func(p *Plan) { p.Interfaces[1].MTU = 1400 }, code: "WIFI_INTERFACE_MTU_UNSUPPORTED"},
		{name: "reserved bridge name", edit: func(p *Plan) {
			p.Interfaces = append(p.Interfaces, Interface{StableID: "br", CurrentName: LabBridgeName, Role: RoleManagement})
		}, code: "WIFI_BRIDGE_NAME_RESERVED"},
		{name: "wired lab without bridge", edit: func(p *Plan) {
			p.Interfaces = append(p.Interfaces, Interface{StableID: "pci-0000:02:00.0", CurrentName: "enp2s0", Role: RoleLab})
		}, code: "WIFI_LAB_BRIDGE_REQUIRED"},
		{name: "single arm", edit: func(p *Plan) { p.Topology = TopologySingleArm }, code: "WIFI_TOPOLOGY_UNSUPPORTED"},
		{name: "vlan trunk", edit: func(p *Plan) { p.Topology = TopologyVLANTrunk }, code: "WIFI_TOPOLOGY_UNSUPPORTED"},
		{name: "passive", edit: func(p *Plan) { p.Topology = TopologyPassiveSensor }, code: "WIFI_TOPOLOGY_UNSUPPORTED"},
		{name: "two wired labs", edit: func(p *Plan) {
			p.WiFi.BridgeWithLab = true
			p.Interfaces = append(p.Interfaces,
				Interface{StableID: "pci-0000:02:00.0", CurrentName: "enp2s0", Role: RoleLab},
				Interface{StableID: "pci-0000:03:00.0", CurrentName: "enp3s0", Role: RoleLab})
		}, code: "LAB_COUNT_INVALID"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			plan := validWiFiPlan()
			test.edit(&plan)
			result := Validate(plan)
			if result.Valid || result.PlanHash != "" || !hasIssue(result.Errors, test.code) {
				t.Fatalf("expected %s, got valid=%t errors=%+v", test.code, result.Valid, result.Errors)
			}
			for _, issue := range result.Errors {
				if strings.HasPrefix(issue.Code, "WIFI_") && (issue.Message == "" || !strings.HasSuffix(issue.Message, ".")) {
					t.Fatalf("Wi-Fi error is not a plain sentence: %+v", issue)
				}
			}
			if preview := BuildPreview(plan, time.Unix(1, 0)); preview.HostapdConf != "" || preview.NetplanYAML != "" {
				t.Fatalf("invalid Wi-Fi plan reached the renderer: %+v", preview)
			}
		})
	}
}

func TestWiFiValidationWarnings(t *testing.T) {
	cases := []struct {
		name string
		edit func(*Plan)
		code string
	}{
		{name: "open network", edit: func(p *Plan) { p.WiFi.Security, p.WiFi.Passphrase = WiFiSecurityOpen, "" }, code: "WIFI_OPEN_NETWORK"},
		{name: "open ignores password", edit: func(p *Plan) { p.WiFi.Security = WiFiSecurityOpen }, code: "WIFI_PASSPHRASE_IGNORED"},
		{name: "wpa3 only", edit: func(p *Plan) { p.WiFi.Security = WiFiSecurityWPA3SAE }, code: "WIFI_WPA3_ONLY"},
		{name: "channel 13", edit: func(p *Plan) { p.WiFi.Channel = 13 }, code: "WIFI_CHANNEL_REGULATORY"},
		{name: "channel 165", edit: func(p *Plan) { p.WiFi.Band, p.WiFi.Channel = WiFiBand5GHz, 165 }, code: "WIFI_CHANNEL_REGULATORY"},
		{name: "hidden", edit: func(p *Plan) { p.WiFi.Hidden = true }, code: "WIFI_HIDDEN_NETWORK"},
		{name: "lab isolation without wifi isolation", edit: func(p *Plan) { p.IPv4.ClientIsolation = true }, code: "WIFI_ISOLATION_NOT_ENABLED"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			plan := validWiFiPlan()
			test.edit(&plan)
			result := Validate(plan)
			if !result.Valid || !hasIssue(result.Warnings, test.code) {
				t.Fatalf("expected valid plan with warning %s: %+v %+v", test.code, result.Errors, result.Warnings)
			}
		})
	}
	bridged := validBridgedWiFiPlan()
	bridged.WiFi.ClientIsolation = true
	if result := Validate(bridged); !result.Valid || !hasIssue(result.Warnings, "WIFI_ISOLATION_BRIDGED") {
		t.Fatalf("bridged isolation limitation was not explained: %+v", result.Warnings)
	}
}

func TestWiFiChannelDefaultsAndBands(t *testing.T) {
	config := WiFiConfiguration{}
	if EffectiveWiFiBand(config) != WiFiBand24GHz || EffectiveWiFiChannel(config) != 6 {
		t.Fatalf("2.4 GHz defaults changed: %s %d", EffectiveWiFiBand(config), EffectiveWiFiChannel(config))
	}
	config.Band = WiFiBand5GHz
	if EffectiveWiFiChannel(config) != 36 {
		t.Fatalf("5 GHz default channel changed: %d", EffectiveWiFiChannel(config))
	}
	for channel := 1; channel <= 13; channel++ {
		plan := validWiFiPlan()
		plan.WiFi.Channel = channel
		if result := Validate(plan); !result.Valid {
			t.Fatalf("2.4 GHz channel %d rejected: %+v", channel, result.Errors)
		}
	}
	for _, channel := range NonDFS5GHzChannels {
		plan := validWiFiPlan()
		plan.WiFi.Band, plan.WiFi.Channel = WiFiBand5GHz, channel
		if result := Validate(plan); !result.Valid {
			t.Fatalf("5 GHz channel %d rejected: %+v", channel, result.Errors)
		}
	}
	for _, channel := range []int{32, 50, 52, 56, 60, 64, 100, 116, 132, 140, 144, 169, 173, 177} {
		plan := validWiFiPlan()
		plan.WiFi.Band, plan.WiFi.Channel = WiFiBand5GHz, channel
		if result := Validate(plan); result.Valid {
			t.Fatalf("DFS or unsupported 5 GHz channel %d was accepted", channel)
		}
	}
}

func TestCountryCodesAreTheISOAlpha2Set(t *testing.T) {
	codes := strings.Fields(iso3166Alpha2)
	if len(codes) != 249 {
		t.Fatalf("expected 249 ISO 3166-1 alpha-2 codes, got %d", len(codes))
	}
	seen := map[string]bool{}
	for _, code := range codes {
		if seen[code] || !validCountryCode(code) {
			t.Fatalf("country code list is malformed at %q", code)
		}
		seen[code] = true
	}
	for _, code := range []string{"U", "USA", "u1", "EU", "UK", "", " US"} {
		if validCountryCode(code) {
			t.Fatalf("invalid country code %q was accepted", code)
		}
	}
}

func TestWiFiLabInterfaceIsBridgeOrAccessPoint(t *testing.T) {
	lab, ok := LabInterface(validWiFiPlan())
	if !ok || lab.CurrentName != "wlan0" || IsLabBridge(lab) {
		t.Fatalf("Wi-Fi-only lab interface is wrong: %+v", lab)
	}
	lab, ok = LabInterface(validBridgedWiFiPlan())
	if !ok || lab.CurrentName != LabBridgeName || !IsLabBridge(lab) {
		t.Fatalf("bridged lab interface is wrong: %+v", lab)
	}
	lab, ok = LabInterface(validTwoNICPlan())
	if !ok || lab.CurrentName != "enp2s0" || IsLabBridge(lab) {
		t.Fatalf("wired lab interface changed: %+v", lab)
	}
	if ap, ok := WiFiAccessPoint(validBridgedWiFiPlan()); !ok || ap.CurrentName != "wlan0" {
		t.Fatalf("access point lookup failed: %+v", ap)
	}
}

func TestWiFiOnlyPreviewRendersAccessPointAsLabSegment(t *testing.T) {
	preview := BuildPreview(validWiFiPlan(), time.Unix(100, 0))
	if !preview.Validation.Valid {
		t.Fatalf("Wi-Fi preview invalid: %+v", preview.Validation.Errors)
	}
	assertFixture(t, "90-shakerproxy-wifi.yaml", preview.NetplanYAML)
	assertFixture(t, "hostapd-shakerproxy-wifi.conf", preview.HostapdConf)
	if !strings.Contains(preview.KeaDHCP4JSON, "\"wlan0\"") {
		t.Fatalf("Kea does not serve the access point:\n%s", preview.KeaDHCP4JSON)
	}
	for _, expected := range []string{
		"-A SHAKERPROXY-FORWARD -i wlan0 ! -s 10.77.0.0/24 -j DROP",
		"-A SHAKERPROXY-FORWARD -i wlan0 -o enp1s0 -s 10.77.0.0/24 -j ACCEPT",
		"-A SHAKERPROXY-FORWARD -i enp1s0 -o wlan0 -d 10.77.0.0/24 -j DROP",
	} {
		if !strings.Contains(preview.FirewallRestoreIPv4, expected) {
			t.Fatalf("firewall missing %q:\n%s", expected, preview.FirewallRestoreIPv4)
		}
	}
	if strings.Contains(preview.FirewallRestoreIPv4, LabBridgeName) || strings.Contains(preview.NetplanYAML, "bridges:") {
		t.Fatalf("Wi-Fi-only plan rendered a bridge:\n%s\n%s", preview.NetplanYAML, preview.FirewallRestoreIPv4)
	}
	for _, object := range []string{ManagedHostapdPath, HostapdUnit} {
		if !containsString(preview.ChangedObjects, object) {
			t.Fatalf("changed objects miss %s: %+v", object, preview.ChangedObjects)
		}
	}
	if !impactMentions(preview.Impact, `broadcast the Wi-Fi network "ShakerProxy" from wlan0 (WPA2 password, 2.4 GHz channel 6)`) || !impactMentions(preview.Impact, "whole lab network") {
		t.Fatalf("impact does not explain the access point: %+v", preview.Impact)
	}
}

func TestBridgedWiFiPreviewJoinsWiredLabAndAccessPoint(t *testing.T) {
	plan := validBridgedWiFiPlan()
	preview := BuildPreview(plan, time.Unix(100, 0))
	if !preview.Validation.Valid {
		t.Fatalf("bridged preview invalid: %+v", preview.Validation.Errors)
	}
	assertFixture(t, "90-shakerproxy-wifi-bridge.yaml", preview.NetplanYAML)
	assertFixture(t, "hostapd-shakerproxy-wifi-bridge.conf", preview.HostapdConf)
	if strings.Contains(preview.NetplanYAML, "wlan0") {
		t.Fatalf("Netplan must leave the bridged access point to hostapd:\n%s", preview.NetplanYAML)
	}
	if !strings.Contains(preview.KeaDHCP4JSON, "\""+LabBridgeName+"\"") || strings.Contains(preview.KeaDHCP4JSON, "enp2s0") {
		t.Fatalf("Kea does not serve the lab bridge:\n%s", preview.KeaDHCP4JSON)
	}
	firewall := preview.FirewallRestoreIPv4
	for _, expected := range []string{
		"-A SHAKERPROXY-FORWARD -i lgbr0 -o lgbr0 -j ACCEPT\n-A SHAKERPROXY-FORWARD -i lgbr0 ! -s 10.77.0.0/24 -j DROP",
		"-A SHAKERPROXY-FORWARD -i lgbr0 -o enp1s0 -s 10.77.0.0/24 -j ACCEPT",
		"-A SHAKERPROXY-FORWARD -i enp1s0 -o lgbr0 -d 10.77.0.0/24 -j DROP",
	} {
		if !strings.Contains(firewall, expected) {
			t.Fatalf("bridged firewall missing %q:\n%s", expected, firewall)
		}
	}
	if strings.Contains(firewall, "enp2s0") || strings.Contains(firewall, "wlan0") {
		t.Fatalf("bridged firewall must match only the bridge:\n%s", firewall)
	}
	if !containsString(preview.ChangedObjects, "bridge "+LabBridgeName) || !impactMentions(preview.Impact, "Wired lab port enp2s0 and Wi-Fi wlan0 would share one lab network through bridge lgbr0") {
		t.Fatalf("bridge impact missing: %+v %+v", preview.ChangedObjects, preview.Impact)
	}

	plan.IPv4.ClientIsolation = true
	plan.WiFi.ClientIsolation = true
	isolated := BuildPreview(plan, time.Unix(100, 0))
	if strings.Contains(isolated.FirewallRestoreIPv4, "-i lgbr0 -o lgbr0 -j ACCEPT") || !strings.Contains(isolated.FirewallRestoreIPv4, "-A SHAKERPROXY-FORWARD -i lgbr0 -o lgbr0 -s 10.77.0.0/24 -d 10.77.0.0/24 -j DROP") {
		t.Fatalf("lab isolation was weakened by the bridge rule:\n%s", isolated.FirewallRestoreIPv4)
	}
	if !strings.Contains(isolated.HostapdConf, "\nap_isolate=1\n") {
		t.Fatalf("Wi-Fi isolation was not rendered:\n%s", isolated.HostapdConf)
	}
}

func TestHostapdSecurityModes(t *testing.T) {
	cases := map[WiFiSecurity][]string{
		WiFiSecurityWPA2PSK:  {"wpa=2", "wpa_key_mgmt=WPA-PSK", "rsn_pairwise=CCMP", "wpa_passphrase=" + testWiFiPassphrase},
		WiFiSecurityWPA3SAE:  {"wpa=2", "wpa_key_mgmt=SAE", "rsn_pairwise=CCMP", "ieee80211w=2", "sae_pwe=2", "wpa_passphrase=" + testWiFiPassphrase},
		WiFiSecurityWPA2WPA3: {"wpa=2", "wpa_key_mgmt=WPA-PSK SAE", "rsn_pairwise=CCMP", "ieee80211w=1", "sae_require_mfp=1", "wpa_passphrase=" + testWiFiPassphrase},
		WiFiSecurityOpen:     {"wpa=0"},
	}
	for security, expected := range cases {
		t.Run(string(security), func(t *testing.T) {
			plan := validWiFiPlan()
			plan.WiFi.Security = security
			if security == WiFiSecurityOpen {
				plan.WiFi.Passphrase = ""
			}
			config, err := RenderHostapdConf(plan)
			if err != nil {
				t.Fatal(err)
			}
			for _, line := range expected {
				if !strings.Contains(config, "\n"+line+"\n") {
					t.Fatalf("%s missing %q:\n%s", security, line, config)
				}
			}
			if security == WiFiSecurityOpen && (strings.Contains(config, "wpa_key_mgmt") || strings.Contains(config, "passphrase")) {
				t.Fatalf("open network rendered credentials:\n%s", config)
			}
			if security != WiFiSecurityWPA3SAE && security != WiFiSecurityWPA2WPA3 && strings.Contains(config, "ieee80211w") {
				t.Fatalf("%s must not require management frame protection:\n%s", security, config)
			}
		})
	}
}

func TestHostapdRenderingCannotBeInjected(t *testing.T) {
	plan := validWiFiPlan()
	// Validation rejects control characters; the renderer must still be safe
	// if it were ever handed raw input, because ssid2= is hex encoded.
	plan.WiFi.SSID = "Lab\nwpa=0\nignore_broadcast_ssid=1"[:26]
	plan.WiFi.Passphrase = "p=ss#word|mac=00:11:22:33:44:55 "
	config, err := RenderHostapdConf(plan)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]int{}
	for _, line := range strings.Split(strings.TrimSuffix(config, "\n"), "\n") {
		key, _, found := strings.Cut(line, "=")
		if strings.HasPrefix(line, "#") {
			continue
		}
		if !found || strings.ContainsAny(key, " \t") {
			t.Fatalf("rendered a line that is not key=value: %q", line)
		}
		keys[key]++
	}
	for key, count := range keys {
		if count != 1 {
			t.Fatalf("directive %s rendered %d times:\n%s", key, count, config)
		}
	}
	if !strings.Contains(config, "\nssid2=4c61620a7770613d300a69676e6f72655f62726f616463617374\n") || strings.Contains(config, "\nssid=") {
		t.Fatalf("SSID was not hex encoded:\n%s", config)
	}
	if !strings.Contains(config, "\nwpa_passphrase=p=ss#word|mac=00:11:22:33:44:55 \n") || strings.Contains(config, "sae_password") {
		t.Fatalf("password was not rendered verbatim on its own line:\n%s", config)
	}
	if !strings.Contains(config, "\nignore_broadcast_ssid=0\n") || !strings.Contains(config, "\nwpa=2\n") {
		t.Fatalf("injected directives took effect:\n%s", config)
	}

	plan.WiFi.Passphrase = "password1\nwpa=0"
	if _, err := RenderHostapdConf(plan); err == nil {
		t.Fatal("a password with a line break was rendered")
	}
	plan = validWiFiPlan()
	plan.Interfaces[1].CurrentName = "wlan0\nbridge=eth0"
	if _, err := RenderHostapdConf(plan); err == nil {
		t.Fatal("an unsafe interface name was rendered")
	}
}

func TestPreviewNeverContainsWiFiPassword(t *testing.T) {
	for _, security := range []WiFiSecurity{WiFiSecurityWPA2PSK, WiFiSecurityWPA3SAE, WiFiSecurityWPA2WPA3} {
		plan := validBridgedWiFiPlan()
		plan.WiFi.Security = security
		preview := BuildPreview(plan, time.Unix(100, 0))
		encoded, err := json.Marshal(preview)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(encoded), testWiFiPassphrase) || !strings.Contains(preview.HostapdConf, "\nwpa_passphrase=<redacted>\n") {
			t.Fatalf("%s preview leaked or lost the redacted password:\n%s", security, preview.HostapdConf)
		}
		full, err := RenderHostapdConf(plan)
		if err != nil || RedactHostapdConf(full) != preview.HostapdConf {
			t.Fatalf("preview is not the redacted form of the applied configuration: %v", err)
		}
	}
	if got := RedactHostapdConf("a=1\nsae_password=secret|id=x\nwpa_passphrase=other"); got != "a=1\nsae_password=<redacted>\nwpa_passphrase=<redacted>" {
		t.Fatalf("redaction is incomplete: %q", got)
	}
}

func TestHostapdMarksUTF8SSID(t *testing.T) {
	plan := validWiFiPlan()
	plan.WiFi.SSID = "Café lab"
	config, err := RenderHostapdConf(plan)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(config, "\nssid2=436166c3a9206c6162\nutf8_ssid=1\n") {
		t.Fatalf("UTF-8 SSID was not encoded and flagged:\n%s", config)
	}
	if result := Validate(plan); !result.Valid {
		t.Fatalf("UTF-8 SSID rejected: %+v", result.Errors)
	}
}

func TestActiveSSHOnAccessPointInvalidatesPlan(t *testing.T) {
	plan := validWiFiPlan()
	result := ValidateWithObservedSSH(plan, []ObservedInterface{
		{CurrentName: "enp1s0", StableID: "pci-0000:01:00.0"},
		{CurrentName: "wlan0", StableID: plan.Interfaces[1].StableID},
	}, []ActiveSSHSession{{SourceAddress: "192.0.2.100", SourcePort: 49152, DestinationAddress: "192.0.2.10", DestinationPort: 22, DestinationInterface: "wlan0"}})
	if result.Valid || !hasIssue(result.Errors, "ACTIVE_SSH_ON_LAB_INTERFACE") {
		t.Fatalf("SSH over the future access point was accepted: %+v", result)
	}
}

func TestBridgeGatewayAddressIsNotAHostConflict(t *testing.T) {
	plan := validBridgedWiFiPlan()
	result := ValidateWithObserved(plan, []ObservedInterface{
		{CurrentName: "enp1s0", StableID: "pci-0000:01:00.0"},
		{CurrentName: "enp2s0", StableID: "pci-0000:02:00.0"},
		{CurrentName: "wlan0", StableID: plan.Interfaces[2].StableID},
		{CurrentName: LabBridgeName, StableID: "path:virtual:lgbr0|mac:02:00:00:00:00:09", Addresses: []string{"10.77.0.1/24"}},
	})
	if !result.Valid {
		t.Fatalf("existing ShakerProxy bridge address was treated as a conflict: %+v", result.Errors)
	}
	result = ValidateWithObserved(plan, []ObservedInterface{
		{CurrentName: "enp1s0", StableID: "pci-0000:01:00.0", Addresses: []string{"10.77.0.9/24"}},
		{CurrentName: "enp2s0", StableID: "pci-0000:02:00.0"},
		{CurrentName: "wlan0", StableID: plan.Interfaces[2].StableID},
	})
	if result.Valid || !hasIssue(result.Errors, "LAB_CIDR_HOST_CONFLICT") {
		t.Fatalf("lab prefix conflict was accepted for a bridged plan: %+v", result.Errors)
	}
}

func TestValidateWiFiHost(t *testing.T) {
	yes, no := true, false
	ready := WiFiHostEvidence{HostapdInstalled: true, Interfaces: map[string]WirelessInterfaceEvidence{
		"wlan0":  {Wireless: true, APSupported: &yes, Bands: []WiFiBand{WiFiBand24GHz, WiFiBand5GHz}},
		"enp1s0": {APSupported: &no},
	}}
	base := validBridgedWiFiPlan()
	if result := ValidateWiFiHost(Validate(base), base, ready); !result.Valid || len(result.PlanHash) != 64 {
		t.Fatalf("ready host rejected: %+v", result.Errors)
	}
	cases := []struct {
		name    string
		edit    func(*WiFiHostEvidence)
		code    string
		warning bool
	}{
		{name: "hostapd missing", edit: func(h *WiFiHostEvidence) { h.HostapdInstalled = false }, code: "WIFI_HOSTAPD_MISSING"},
		{name: "wired adapter", edit: func(h *WiFiHostEvidence) { h.Interfaces["wlan0"] = WirelessInterfaceEvidence{APSupported: &no} }, code: "WIFI_INTERFACE_NOT_WIRELESS"},
		{name: "no AP mode", edit: func(h *WiFiHostEvidence) {
			h.Interfaces["wlan0"] = WirelessInterfaceEvidence{Wireless: true, APSupported: &no}
		}, code: "WIFI_AP_MODE_UNSUPPORTED"},
		{name: "2.4 GHz only adapter", edit: func(h *WiFiHostEvidence) {
			h.Interfaces["wlan0"] = WirelessInterfaceEvidence{Wireless: true, APSupported: &yes, Bands: []WiFiBand{WiFiBand24GHz}}
		}, code: "WIFI_BAND_UNSUPPORTED"},
		{name: "unknown AP support", edit: func(h *WiFiHostEvidence) {
			h.Interfaces["wlan0"] = WirelessInterfaceEvidence{Wireless: true}
		}, code: "WIFI_AP_SUPPORT_UNKNOWN", warning: true},
		{name: "network manager", edit: func(h *WiFiHostEvidence) { h.NetworkManagerActive = true }, code: "WIFI_NETWORK_MANAGER_ACTIVE", warning: true},
		{name: "adapter is the uplink", edit: func(h *WiFiHostEvidence) {
			h.Interfaces["wlan0"] = WirelessInterfaceEvidence{Wireless: true, APSupported: &yes, DefaultRoute: true}
		}, code: "WIFI_INTERFACE_IN_USE"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			host := WiFiHostEvidence{HostapdInstalled: ready.HostapdInstalled, Interfaces: map[string]WirelessInterfaceEvidence{}}
			for name, evidence := range ready.Interfaces {
				host.Interfaces[name] = evidence
			}
			test.edit(&host)
			result := ValidateWiFiHost(Validate(base), base, host)
			if test.warning {
				if !result.Valid || !hasIssue(result.Warnings, test.code) {
					t.Fatalf("expected warning %s: %+v %+v", test.code, result.Errors, result.Warnings)
				}
				return
			}
			if result.Valid || result.PlanHash != "" || !hasIssue(result.Errors, test.code) {
				t.Fatalf("expected error %s: %+v", test.code, result)
			}
		})
	}
	withoutWiFi := validTwoNICPlan()
	if result := ValidateWiFiHost(Validate(withoutWiFi), withoutWiFi, WiFiHostEvidence{}); !result.Valid {
		t.Fatalf("host Wi-Fi evidence affected a wired plan: %+v", result.Errors)
	}
}

func assertFixture(t *testing.T, name, actual string) {
	t.Helper()
	path := "../../tests/netlab/fixtures/" + name
	if os.Getenv("SHAKERPROXY_UPDATE_FIXTURES") == "1" {
		if err := os.WriteFile(path, []byte(actual), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if actual != string(want) {
		t.Fatalf("%s drifted from the renderer:\n%s", name, actual)
	}
}

func impactMentions(impact []string, fragment string) bool {
	for _, line := range impact {
		if strings.Contains(line, fragment) {
			return true
		}
	}
	return false
}
