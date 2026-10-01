package networkplan

import "testing"

func TestNetworkManagerHostRefusesInterfacesItManages(t *testing.T) {
	plan := Plan{Interfaces: []Interface{{CurrentName: "ens18", Role: RoleWANLab}, {CurrentName: "wlan0", Role: RoleWiFiAP}}}
	valid := ValidationResult{Valid: true, PlanHash: "abc"}

	if got := ValidateNetworkManagerHost(valid, plan, NetworkManagerEvidence{}); !got.Valid || len(got.Errors) != 0 {
		t.Fatalf("a host without NetworkManager must not be refused: %+v", got)
	}
	networkd := NetworkManagerEvidence{Active: true, NetworkdConfigured: map[string]bool{"ens18": true}}
	if got := ValidateNetworkManagerHost(valid, plan, networkd); !got.Valid || len(got.Errors) != 0 {
		t.Fatalf("an interface systemd-networkd manages must be accepted: %+v", got)
	}
	got := ValidateNetworkManagerHost(valid, plan, NetworkManagerEvidence{Active: true})
	if got.Valid || got.PlanHash != "" || len(got.Errors) != 1 || got.Errors[0].Code != "NETWORK_MANAGER_OWNS_INTERFACE" || got.Errors[0].Path != "interfaces[0]" {
		t.Fatalf("a NetworkManager-managed WAN must be refused (and Wi-Fi left to its own check): %+v", got)
	}
}
