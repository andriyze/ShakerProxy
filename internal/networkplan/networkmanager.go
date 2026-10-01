package networkplan

import "fmt"

// NetworkManagerEvidence describes who manages the host's network interfaces.
type NetworkManagerEvidence struct {
	// Active reports whether NetworkManager is running (Ubuntu Desktop).
	Active bool
	// NetworkdConfigured lists the interfaces systemd-networkd manages.
	NetworkdConfigured map[string]bool
}

// ValidateNetworkManagerHost refuses a plan whose interfaces NetworkManager
// manages. Applying any plan runs "netplan apply", which restarts
// NetworkManager; its interfaces drop long enough for the health checks to
// fail, so the change would always roll back. The Wi-Fi access point keeps
// its own, more specific warning in ValidateWiFiHost.
func ValidateNetworkManagerHost(result ValidationResult, plan Plan, host NetworkManagerEvidence) ValidationResult {
	if !host.Active {
		return result
	}
	for index, iface := range plan.Interfaces {
		if iface.Role == RoleWiFiAP || iface.Role == RoleUnused || host.NetworkdConfigured[iface.CurrentName] {
			continue
		}
		result.Errors = append(result.Errors, Issue{
			Code:    "NETWORK_MANAGER_OWNS_INTERFACE",
			Path:    fmt.Sprintf("interfaces[%d]", index),
			Message: fmt.Sprintf("NetworkManager manages %[1]s (this looks like Ubuntu Desktop). Applying the plan would restart NetworkManager and drop %[1]s, so the change would roll back. Use Ubuntu Server, or hand %[1]s to systemd-networkd first: see \"NetworkManager hosts\" in docs/networking.md.", iface.CurrentName),
		})
	}
	if len(result.Errors) != 0 {
		sortIssues(result.Errors)
		result.Valid = false
		result.PlanHash = ""
	}
	return result
}
