package networkplan

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

var interfaceNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)
var dnsNamePattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`)

const (
	defaultDHCPLeaseSeconds = 3600
	minimumDHCPLeaseSeconds = 60
	maximumDHCPLeaseSeconds = 604800
)

func Validate(plan Plan) ValidationResult {
	result := ValidationResult{Errors: []Issue{}, Warnings: []Issue{}}
	addError := func(code, path, message string) {
		result.Errors = append(result.Errors, Issue{Code: code, Path: path, Message: message})
	}
	addWarning := func(code, path, message string) {
		result.Warnings = append(result.Warnings, Issue{Code: code, Path: path, Message: message})
	}

	if plan.Schema != SchemaVersion {
		addError("SCHEMA_UNSUPPORTED", "schema", fmt.Sprintf("schema must be %d", SchemaVersion))
	}
	if strings.TrimSpace(plan.Name) == "" || len(plan.Name) > 120 {
		addError("NAME_INVALID", "name", "name must contain 1 to 120 characters")
	}
	if !validTopology(plan.Topology) {
		addError("TOPOLOGY_INVALID", "topology", "unknown topology")
	}
	if len(plan.Interfaces) == 0 || len(plan.Interfaces) > 64 {
		addError("INTERFACES_INVALID", "interfaces", "between 1 and 64 interfaces are required")
	}

	stableIDs, names, vlanIDs := map[string]bool{}, map[string]bool{}, map[int]bool{}
	roles := map[InterfaceRole]int{}
	for i, iface := range plan.Interfaces {
		path := fmt.Sprintf("interfaces[%d]", i)
		if strings.TrimSpace(iface.StableID) == "" || len(iface.StableID) > 256 {
			addError("STABLE_ID_INVALID", path+".stable_id", "stable interface identity is required")
		}
		stableKey := iface.StableID
		if plan.Topology == TopologyVLANTrunk && iface.VLANID != nil {
			stableKey = fmt.Sprintf("%s/%d", iface.StableID, *iface.VLANID)
		}
		if stableIDs[stableKey] {
			addError("STABLE_ID_DUPLICATE", path+".stable_id", "stable interface identity and VLAN combination must be unique")
		}
		stableIDs[stableKey] = true
		if !interfaceNamePattern.MatchString(iface.CurrentName) {
			addError("INTERFACE_NAME_INVALID", path+".current_name", "interface name contains unsupported characters")
		}
		if names[iface.CurrentName] {
			addError("INTERFACE_NAME_DUPLICATE", path+".current_name", "interface name must be unique")
		}
		names[iface.CurrentName] = true
		if !validRole(iface.Role) {
			addError("ROLE_INVALID", path+".role", "unknown interface role")
		}
		roles[iface.Role]++
		if iface.VLANID != nil && (*iface.VLANID < 1 || *iface.VLANID > 4094) {
			addError("VLAN_ID_INVALID", path+".vlan_id", "VLAN ID must be between 1 and 4094")
		}
		if iface.MTU != 0 && (iface.MTU < 576 || iface.MTU > 9216) {
			addError("MTU_INVALID", path+".mtu", "MTU must be zero to preserve the current value or between 576 and 9216")
		}
		if plan.Topology != TopologyVLANTrunk && iface.VLANID != nil {
			addError("VLAN_TOPOLOGY_MISMATCH", path+".vlan_id", "VLAN IDs require the VLAN trunk topology")
		}
		if plan.Topology == TopologyVLANTrunk && (iface.Role == RoleWAN || iface.Role == RoleLab) {
			if iface.VLANID == nil {
				addError("VLAN_ID_REQUIRED", path+".vlan_id", "WAN and LAB roles require VLAN IDs in a VLAN trunk topology")
			} else if vlanIDs[*iface.VLANID] {
				addError("VLAN_ID_DUPLICATE", path+".vlan_id", "WAN and LAB VLAN IDs must differ")
			} else {
				vlanIDs[*iface.VLANID] = true
			}
		}
	}

	routed := plan.Topology != TopologyPassiveSensor
	if plan.Topology == TopologySingleArm {
		if roles[RoleWANLab] != 1 || roles[RoleWAN] != 0 || roles[RoleLab] != 0 {
			addError("SINGLE_ARM_ROLES_INVALID", "interfaces", "single-arm topology requires exactly one WAN_LAB interface and no separate WAN or LAB role")
		}
		if len(plan.Interfaces) != 1 {
			addError("SINGLE_ARM_INTERFACE_COUNT_INVALID", "interfaces", "single-arm topology accepts exactly one interface")
		}
		if arm, ok := InterfaceForRole(plan, RoleWANLab); ok && len(arm.CurrentName) > 15 {
			addError("SINGLE_ARM_INTERFACE_NAME_INVALID", "interfaces", "single-arm sysctl ownership requires a Linux interface name no longer than 15 characters")
		}
		if !plan.IPv4.Enabled {
			addError("IPV4_REQUIRED_FOR_ROUTED_V1", "ipv4.enabled", "this build requires IPv4 for routed topology; IPv6-only routing is not implemented")
		}
		if !plan.IPv4.NAT44 {
			addError("SINGLE_ARM_NAT44_REQUIRED", "ipv4.nat44", "single-arm routing requires NAT44 so return traffic cannot bypass ShakerProxy")
		}
		if plan.IPv4.ClientIsolation {
			addError("SINGLE_ARM_CLIENT_ISOLATION_UNAVAILABLE", "ipv4.client_isolation", "same-subnet client isolation cannot be enforced by a single-arm gateway")
		}
		if plan.IPv4.DHCPStart != "" || plan.IPv4.DHCPEnd != "" || plan.IPv4.DHCPLeaseSeconds != 0 || len(plan.IPv4.DNSAddresses) != 0 || plan.IPv4.SearchDomain != "" || len(plan.IPv4.Reservations) != 0 {
			addError("SINGLE_ARM_DHCP_FORBIDDEN", "ipv4", "single-arm mode does not run DHCP; configure each client gateway and DNS manually")
		}
		if arm, ok := InterfaceForRole(plan, RoleWANLab); ok && wanConfigurationChangesHost(plan.WAN, arm) {
			addError("SINGLE_ARM_INTERFACE_MUTATION", "wan", "single-arm mode must keep the interface's existing addressing, routes, DNS ownership, VLAN, and MTU")
		}
		addWarning("SINGLE_ARM_MANUAL_CLIENT_SETUP", "topology", "each test client must use the ShakerProxy address as its default gateway and DNS server")
		addWarning("SINGLE_ARM_IPV6_BYPASS", "ipv6.strategy", "clients can bypass ShakerProxy over IPv6 unless IPv6 is disabled on the client or isolated by the upstream network")
	} else if routed {
		if roles[RoleWAN] != 1 {
			addError("WAN_COUNT_INVALID", "interfaces", "routed topology requires exactly one WAN interface")
		}
		if roles[RoleLab] != 1 && !(WiFiEnabled(plan) && roles[RoleLab] == 0) {
			addError("LAB_COUNT_INVALID", "interfaces", "routed topology requires exactly one LAB interface")
		}
		if !plan.IPv4.Enabled {
			addError("IPV4_REQUIRED_FOR_ROUTED_V1", "ipv4.enabled", "this build requires IPv4 for routed topology; IPv6-only routing is not implemented")
		}
	} else {
		if roles[RoleWAN] != 0 || roles[RoleLab] != 0 || roles[RoleWANLab] != 0 || roles[RoleMirror] != 1 {
			addError("PASSIVE_ROLES_INVALID", "interfaces", "passive topology requires exactly one MIRROR and no WAN or LAB role")
		}
		if plan.IPv4.Enabled || plan.IPv4.NAT44 {
			addError("PASSIVE_IPV4_MUTATION", "ipv4", "passive topology cannot enable routing or NAT")
		}
	}
	if !plan.Management.PreserveActiveSSH {
		addError("SSH_PRESERVATION_REQUIRED", "management.preserve_active_ssh", "active SSH preservation cannot be disabled")
	}
	validateWAN(plan, routed, addError, addWarning)
	validateWiFi(plan, roles, addError, addWarning)
	for i, cidr := range plan.Management.AllowedCIDRs {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			addError("MANAGEMENT_CIDR_INVALID", fmt.Sprintf("management.allowed_cidrs[%d]", i), "management CIDR is invalid")
		}
	}

	if plan.IPv4.Enabled {
		validateIPv4(plan.IPv4, UsesManagedDHCP4(plan), addError)
	} else if plan.IPv4.LabCIDR != "" || plan.IPv4.GatewayAddress != "" || plan.IPv4.DHCPStart != "" || plan.IPv4.DHCPEnd != "" || plan.IPv4.DHCPLeaseSeconds != 0 || len(plan.IPv4.DNSAddresses) != 0 || plan.IPv4.SearchDomain != "" || len(plan.IPv4.Reservations) != 0 || plan.IPv4.NAT44 {
		addError("IPV4_DISABLED_FIELDS", "ipv4", "disabled IPv4 configuration cannot contain addresses, DHCP range, or NAT")
	}
	if !validIPv6Strategy(plan.IPv6.Strategy) {
		addError("IPV6_STRATEGY_INVALID", "ipv6.strategy", "an explicit IPv6 strategy is required")
	}
	validateIPv6(plan, addError, addWarning)
	if plan.Topology == TopologyAdvancedCustom {
		addWarning("ADVANCED_TOPOLOGY", "topology", "advanced custom topology requires additional lockout review")
	}
	if routed && roles[RoleManagement] == 0 && plan.Topology != TopologySingleArm {
		addWarning("NO_DEDICATED_MANAGEMENT", "interfaces", "a separate management interface or VLAN is strongly recommended")
	}

	sortIssues(result.Errors)
	sortIssues(result.Warnings)
	result.Valid = len(result.Errors) == 0
	if result.Valid {
		result.PlanHash = CanonicalPlanHash(plan)
	}
	return result
}

type ObservedInterface struct {
	CurrentName      string
	StableID         string
	Addresses        []string
	DefaultIPv4      bool
	DefaultIPv6      bool
	CloudInitManaged bool
}

func ValidateWithObserved(plan Plan, observed []ObservedInterface) ValidationResult {
	return ValidateWithObservedSSH(plan, observed, nil)
}

func ValidateWithObservedSSH(plan Plan, observed []ObservedInterface, activeSSH []ActiveSSHSession) ValidationResult {
	result := Validate(plan)
	byName := make(map[string]ObservedInterface, len(observed))
	for _, iface := range observed {
		byName[iface.CurrentName] = iface
	}
	for i, selected := range plan.Interfaces {
		if selected.Role == RoleUnused {
			continue
		}
		path := fmt.Sprintf("interfaces[%d]", i)
		current, ok := byName[selected.CurrentName]
		if !ok && plan.Topology == TopologyVLANTrunk && selected.VLANID != nil {
			for _, candidate := range observed {
				if candidate.StableID == selected.StableID {
					current, ok = candidate, true
					expectedName := fmt.Sprintf("%s.%d", candidate.CurrentName, *selected.VLANID)
					if selected.CurrentName != expectedName {
						result.Errors = append(result.Errors, Issue{Code: "VLAN_INTERFACE_NAME_MISMATCH", Path: path + ".current_name", Message: "managed VLAN name must be derived from the observed physical parent and VLAN ID"})
					}
					break
				}
			}
		}
		if !ok {
			result.Errors = append(result.Errors, Issue{Code: "INTERFACE_NOT_FOUND", Path: path + ".current_name", Message: "selected interface is not present on the host"})
			continue
		}
		if current.StableID != "" && selected.StableID != current.StableID {
			result.Errors = append(result.Errors, Issue{Code: "INTERFACE_IDENTITY_MISMATCH", Path: path + ".stable_id", Message: "selected stable identity does not match the current host interface"})
		}
	}
	wan, hasWAN := WANInterface(plan)
	if hasWAN {
		var observedWAN *ObservedInterface
		for index := range observed {
			if observed[index].CurrentName == wan.CurrentName || observed[index].StableID == wan.StableID {
				observedWAN = &observed[index]
				break
			}
		}
		if observedWAN != nil && wanConfigurationChangesHost(plan.WAN, wan) {
			working := observedWAN.DefaultIPv4 || observedWAN.DefaultIPv6
			if working && !plan.WAN.AllowWorkingWANChange {
				result.Errors = append(result.Errors, Issue{Code: "WORKING_WAN_CHANGE_NOT_ACKNOWLEDGED", Path: "wan.allow_working_wan_change", Message: "the selected WAN has a working default route; keep its configuration or explicitly acknowledge the reviewed change"})
			}
			if observedWAN.CloudInitManaged && !plan.WAN.AllowCloudInitOverride {
				result.Errors = append(result.Errors, Issue{Code: "CLOUD_INIT_WAN_OVERRIDE_NOT_ACKNOWLEDGED", Path: "wan.allow_cloud_init_override", Message: "cloud-init appears to own host networking; an explicit override acknowledgement is required"})
			}
			if observedWAN.CurrentName != wan.CurrentName {
				for index, session := range activeSSH {
					if session.DestinationInterface == observedWAN.CurrentName {
						result.Errors = append(result.Errors, Issue{Code: "ACTIVE_SSH_WAN_MUTATION", Path: fmt.Sprintf("active_ssh[%d].destination_interface", index), Message: "the active SSH path uses the WAN parent; its addressing or MTU cannot be changed by this plan"})
					}
				}
			}
		}
	}
	if plan.IPv4.Enabled {
		labPrefix, prefixErr := netip.ParsePrefix(plan.IPv4.LabCIDR)
		gateway, gatewayErr := netip.ParseAddr(plan.IPv4.GatewayAddress)
		lab, _ := LabInterface(plan)
		if prefixErr == nil && gatewayErr == nil {
			labPrefix = labPrefix.Masked()
			for _, iface := range observed {
				for _, rawAddress := range iface.Addresses {
					currentPrefix, err := netip.ParsePrefix(rawAddress)
					if err != nil || !currentPrefix.Addr().Is4() || !prefixesOverlap(labPrefix, currentPrefix.Masked()) {
						continue
					}
					if iface.CurrentName == lab.CurrentName && currentPrefix.Addr() == gateway {
						continue
					}
					result.Errors = append(result.Errors, Issue{Code: "LAB_CIDR_HOST_CONFLICT", Path: "ipv4.lab_cidr", Message: fmt.Sprintf("lab CIDR overlaps existing address %s on %s", rawAddress, iface.CurrentName)})
				}
			}
			if plan.Topology == TopologySingleArm {
				var armObserved *ObservedInterface
				for index := range observed {
					if observed[index].CurrentName == lab.CurrentName && (observed[index].StableID == "" || observed[index].StableID == lab.StableID) {
						armObserved = &observed[index]
						break
					}
				}
				if armObserved == nil || !armObserved.DefaultIPv4 {
					result.Errors = append(result.Errors, Issue{Code: "SINGLE_ARM_DEFAULT_ROUTE_REQUIRED", Path: "interfaces", Message: "the single-arm interface must carry the host IPv4 default route"})
				}
				hasGateway := false
				if armObserved != nil {
					for _, rawAddress := range armObserved.Addresses {
						currentPrefix, parseErr := netip.ParsePrefix(rawAddress)
						if parseErr == nil && currentPrefix.Addr() == gateway && currentPrefix.Bits() == labPrefix.Bits() {
							hasGateway = true
							break
						}
					}
				}
				if !hasGateway {
					result.Errors = append(result.Errors, Issue{Code: "SINGLE_ARM_GATEWAY_NOT_CONFIGURED", Path: "ipv4.gateway_address", Message: "gateway address and prefix must exactly match an existing address on the single-arm interface"})
				}
			}
		}
	}
	validateIPv6Observed(plan, observed, &result)
	validateActiveSSH(plan, activeSSH, &result)
	sortIssues(result.Errors)
	if len(result.Errors) != 0 {
		result.Valid = false
		result.PlanHash = ""
	}
	return result
}

func validateActiveSSH(plan Plan, sessions []ActiveSSHSession, result *ValidationResult) {
	selectedRoles := make(map[string]InterfaceRole, len(plan.Interfaces))
	for _, iface := range plan.Interfaces {
		selectedRoles[iface.CurrentName] = iface.Role
	}
	allowed := make([]netip.Prefix, 0, len(plan.Management.AllowedCIDRs))
	for _, raw := range plan.Management.AllowedCIDRs {
		if prefix, err := netip.ParsePrefix(raw); err == nil {
			allowed = append(allowed, prefix)
		}
	}
	for index, session := range sessions {
		path := fmt.Sprintf("active_ssh[%d]", index)
		if session.DestinationInterface == "" {
			result.Errors = append(result.Errors, Issue{Code: "ACTIVE_SSH_PATH_UNKNOWN", Path: path + ".destination_address", Message: "active SSH destination could not be mapped to a host interface"})
		} else if selectedRoles[session.DestinationInterface] == RoleLab || selectedRoles[session.DestinationInterface] == RoleWiFiAP {
			result.Errors = append(result.Errors, Issue{Code: "ACTIVE_SSH_ON_LAB_INTERFACE", Path: path + ".destination_interface", Message: "an interface carrying active SSH cannot become the lab interface"})
		} else if selectedRoles[session.DestinationInterface] == RoleWAN || selectedRoles[session.DestinationInterface] == RoleWANLab {
			wan, _ := WANInterface(plan)
			if wanConfigurationChangesHost(plan.WAN, wan) {
				result.Errors = append(result.Errors, Issue{Code: "ACTIVE_SSH_WAN_MUTATION", Path: path + ".destination_interface", Message: "the active SSH path uses the WAN; its addressing or MTU cannot be changed by this plan"})
			}
		}
		if len(allowed) == 0 {
			continue
		}
		source, err := netip.ParseAddr(session.SourceAddress)
		permitted := err == nil
		if permitted {
			permitted = false
			for _, prefix := range allowed {
				if prefix.Contains(source) {
					permitted = true
					break
				}
			}
		}
		if !permitted {
			result.Errors = append(result.Errors, Issue{Code: "ACTIVE_SSH_SOURCE_NOT_ALLOWED", Path: path + ".source_address", Message: "active SSH source is outside the configured management CIDRs"})
		}
	}
}

func validateWAN(plan Plan, routed bool, addError, addWarning func(string, string, string)) {
	ipv4Mode := effectiveWANIPv4Mode(plan.WAN.IPv4Mode)
	ipv6Mode := effectiveWANIPv6Mode(plan.WAN.IPv6Mode)
	dnsMode := effectiveWANDNSMode(plan.WAN.DNSMode)
	if !routed {
		if wanConfigurationChangesHost(plan.WAN, Interface{}) || plan.WAN.UpstreamNAT || plan.WAN.ClampMSS {
			addError("PASSIVE_WAN_MUTATION", "wan", "passive topology cannot configure an upstream WAN")
		}
		return
	}
	if ipv4Mode != WANIPv4KeepExisting && ipv4Mode != WANIPv4DHCP && ipv4Mode != WANIPv4Static {
		addError("WAN_IPV4_MODE_INVALID", "wan.ipv4_mode", "WAN IPv4 mode must keep existing, use DHCP, or use a static address")
	}
	if ipv4Mode == WANIPv4Static {
		prefix, prefixErr := netip.ParsePrefix(plan.WAN.IPv4Address)
		gateway, gatewayErr := netip.ParseAddr(plan.WAN.IPv4Gateway)
		if prefixErr != nil || !prefix.Addr().Is4() || prefix.Bits() < 1 || prefix.Bits() > 32 {
			addError("WAN_IPV4_ADDRESS_INVALID", "wan.ipv4_address", "static WAN IPv4 address must be an IPv4 CIDR")
		} else if !isUsableIPv4(prefix.Masked(), prefix.Addr()) {
			addError("WAN_IPV4_ADDRESS_RESERVED", "wan.ipv4_address", "static WAN IPv4 address cannot be the network or broadcast address")
		} else if gatewayErr != nil || !gateway.Is4() || !prefix.Masked().Contains(gateway) || !isUsableIPv4(prefix.Masked(), gateway) || gateway.IsUnspecified() || gateway.IsMulticast() {
			addError("WAN_IPV4_GATEWAY_INVALID", "wan.ipv4_gateway", "static WAN IPv4 gateway must be a usable address in the WAN prefix")
		}
	} else if plan.WAN.IPv4Address != "" || plan.WAN.IPv4Gateway != "" {
		addError("WAN_IPV4_STATIC_FIELDS_UNUSED", "wan", "WAN IPv4 address and gateway require static mode")
	}
	if plan.Topology == TopologyVLANTrunk && ipv4Mode == WANIPv4KeepExisting && (ipv6Mode == WANIPv6KeepExisting || ipv6Mode == WANIPv6None) {
		addError("VLAN_WAN_CONFIGURATION_REQUIRED", "wan", "a newly managed WAN VLAN requires explicit DHCP, static, SLAAC, or DHCPv6 configuration; use existing-routed-VLAN for a preconfigured interface")
	}
	if plan.Topology == TopologyVLANTrunk && plan.IPv4.NAT44 && ipv4Mode == WANIPv4KeepExisting {
		addError("VLAN_WAN_IPV4_REQUIRED_FOR_NAT44", "wan.ipv4_mode", "a newly managed WAN VLAN needs DHCP or static IPv4 before NAT44 can be enabled")
	}
	switch ipv6Mode {
	case WANIPv6KeepExisting, WANIPv6SLAAC, WANIPv6DHCP, WANIPv6PrefixDelegation, WANIPv6Static, WANIPv6None:
	default:
		addError("WAN_IPV6_MODE_INVALID", "wan.ipv6_mode", "unknown WAN IPv6 mode")
	}
	if ipv6Mode == WANIPv6Static {
		prefix, prefixErr := netip.ParsePrefix(plan.WAN.IPv6Address)
		gateway, gatewayErr := netip.ParseAddr(plan.WAN.IPv6Gateway)
		if prefixErr != nil || !prefix.Addr().Is6() || prefix.Bits() < 1 || prefix.Bits() > 128 {
			addError("WAN_IPV6_ADDRESS_INVALID", "wan.ipv6_address", "static WAN IPv6 address must be an IPv6 CIDR")
		} else if gatewayErr != nil || !gateway.Is6() || gateway.IsUnspecified() || gateway.IsMulticast() {
			addError("WAN_IPV6_GATEWAY_INVALID", "wan.ipv6_gateway", "static WAN IPv6 gateway must be a usable IPv6 address")
		}
	} else if plan.WAN.IPv6Address != "" || plan.WAN.IPv6Gateway != "" {
		addError("WAN_IPV6_STATIC_FIELDS_UNUSED", "wan", "WAN IPv6 address and gateway require static mode")
	}
	if ipv6Mode == WANIPv6PrefixDelegation {
		if plan.WAN.RequestedPrefixLength < 48 || plan.WAN.RequestedPrefixLength > 64 {
			addError("WAN_PD_PREFIX_LENGTH_INVALID", "wan.requested_prefix_length", "requested delegated prefix length must be between 48 and 64")
		}
	} else if plan.WAN.RequestedPrefixLength != 0 {
		addError("WAN_PD_PREFIX_LENGTH_UNUSED", "wan.requested_prefix_length", "a requested prefix length requires prefix-delegation mode")
	}
	if dnsMode != WANDNSUseDHCP && dnsMode != WANDNSIgnoreDHCP && dnsMode != WANDNSBootstrapOnly {
		addError("WAN_DNS_MODE_INVALID", "wan.dns_mode", "unknown WAN DHCP DNS handling")
	}
	if dnsMode != WANDNSUseDHCP && ipv4Mode != WANIPv4DHCP && ipv6Mode != WANIPv6DHCP {
		addError("WAN_DNS_MODE_REQUIRES_DHCP", "wan.dns_mode", "non-default DHCP DNS handling requires a managed DHCP WAN mode")
	}
	if dnsMode == WANDNSBootstrapOnly {
		addError("WAN_BOOTSTRAP_DNS_UNAVAILABLE", "wan.dns_mode", "bootstrap-only upstream DNS requires the future managed resolver")
	}
	if ipv6Mode == WANIPv6PrefixDelegation {
		addError("WAN_PREFIX_DELEGATION_UNAVAILABLE", "wan.ipv6_mode", "upstream prefix delegation is not active in this release")
	}
	if plan.WAN.ClampMSS {
		addError("WAN_MSS_CLAMP_UNAVAILABLE", "wan.clamp_mss", "managed MSS clamping is not active in this release")
	}
	if plan.WAN.UpstreamNAT && plan.IPv4.NAT44 {
		addWarning("DOUBLE_NAT", "wan.upstream_nat", "the lab will use deliberate double NAT")
	}
}

func effectiveWANIPv4Mode(mode WANIPv4Mode) WANIPv4Mode {
	if mode == "" {
		return WANIPv4KeepExisting
	}
	return mode
}

func effectiveWANIPv6Mode(mode WANIPv6Mode) WANIPv6Mode {
	if mode == "" {
		return WANIPv6KeepExisting
	}
	return mode
}

func effectiveWANDNSMode(mode WANDNSMode) WANDNSMode {
	if mode == "" {
		return WANDNSUseDHCP
	}
	return mode
}

func wanConfigurationChangesHost(config WANConfiguration, wan Interface) bool {
	return effectiveWANIPv4Mode(config.IPv4Mode) != WANIPv4KeepExisting ||
		effectiveWANIPv6Mode(config.IPv6Mode) != WANIPv6KeepExisting ||
		effectiveWANDNSMode(config.DNSMode) != WANDNSUseDHCP || wan.MTU != 0 || wan.VLANID != nil
}

func validateIPv4(config IPv4Configuration, managedDHCP4 bool, addError func(string, string, string)) {
	prefix, err := netip.ParsePrefix(config.LabCIDR)
	if err != nil || !prefix.Addr().Is4() {
		addError("LAB_CIDR_INVALID", "ipv4.lab_cidr", "lab CIDR must be a valid IPv4 prefix")
		return
	}
	prefix = prefix.Masked()
	if prefix.Bits() < 8 || prefix.Bits() > 30 {
		addError("LAB_CIDR_SIZE_INVALID", "ipv4.lab_cidr", "lab CIDR prefix length must be between /8 and /30")
	}
	gateway, err := netip.ParseAddr(config.GatewayAddress)
	if err != nil || !gateway.Is4() || !prefix.Contains(gateway) {
		addError("GATEWAY_INVALID", "ipv4.gateway_address", "gateway must be an IPv4 address inside the lab CIDR")
	} else if !isUsableIPv4(prefix, gateway) {
		addError("GATEWAY_RESERVED", "ipv4.gateway_address", "gateway cannot be the network or broadcast address")
	}
	if !managedDHCP4 {
		return
	}
	start, startErr := netip.ParseAddr(config.DHCPStart)
	end, endErr := netip.ParseAddr(config.DHCPEnd)
	if startErr != nil || endErr != nil || !start.Is4() || !end.Is4() || !prefix.Contains(start) || !prefix.Contains(end) {
		addError("DHCP_RANGE_INVALID", "ipv4", "DHCP start and end must be IPv4 addresses inside the lab CIDR")
		return
	}
	if !isUsableIPv4(prefix, start) || !isUsableIPv4(prefix, end) {
		addError("DHCP_RANGE_RESERVED", "ipv4", "DHCP range cannot include the network or broadcast address")
	}
	if start.Compare(end) > 0 {
		addError("DHCP_RANGE_REVERSED", "ipv4.dhcp_start", "DHCP start must not be after DHCP end")
	}
	if gateway.IsValid() && gateway.Compare(start) >= 0 && gateway.Compare(end) <= 0 {
		addError("GATEWAY_IN_DHCP_RANGE", "ipv4.gateway_address", "gateway address cannot be leased by DHCP")
	}
	if config.DHCPLeaseSeconds != 0 && (config.DHCPLeaseSeconds < minimumDHCPLeaseSeconds || config.DHCPLeaseSeconds > maximumDHCPLeaseSeconds) {
		addError("DHCP_LEASE_DURATION_INVALID", "ipv4.dhcp_lease_seconds", "DHCP lease duration must be between 60 and 604800 seconds")
	}
	if len(config.DNSAddresses) > 8 {
		addError("DHCP_DNS_TOO_MANY", "ipv4.dns_addresses", "at most eight IPv4 DNS server addresses may be advertised")
	}
	seenDNS := map[netip.Addr]bool{}
	for i, raw := range config.DNSAddresses {
		address, parseErr := netip.ParseAddr(raw)
		path := fmt.Sprintf("ipv4.dns_addresses[%d]", i)
		if parseErr != nil || !address.Is4() || address.IsUnspecified() || address.IsMulticast() || address.IsLoopback() {
			addError("DHCP_DNS_ADDRESS_INVALID", path, "DHCP DNS option must contain a unicast IPv4 address")
			continue
		}
		if seenDNS[address] {
			addError("DHCP_DNS_ADDRESS_DUPLICATE", path, "DHCP DNS server addresses must be unique")
		}
		seenDNS[address] = true
	}
	if config.SearchDomain != "" && (len(config.SearchDomain) > 253 || !dnsNamePattern.MatchString(config.SearchDomain)) {
		addError("DHCP_SEARCH_DOMAIN_INVALID", "ipv4.search_domain", "search domain must be a valid DNS name of at most 253 characters")
	}
	if len(config.Reservations) > 1024 {
		addError("DHCP_RESERVATIONS_TOO_MANY", "ipv4.reservations", "at most 1024 DHCP reservations are supported")
	}
	seenMAC, seenIP, seenHostname := map[string]bool{}, map[netip.Addr]bool{}, map[string]bool{}
	for i, reservation := range config.Reservations {
		path := fmt.Sprintf("ipv4.reservations[%d]", i)
		hardwareAddress, parseErr := net.ParseMAC(reservation.HardwareAddress)
		if parseErr != nil || len(hardwareAddress) != 6 || !usableReservationMAC(hardwareAddress) {
			addError("DHCP_RESERVATION_MAC_INVALID", path+".hardware_address", "reservation hardware address must be a 48-bit MAC address")
		} else {
			canonical := hardwareAddress.String()
			if seenMAC[canonical] {
				addError("DHCP_RESERVATION_MAC_DUPLICATE", path+".hardware_address", "reservation hardware addresses must be unique")
			}
			seenMAC[canonical] = true
		}
		address, parseErr := netip.ParseAddr(reservation.IPAddress)
		if parseErr != nil || !address.Is4() || !prefix.Contains(address) || !isUsableIPv4(prefix, address) {
			addError("DHCP_RESERVATION_IP_INVALID", path+".ip_address", "reservation address must be a usable IPv4 address inside the lab CIDR")
		} else {
			if address == gateway {
				addError("DHCP_RESERVATION_GATEWAY_CONFLICT", path+".ip_address", "reservation address cannot equal the lab gateway")
			}
			if startErr == nil && endErr == nil && address.Compare(start) >= 0 && address.Compare(end) <= 0 {
				addError("DHCP_RESERVATION_IN_DYNAMIC_POOL", path+".ip_address", "reservation address must be outside the dynamic DHCP pool")
			}
			if seenIP[address] {
				addError("DHCP_RESERVATION_IP_DUPLICATE", path+".ip_address", "reservation addresses must be unique")
			}
			seenIP[address] = true
		}
		if reservation.Hostname != "" {
			hostname := strings.ToLower(reservation.Hostname)
			if len(reservation.Hostname) > 253 || !dnsNamePattern.MatchString(reservation.Hostname) {
				addError("DHCP_RESERVATION_HOSTNAME_INVALID", path+".hostname", "reservation hostname must be a valid DNS name of at most 253 characters")
			} else if seenHostname[hostname] {
				addError("DHCP_RESERVATION_HOSTNAME_DUPLICATE", path+".hostname", "reservation hostnames must be unique")
			}
			seenHostname[hostname] = true
		}
	}
}

func normalizedDHCPLeaseSeconds(value int) int {
	if value == 0 {
		return defaultDHCPLeaseSeconds
	}
	return value
}

func usableReservationMAC(address net.HardwareAddr) bool {
	if len(address) != 6 || address[0]&1 != 0 {
		return false
	}
	for _, octet := range address {
		if octet != 0 {
			return true
		}
	}
	return false
}

func isUsableIPv4(prefix netip.Prefix, address netip.Addr) bool {
	if !address.Is4() || !prefix.Addr().Is4() {
		return false
	}
	network := binary.BigEndian.Uint32(prefix.Masked().Addr().AsSlice())
	value := binary.BigEndian.Uint32(address.AsSlice())
	hostBits := uint(32 - prefix.Bits())
	broadcast := network | uint32((uint64(1)<<hostBits)-1)
	return value != network && value != broadcast
}

func prefixesOverlap(left, right netip.Prefix) bool {
	return left.Contains(right.Addr()) || right.Contains(left.Addr())
}

func validTopology(value Topology) bool {
	switch value {
	case TopologyTwoNIC, TopologySingleArm, TopologyThreeInterface, TopologyVLANTrunk, TopologyExistingRoutedVLAN, TopologyPassiveSensor, TopologyAdvancedCustom:
		return true
	}
	return false
}
func validRole(value InterfaceRole) bool {
	switch value {
	case RoleWAN, RoleLab, RoleWANLab, RoleManagement, RoleMirror, RoleUnused, RoleWiFiAP:
		return true
	}
	return false
}
func validIPv6Strategy(value IPv6Strategy) bool {
	switch value {
	case IPv6NativeRouted, IPv6PrefixDelegation, IPv6ULANAT66Lab, IPv6ObserveOnly, IPv6Disabled:
		return true
	}
	return false
}
func sortIssues(issues []Issue) {
	sort.SliceStable(issues, func(i, j int) bool {
		if issues[i].Path == issues[j].Path {
			return issues[i].Code < issues[j].Code
		}
		return issues[i].Path < issues[j].Path
	})
}

func InterfaceForRole(plan Plan, role InterfaceRole) (Interface, bool) {
	for _, iface := range plan.Interfaces {
		if iface.Role == role {
			return iface, true
		}
	}
	return Interface{}, false
}

func WANInterface(plan Plan) (Interface, bool) {
	if plan.Topology == TopologySingleArm {
		return InterfaceForRole(plan, RoleWANLab)
	}
	return InterfaceForRole(plan, RoleWAN)
}

func LabInterface(plan Plan) (Interface, bool) {
	if lab, ok := wifiLabInterface(plan); ok {
		return lab, true
	}
	if plan.Topology == TopologySingleArm {
		return InterfaceForRole(plan, RoleWANLab)
	}
	return InterfaceForRole(plan, RoleLab)
}

func UsesManagedDHCP4(plan Plan) bool {
	return plan.Topology != TopologySingleArm && plan.Topology != TopologyPassiveSensor
}
