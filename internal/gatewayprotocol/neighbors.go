package gatewayprotocol

import (
	"errors"
	"net"
	"net/netip"
	"regexp"
	"time"
)

const (
	NeighborTableSchema = 1
	// MaxNeighbors bounds one GetNeighbors response (well under
	// MaxResponseBytes at roughly 150 bytes per entry).
	MaxNeighbors = 2048
)

var neighborInterfacePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}$`)
var neighborPlanHashPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

// Neighbor is one IPv6 neighbor-discovery (NDP) entry on the lab interface.
// LastConfirmedAt is when the kernel last confirmed the device was reachable;
// an entry left STALE for a long time keeps an old LastConfirmedAt.
type Neighbor struct {
	Address         string    `json:"address"`
	HardwareAddress string    `json:"hardware_address"`
	State           string    `json:"state"`
	Router          bool      `json:"router,omitempty"`
	LastConfirmedAt time.Time `json:"last_confirmed_at"`
}

// NeighborTable is the GetNeighbors result. Active is false (and Neighbors
// empty) unless a confirmed plan routes lab IPv6.
// NeighborFamilyIPv4 marks an IPv4 (ARP) neighbor table.
const NeighborFamilyIPv4 = "ipv4"

type NeighborTable struct {
	Schema int `json:"schema"`
	// Family is NeighborFamilyIPv4 for GetIPv4Neighbors (ARP) and empty for
	// GetNeighbors (IPv6 NDP), which predates it.
	Family        string     `json:"family,omitempty"`
	Active        bool       `json:"active"`
	Interface     string     `json:"interface,omitempty"`
	VLANID        *int       `json:"vlan_id,omitempty"`
	ScopePlanHash string     `json:"scope_plan_hash,omitempty"`
	LabPrefix     string     `json:"lab_prefix,omitempty"`
	ObservedAt    time.Time  `json:"observed_at"`
	Neighbors     []Neighbor `json:"neighbors"`
	Truncated     bool       `json:"truncated"`
}

// Validate checks a neighbor table received over the privileged socket
// before its evidence reaches the device inventory.
func (t NeighborTable) Validate() error {
	if t.Schema != NeighborTableSchema || t.ObservedAt.IsZero() || len(t.Neighbors) > MaxNeighbors || t.Family != "" && t.Family != NeighborFamilyIPv4 {
		return errors.New("neighbor table identity or bounds are invalid")
	}
	if !t.Active {
		if len(t.Neighbors) != 0 || t.Interface != "" || t.ScopePlanHash != "" {
			return errors.New("inactive neighbor table cannot carry evidence")
		}
		return nil
	}
	prefix, err := netip.ParsePrefix(t.LabPrefix)
	ipv4 := t.Family == NeighborFamilyIPv4
	validPrefix := err == nil && prefix == prefix.Masked() && (ipv4 && prefix.Addr().Is4() && prefix.Bits() >= 8 && prefix.Bits() <= 30 || !ipv4 && prefix.Addr().Is6() && prefix.Bits() == 64)
	if !validPrefix || !neighborInterfacePattern.MatchString(t.Interface) || !neighborPlanHashPattern.MatchString(t.ScopePlanHash) || t.VLANID != nil && (*t.VLANID < 1 || *t.VLANID > 4094) {
		return errors.New("neighbor table scope is invalid")
	}
	for _, neighbor := range t.Neighbors {
		address, err := netip.ParseAddr(neighbor.Address)
		inLab := err == nil && address.String() == neighbor.Address && (ipv4 && address.Is4() && prefix.Contains(address) && !neighbor.Router ||
			!ipv4 && address.Is6() && !address.Is4In6() && address.Zone() == "" && (address.IsLinkLocalUnicast() || prefix.Contains(address)))
		if !inLab {
			return errors.New("neighbor address is outside the lab")
		}
		mac, err := net.ParseMAC(neighbor.HardwareAddress)
		if err != nil || len(mac) != 6 || mac.String() != neighbor.HardwareAddress || mac[0]&1 != 0 {
			return errors.New("neighbor hardware address is invalid")
		}
		switch neighbor.State {
		case "REACHABLE", "STALE", "DELAY", "PROBE":
		default:
			return errors.New("neighbor state is invalid")
		}
		if neighbor.LastConfirmedAt.IsZero() || neighbor.LastConfirmedAt.After(t.ObservedAt) {
			return errors.New("neighbor confirmation time is invalid")
		}
	}
	return nil
}
