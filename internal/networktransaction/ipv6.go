package networktransaction

import "errors"

// IPv6 firewall modes recorded in a rollback specification.
const (
	IPv6FirewallBlock = "BLOCK"
	IPv6FirewallRoute = "ROUTE"
)

// IPv6RollbackSpec records the prior IPv6 state that a guarded apply may
// change. The zero value means the apply leaves IPv6 alone (manifests written
// before IPv6 support decode to it).
//
//   - Firewall BLOCK: the apply loads ShakerProxy's DISABLED drop chain.
//   - Firewall ROUTE: the apply loads the routed ShakerProxy chains, enables
//     net.ipv6.conf.all.forwarding (prior value in Forwarding), may raise the
//     WAN accept_ra from 1 to 2 (AcceptRAInterface/AcceptRA hold the prior
//     value) and starts shakerproxy-radvd.
//   - The radvd configuration digest/mode always describe the owned file
//     before apply so rollback can restore or remove it exactly.
type IPv6RollbackSpec struct {
	Firewall           string `json:"firewall,omitempty"`
	Ip6tablesPath      string `json:"ip6tables_path,omitempty"`
	ForwardParent      string `json:"forward_parent,omitempty"`
	NAT66              bool   `json:"nat66,omitempty"`
	Forwarding         int    `json:"forwarding,omitempty"`
	AcceptRAInterface  string `json:"accept_ra_interface,omitempty"`
	AcceptRA           int    `json:"accept_ra,omitempty"`
	RadvdConfigExisted bool   `json:"radvd_config_existed,omitempty"`
	RadvdConfigSHA256  string `json:"radvd_config_sha256,omitempty"`
	RadvdConfigMode    uint32 `json:"radvd_config_mode,omitempty"`
}

func (r IPv6RollbackSpec) Validate() error {
	if r.RadvdConfigExisted {
		if !planHashPattern.MatchString(r.RadvdConfigSHA256) || r.RadvdConfigMode&^0o777 != 0 {
			return errors.New("radvd configuration backup metadata is invalid")
		}
	} else if r.RadvdConfigSHA256 != "" || r.RadvdConfigMode != 0 {
		return errors.New("absent radvd configuration cannot have backup metadata")
	}
	switch r.Firewall {
	case "":
		if r.Ip6tablesPath != "" || r.ForwardParent != "" || r.NAT66 || r.Forwarding != 0 || r.AcceptRAInterface != "" || r.AcceptRA != 0 {
			return errors.New("IPv6 rollback state requires a ShakerProxy IPv6 firewall mode")
		}
		return nil
	case IPv6FirewallBlock, IPv6FirewallRoute:
	default:
		return errors.New("IPv6 firewall rollback mode is unsupported")
	}
	if r.Ip6tablesPath != "/usr/sbin/ip6tables" && r.Ip6tablesPath != "/usr/bin/ip6tables" {
		return errors.New("ip6tables rollback path is not approved")
	}
	if r.ForwardParent != "DOCKER-USER" && r.ForwardParent != "FORWARD" {
		return errors.New("IPv6 forward chain parent is not approved")
	}
	if r.Firewall == IPv6FirewallBlock {
		if r.NAT66 || r.Forwarding != 0 || r.AcceptRAInterface != "" || r.AcceptRA != 0 {
			return errors.New("blocked lab IPv6 cannot record routing state")
		}
		return nil
	}
	if r.Forwarding != 0 && r.Forwarding != 1 {
		return errors.New("IPv6 forwarding snapshot must be zero or one")
	}
	if r.AcceptRAInterface == "" {
		if r.AcceptRA != 0 {
			return errors.New("IPv6 router advertisement snapshot requires an interface")
		}
	} else if !safeRollbackInterfaceName(r.AcceptRAInterface) || r.AcceptRA != 1 {
		return errors.New("IPv6 router advertisement snapshot is invalid")
	}
	return nil
}
