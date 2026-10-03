// Package labrouting decides, for each device on the lab network, whether
// its traffic goes through ShakerProxy. A device can be on the lab (it asks
// the network's DHCP server for an address, it announces itself with mDNS)
// and still send everything straight to the router: in a single-arm lab the
// router's DHCP tells it to use the router as its gateway. ShakerProxy then
// records only its broadcasts, and the tester sees nothing of its traffic.
// Saying so, with the reason, is the first thing a tester needs.
package labrouting

import (
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"time"

	"shakerproxy.dev/shakerproxy/internal/ingest"
)

type Routing string

const (
	// Through: ShakerProxy saw the device's traffic recently.
	Through Routing = "THROUGH_SHAKERPROXY"
	// Bypassing: the device has been on the lab for a while, and none of its
	// traffic reached ShakerProxy.
	Bypassing Routing = "BYPASSING"
	// Unknown: the device just appeared; it may not have sent traffic yet.
	Unknown Routing = "UNKNOWN"
)

const (
	// DefaultThreshold is how long a device must be seen on the lab without
	// any traffic through ShakerProxy before it counts as bypassing.
	DefaultThreshold = 2 * time.Minute
	// PresentWindow is how recently a device must have been seen to be
	// reported at all.
	PresentWindow = 10 * time.Minute
)

// Context is what ShakerProxy knows about the lab.
type Context struct {
	Now time.Time
	// ShakerProxy is ShakerProxy's own lab address, the gateway devices
	// should use.
	ShakerProxy netip.Addr
	// Router is the network's own router, when known: ShakerProxy's default
	// gateway on the lab interface in a single-arm lab.
	Router netip.Addr
	// ShakerProxyServesDHCP is true when ShakerProxy runs the lab's DHCP
	// (a routed lab); false in a single-arm lab or an inline bridge, where
	// the router does.
	ShakerProxyServesDHCP bool
	// ShakerProxyLeases are the lab addresses ShakerProxy's own DHCP holds
	// an active lease for, each with the lease's MAC ("" when unknown). A
	// device with one has ShakerProxy as its gateway even when its DHCP
	// exchange is older than the presence window.
	ShakerProxyLeases map[netip.Addr]string
	Threshold         time.Duration
}

// leaseOrigin is who gave a device its address, as far as ShakerProxy can
// tell.
type leaseOrigin int

const (
	leaseUnknown leaseOrigin = iota
	// leaseShakerProxy: ShakerProxy's DHCP, which makes ShakerProxy the
	// gateway.
	leaseShakerProxy
	// leaseOther: the router's DHCP, or another server on the lab.
	leaseOther
)

// originOf prefers the newest DHCP acknowledgement ShakerProxy saw (its
// gateway option, else its server), then ShakerProxy's own lease table.
func originOf(host ingest.LabPresenceHost, address netip.Addr, context Context) leaseOrigin {
	for _, observed := range []string{host.DHCPGateway, host.DHCPServer} {
		if value, err := netip.ParseAddr(observed); err == nil {
			if context.ShakerProxy.IsValid() && value == context.ShakerProxy {
				return leaseShakerProxy
			}
			return leaseOther
		}
	}
	if mac, leased := context.ShakerProxyLeases[address]; leased && (mac == "" || len(host.HardwareAddrs) == 0 || slices.Contains(host.HardwareAddrs, mac)) {
		return leaseShakerProxy
	}
	return leaseUnknown
}

// Result is one device's state.
type Result struct {
	Address       string    `json:"address"`
	HardwareAddrs []string  `json:"hardware_addrs,omitempty"`
	HostName      string    `json:"host_name,omitempty"`
	Routing       Routing   `json:"routing"`
	Since         time.Time `json:"since"`
	LastSeen      time.Time `json:"last_seen"`
	// Evidence lists, in plain words, what ShakerProxy saw.
	Evidence []string `json:"evidence"`
	// Reason says why the traffic bypasses ShakerProxy, when it does.
	Reason string `json:"reason,omitempty"`
}

// Classify judges each host seen within PresentWindow; ShakerProxy and the
// router themselves are not devices under test.
func Classify(hosts []ingest.LabPresenceHost, context Context) []Result {
	threshold := context.Threshold
	if threshold <= 0 {
		threshold = DefaultThreshold
	}
	results := make([]Result, 0, len(hosts))
	for _, host := range hosts {
		address, err := netip.ParseAddr(host.Address)
		if err != nil || address == context.ShakerProxy || address == context.Router || context.Now.Sub(host.LastSeen) > PresentWindow {
			continue
		}
		origin := originOf(host, address, context)
		result := Result{Address: host.Address, HardwareAddrs: host.HardwareAddrs, HostName: host.HostName, LastSeen: host.LastSeen, Evidence: evidence(host, origin)}
		quiet := quietSince(host)
		// A device whose newest DHCP exchange was not ShakerProxy's (the
		// router's, in a lab where ShakerProxy serves none, or another
		// server's) has that server's gateway; otherwise it must have been
		// active for a while before its silence through ShakerProxy means
		// anything. Its DHCP and discovery broadcasts are not activity: an
		// idle printer announcing itself sends nothing anywhere.
		otherLease := !host.DHCPLastSeen.IsZero() && (origin == leaseOther || origin == leaseUnknown && !context.ShakerProxyServesDHCP)
		activity := host.Events - host.DiscoveryEvents - host.DHCPEvents
		active := host.LastSeen.Sub(quiet) >= threshold || activity >= 3 || otherLease
		switch {
		case host.VisibleEvents > 0 && !rejoinedSince(host, otherLease, context.Now, threshold):
			result.Routing, result.Since = Through, host.VisibleFirstSeen
		case origin == leaseShakerProxy:
			// ShakerProxy is its gateway; it has just sent nothing yet.
			result.Routing, result.Since = Unknown, quiet
		case context.Now.Sub(quiet) >= threshold && active:
			result.Routing, result.Since = Bypassing, quiet
			result.Reason = reason(host, origin, context)
		default:
			result.Routing, result.Since = Unknown, quiet
		}
		results = append(results, result)
	}
	sort.SliceStable(results, func(i, j int) bool {
		if rank(results[i].Routing) != rank(results[j].Routing) {
			return rank(results[i].Routing) < rank(results[j].Routing)
		}
		return results[i].LastSeen.After(results[j].LastSeen)
	})
	return results
}

// rejoinedSince reports a device that asked another DHCP server for its
// address after its last traffic through ShakerProxy and has sent nothing
// through it for threshold since: it rejoined the network and the router's
// DHCP took it over. The time is measured to now, not to its last sighting,
// so a device that rejoins and then goes quiet is caught too.
func rejoinedSince(host ingest.LabPresenceHost, otherLease bool, now time.Time, threshold time.Duration) bool {
	return otherLease && host.DHCPLastSeen.After(host.VisibleLastSeen) && now.Sub(host.DHCPLastSeen) >= threshold
}

// quietSince is when the device's time without traffic through ShakerProxy
// began: its first appearance, or its newest DHCP request after its last
// traffic through ShakerProxy.
func quietSince(host ingest.LabPresenceHost) time.Time {
	if host.VisibleEvents > 0 && !host.DHCPLastSeen.IsZero() && host.DHCPLastSeen.After(host.VisibleLastSeen) {
		return host.DHCPLastSeen
	}
	return host.FirstSeen
}

func rank(routing Routing) int {
	switch routing {
	case Bypassing:
		return 0
	case Unknown:
		return 1
	}
	return 2
}

func evidence(host ingest.LabPresenceHost, origin leaseOrigin) []string {
	var items []string
	switch {
	case origin == leaseShakerProxy:
		items = append(items, fmt.Sprintf("has a lease for %s from ShakerProxy's DHCP, so ShakerProxy is its gateway", host.Address))
	case origin == leaseOther && host.DHCPServer != "":
		items = append(items, fmt.Sprintf("got %s from the DHCP server at %s", host.Address, host.DHCPServer))
	case !host.DHCPLastSeen.IsZero():
		items = append(items, fmt.Sprintf("asked the network's DHCP server for %s", host.Address))
	}
	if host.DiscoveryEvents > 0 {
		items = append(items, fmt.Sprintf("%d local discovery %s (mDNS, SSDP and similar)", host.DiscoveryEvents, plural(host.DiscoveryEvents, "message", "messages")))
	}
	if host.VisibleEvents > 0 {
		items = append(items, fmt.Sprintf("%d %s through ShakerProxy", host.VisibleEvents, plural(host.VisibleEvents, "connection or lookup", "connections and lookups")))
	} else {
		items = append(items, "no connections or DNS lookups through ShakerProxy")
	}
	return items
}

func reason(host ingest.LabPresenceHost, origin leaseOrigin, context Context) string {
	router := "the router"
	if context.Router.IsValid() {
		router = fmt.Sprintf("the router (%s)", context.Router)
	}
	switch {
	case origin == leaseOther && context.ShakerProxyServesDHCP:
		server, gateway := "another DHCP server", "another gateway"
		if host.DHCPServer != "" {
			server = "another DHCP server (" + host.DHCPServer + ")"
		}
		if host.DHCPGateway != "" {
			gateway = host.DHCPGateway
		}
		return fmt.Sprintf("It got its address from %s, not ShakerProxy, so it uses %s as its gateway.", server, gateway)
	case !context.ShakerProxyServesDHCP && !host.DHCPLastSeen.IsZero():
		return fmt.Sprintf("It got its address from your router's DHCP, so it uses %s as its gateway, not ShakerProxy.", router)
	case !context.ShakerProxyServesDHCP:
		return fmt.Sprintf("It uses %s as its gateway, not ShakerProxy.", router)
	default:
		return "It does not use ShakerProxy as its gateway; it may have a fixed address with another gateway."
	}
}

func plural(count int64, one, many string) string {
	if count == 1 {
		return one
	}
	return many
}
