package mvppreflight

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

const SchemaVersion = 1

type Snapshot struct {
	Interface        string   `json:"interface"`
	IPv6Addresses    []string `json:"ipv6_addresses"`
	IPv6DefaultRoute bool     `json:"ipv6_default_route"`
	AcceptRA         int      `json:"accept_ra"`
	Autoconf         int      `json:"autoconf"`
	IPv6Forwarding   int      `json:"ipv6_forwarding"`
}

type Check struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

type Report struct {
	SchemaVersion int     `json:"schema_version"`
	Profile       string  `json:"profile"`
	Supported     bool    `json:"supported"`
	Interface     string  `json:"interface"`
	Checks        []Check `json:"checks"`
}

func EvaluateIPv4MVP(snapshot Snapshot) (Report, error) {
	snapshot.Interface = strings.TrimSpace(snapshot.Interface)
	if snapshot.Interface == "" || strings.ContainsAny(snapshot.Interface, " /\t\r\n") {
		return Report{}, errors.New("test interface is invalid")
	}
	for _, value := range []int{snapshot.AcceptRA, snapshot.Autoconf, snapshot.IPv6Forwarding} {
		if value < 0 || value > 2 {
			return Report{}, errors.New("IPv6 sysctl snapshot is invalid")
		}
	}
	addresses := make([]string, 0, len(snapshot.IPv6Addresses))
	for _, raw := range snapshot.IPv6Addresses {
		address, err := netip.ParseAddr(strings.TrimSpace(raw))
		if err != nil || !address.Is6() {
			return Report{}, fmt.Errorf("invalid IPv6 address %q in preflight snapshot", raw)
		}
		addresses = append(addresses, address.String())
	}
	sort.Strings(addresses)

	report := Report{
		SchemaVersion: SchemaVersion,
		Profile:       "mvp-ipv4-only",
		Supported:     true,
		Interface:     snapshot.Interface,
		Checks:        make([]Check, 0, 5),
	}
	add := func(id string, ok bool, good, bad string) {
		status := "PASS"
		message := good
		if !ok {
			status = "FAIL"
			message = bad
			report.Supported = false
		}
		report.Checks = append(report.Checks, Check{ID: id, Status: status, Message: message})
	}
	add(
		"no-ipv6-addresses",
		len(addresses) == 0,
		"test interface has no IPv6 address",
		fmt.Sprintf("test interface has IPv6 addresses: %s", strings.Join(addresses, ", ")),
	)
	add(
		"no-ipv6-default-route",
		!snapshot.IPv6DefaultRoute,
		"test interface has no IPv6 default route",
		"test interface has an IPv6 default route that can bypass the IPv4 ShakerProxy path",
	)
	add(
		"router-advertisements-disabled",
		snapshot.AcceptRA == 0,
		"router-advertisement acceptance is disabled",
		fmt.Sprintf("router-advertisement acceptance is %d, expected 0", snapshot.AcceptRA),
	)
	add(
		"ipv6-autoconfiguration-disabled",
		snapshot.Autoconf == 0,
		"IPv6 SLAAC autoconfiguration is disabled",
		fmt.Sprintf("IPv6 autoconfiguration is %d, expected 0", snapshot.Autoconf),
	)
	add(
		"ipv6-forwarding-disabled",
		snapshot.IPv6Forwarding == 0,
		"IPv6 forwarding is disabled for the MVP test interface",
		fmt.Sprintf("IPv6 forwarding is %d, expected 0", snapshot.IPv6Forwarding),
	)
	return report, nil
}
