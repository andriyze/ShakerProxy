package ingest

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// Who is on the lab, and does ShakerProxy see their traffic? In a single-arm
// lab, ShakerProxy records only frames addressed to it and multicast: a
// device that took the router as its gateway (from the router's DHCP) shows
// its DHCP broadcasts and its mDNS/SSDP, and nothing else. A device whose
// traffic goes through ShakerProxy also shows connections, DNS lookups to
// it, and captured unicast traffic. LabPresence reports both per lab
// address, so the control API can say which devices bypass ShakerProxy.

const (
	LabPresenceSchema = 1
	// LabPresenceWindow is how far back presence and visible traffic are
	// read.
	LabPresenceWindow   = 30 * time.Minute
	MaxLabPresenceHosts = 512
	maxLabPresenceMACs  = 8
	maxLabPresenceRows  = 4096
)

// LabPresenceHost is one lab IPv4 address over the window. Visible* count
// the events that show its traffic reached ShakerProxy: connections and DNS
// lookups ShakerProxy handled, and recorded traffic to a unicast address
// (in a single-arm lab only frames sent to ShakerProxy are recorded).
// DHCPLastSeen is the newest DHCP request for the address.
type LabPresenceHost struct {
	Address          string    `json:"address"`
	HardwareAddrs    []string  `json:"hardware_addrs,omitempty"`
	HostName         string    `json:"host_name,omitempty"`
	FirstSeen        time.Time `json:"first_seen"`
	LastSeen         time.Time `json:"last_seen"`
	Events           int64     `json:"events"`
	DiscoveryEvents  int64     `json:"discovery_events"`
	VisibleEvents    int64     `json:"visible_events"`
	VisibleFirstSeen time.Time `json:"visible_first_seen,omitzero"`
	VisibleLastSeen  time.Time `json:"visible_last_seen,omitzero"`
	DHCPLastSeen     time.Time `json:"dhcp_last_seen,omitzero"`
	// DHCPEvents counts the DHCP exchanges for the address. Like discovery
	// messages they are broadcasts, and say nothing about where the
	// device's traffic goes.
	DHCPEvents int64 `json:"dhcp_events,omitempty"`
	// DHCPServer and DHCPGateway are the server and the gateway (router
	// option) of the newest acknowledged lease ShakerProxy saw for the
	// address: they tell a lease ShakerProxy served from the router's or a
	// rogue server's.
	DHCPServer  string `json:"dhcp_server,omitempty"`
	DHCPGateway string `json:"dhcp_gateway,omitempty"`
}

type LabPresence struct {
	Schema      int               `json:"schema"`
	GeneratedAt time.Time         `json:"generated_at"`
	Prefix      string            `json:"prefix"`
	Since       time.Time         `json:"since"`
	Hosts       []LabPresenceHost `json:"hosts"`
}

type LabPresenceReader interface {
	QueryLabPresence(context.Context, netip.Prefix) (LabPresence, error)
}

// ValidLabPresencePrefix accepts an IPv4 lab prefix between /8 and /30.
func ValidLabPresencePrefix(prefix netip.Prefix) bool {
	return prefix.IsValid() && prefix.Addr().Is4() && prefix.Bits() >= 8 && prefix.Bits() <= 30 && prefix == prefix.Masked()
}

func (p LabPresence) Validate() error {
	prefix, err := netip.ParsePrefix(p.Prefix)
	if p.Schema != LabPresenceSchema || p.GeneratedAt.IsZero() || p.Since.IsZero() || err != nil || !ValidLabPresencePrefix(prefix) || len(p.Hosts) > MaxLabPresenceHosts {
		return errors.New("lab presence is invalid")
	}
	seen := map[string]bool{}
	for _, host := range p.Hosts {
		address, err := netip.ParseAddr(host.Address)
		if err != nil || address.String() != host.Address || !prefix.Contains(address) || seen[host.Address] {
			return errors.New("lab presence address is invalid")
		}
		seen[host.Address] = true
		if host.FirstSeen.IsZero() || host.LastSeen.Before(host.FirstSeen) || host.Events < 0 || host.DiscoveryEvents < 0 || host.VisibleEvents < 0 || host.DiscoveryEvents > host.Events || host.VisibleEvents > host.Events ||
			(host.VisibleEvents > 0) == host.VisibleLastSeen.IsZero() || host.VisibleFirstSeen.After(host.VisibleLastSeen) || len(host.HardwareAddrs) > maxLabPresenceMACs {
			return errors.New("lab presence host is invalid")
		}
		for _, mac := range host.HardwareAddrs {
			if dhcpClientMAC(mac) != mac {
				return errors.New("lab presence hardware address is invalid")
			}
		}
		if host.HostName != "" && dhcpText(host.HostName, 253) != host.HostName {
			return errors.New("lab presence host name is invalid")
		}
		if host.DHCPEvents < 0 || host.DHCPEvents > host.Events || !validOptionalAddress(host.DHCPServer) || !validOptionalAddress(host.DHCPGateway) {
			return errors.New("lab presence DHCP lease is invalid")
		}
	}
	return nil
}

// labVisibleCondition is true for an event that shows the source's traffic
// reached ShakerProxy. Only first-hand evidence counts: a NETWORK_GEAR event
// is the router reporting what it saw, which carries a real destination but is
// the opposite of proof that the traffic reached ShakerProxy, so it is
// excluded here while still counting toward presence.
const labVisibleCondition = `(source <> 'NETWORK_GEAR'
  AND (kind IN ('shakerproxy.conn', 'shakerproxy.dns', 'shakerproxy.blocked')
  OR (destination_ip IS NOT NULL AND family(destination_ip) = 4
      AND NOT destination_ip << '224.0.0.0/4'::cidr
      AND destination_ip <> '255.255.255.255'::inet
      AND destination_ip <> broadcast($2::cidr))))`

const labPresenceStatement = `SELECT host(source_ip), min(occurred_at), max(occurred_at), count(*),
  count(*) FILTER (WHERE protocol_category = 'local-discovery'),
  count(*) FILTER (WHERE ` + labVisibleCondition + `),
  min(occurred_at) FILTER (WHERE ` + labVisibleCondition + `),
  max(occurred_at) FILTER (WHERE ` + labVisibleCondition + `)
FROM normalized_events
WHERE occurred_at >= $1 AND source_ip << $2::cidr AND family(source_ip) = 4
  AND source_ip <> network($2::cidr) AND source_ip <> broadcast($2::cidr)
GROUP BY source_ip
ORDER BY max(occurred_at) DESC
LIMIT $3`

// Zeek writes the MAC of the sender of each recorded connection.
const labPresenceMACStatement = `SELECT host(source_ip), payload->>'orig_l2_addr', min(occurred_at), max(occurred_at)
FROM normalized_events
WHERE source = $1 AND kind = 'zeek.conn' AND occurred_at >= $2 AND source_ip << $3::cidr AND payload ? 'orig_l2_addr'
GROUP BY 1, 2
ORDER BY 4 DESC
LIMIT $4`

const labPresenceDHCPStatement = `SELECT occurred_at, payload FROM normalized_events
WHERE source = $1 AND kind = 'zeek.dhcp' AND occurred_at >= $2
ORDER BY occurred_at DESC
LIMIT $3`

// QueryLabPresence reports the lab addresses seen over the last
// LabPresenceWindow.
func (s PostgresSink) QueryLabPresence(ctx context.Context, prefix netip.Prefix) (LabPresence, error) {
	if s.DB == nil {
		return LabPresence{}, errors.New("PostgreSQL connection is required")
	}
	if !ValidLabPresencePrefix(prefix) {
		return LabPresence{}, errors.New("lab prefix is invalid")
	}
	var generatedAt time.Time
	if err := s.DB.QueryRowContext(ctx, "SELECT clock_timestamp()").Scan(&generatedAt); err != nil {
		return LabPresence{}, fmt.Errorf("read lab presence boundary: %w", err)
	}
	generatedAt = generatedAt.UTC()
	since := generatedAt.Add(-LabPresenceWindow)
	hosts := map[string]*LabPresenceHost{}

	rows, err := s.DB.QueryContext(ctx, labPresenceStatement, since, prefix.String(), MaxLabPresenceHosts)
	if err != nil {
		return LabPresence{}, fmt.Errorf("query lab presence: %w", err)
	}
	for rows.Next() {
		var host LabPresenceHost
		var visibleFirst, visibleLast *time.Time
		if err := rows.Scan(&host.Address, &host.FirstSeen, &host.LastSeen, &host.Events, &host.DiscoveryEvents, &host.VisibleEvents, &visibleFirst, &visibleLast); err != nil {
			rows.Close()
			return LabPresence{}, fmt.Errorf("decode lab presence: %w", err)
		}
		if visibleFirst != nil && visibleLast != nil {
			host.VisibleFirstSeen, host.VisibleLastSeen = visibleFirst.UTC(), visibleLast.UTC()
		}
		host.FirstSeen, host.LastSeen = host.FirstSeen.UTC(), host.LastSeen.UTC()
		hosts[host.Address] = &host
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return LabPresence{}, fmt.Errorf("read lab presence: %w", err)
	}

	var macs []labPresenceMAC
	rows, err = s.DB.QueryContext(ctx, labPresenceMACStatement, string(SourceZeek), since, prefix.String(), maxLabPresenceRows)
	if err != nil {
		return LabPresence{}, fmt.Errorf("query lab presence hardware addresses: %w", err)
	}
	for rows.Next() {
		var item labPresenceMAC
		if err := rows.Scan(&item.address, &item.mac, &item.first, &item.last); err != nil {
			rows.Close()
			return LabPresence{}, fmt.Errorf("decode lab presence hardware address: %w", err)
		}
		macs = append(macs, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return LabPresence{}, fmt.Errorf("read lab presence hardware addresses: %w", err)
	}

	var requests []dhcpExchange
	rows, err = s.DB.QueryContext(ctx, labPresenceDHCPStatement, string(SourceZeek), since, maxLabPresenceRows)
	if err != nil {
		return LabPresence{}, fmt.Errorf("query lab presence DHCP: %w", err)
	}
	for rows.Next() {
		var occurredAt time.Time
		var payload []byte
		if err := rows.Scan(&occurredAt, &payload); err != nil {
			rows.Close()
			return LabPresence{}, fmt.Errorf("decode lab presence DHCP: %w", err)
		}
		if exchange, ok := parseZeekDHCP(payload, occurredAt); ok {
			requests = append(requests, exchange)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return LabPresence{}, fmt.Errorf("read lab presence DHCP: %w", err)
	}

	presence := LabPresence{Schema: LabPresenceSchema, GeneratedAt: generatedAt, Prefix: prefix.String(), Since: since, Hosts: mergeLabPresence(hosts, macs, requests, prefix)}
	if err := presence.Validate(); err != nil {
		return LabPresence{}, err
	}
	return presence, nil
}

type labPresenceMAC struct {
	address, mac string
	first, last  time.Time
}

// mergeLabPresence adds the MACs Zeek saw sending from each address, and
// the DHCP requests for lab addresses: a device that asked for an address
// is on the lab even before it sends anything else.
func mergeLabPresence(hosts map[string]*LabPresenceHost, macs []labPresenceMAC, requests []dhcpExchange, prefix netip.Prefix) []LabPresenceHost {
	for _, item := range macs {
		host, ok := hosts[item.address]
		mac := dhcpClientMAC(item.mac)
		if !ok || mac == "" {
			continue
		}
		addMAC(host, mac)
	}
	sort.SliceStable(requests, func(i, j int) bool { return requests[i].at.After(requests[j].at) })
	for _, request := range requests {
		address := request.requested
		if request.acknowledged {
			address = request.assigned
		}
		if !address.IsValid() || !prefix.Contains(address) || address == prefix.Masked().Addr() {
			continue
		}
		key := address.String()
		host, ok := hosts[key]
		if !ok {
			if len(hosts) >= MaxLabPresenceHosts {
				continue
			}
			host = &LabPresenceHost{Address: key, FirstSeen: request.at, LastSeen: request.at}
			hosts[key] = host
		}
		host.Events++
		host.DHCPEvents++
		if request.acknowledged && host.DHCPServer == "" && host.DHCPGateway == "" {
			// requests run newest first, so this is the newest lease.
			if request.server.IsValid() {
				host.DHCPServer = request.server.String()
			}
			if request.router.IsValid() {
				host.DHCPGateway = request.router.String()
			}
		}
		host.FirstSeen = minTime(host.FirstSeen, request.at)
		if request.at.After(host.LastSeen) {
			host.LastSeen = request.at
		}
		if request.at.After(host.DHCPLastSeen) {
			host.DHCPLastSeen = request.at
		}
		if host.HostName == "" {
			host.HostName = request.hostName
		}
		addMAC(host, request.mac)
	}
	result := make([]LabPresenceHost, 0, len(hosts))
	for _, host := range hosts {
		sort.Strings(host.HardwareAddrs)
		result = append(result, *host)
	}
	sort.Slice(result, func(i, j int) bool {
		if !result[i].LastSeen.Equal(result[j].LastSeen) {
			return result[i].LastSeen.After(result[j].LastSeen)
		}
		return result[i].Address < result[j].Address
	})
	if len(result) > MaxLabPresenceHosts {
		result = result[:MaxLabPresenceHosts]
	}
	return result
}

func validOptionalAddress(value string) bool {
	if value == "" {
		return true
	}
	address, err := netip.ParseAddr(value)
	return err == nil && address.String() == value
}

func addMAC(host *LabPresenceHost, mac string) {
	if mac == "" || len(host.HardwareAddrs) >= maxLabPresenceMACs {
		return
	}
	for _, known := range host.HardwareAddrs {
		if known == mac {
			return
		}
	}
	host.HardwareAddrs = append(host.HardwareAddrs, mac)
}

func minTime(first, second time.Time) time.Time {
	if first.IsZero() || second.Before(first) {
		return second
	}
	return first
}

// ParseLabPresencePrefix reads the prefix query parameter.
func ParseLabPresencePrefix(value string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
	if err != nil || !ValidLabPresencePrefix(prefix) {
		return netip.Prefix{}, errors.New("prefix must be an IPv4 lab prefix between /8 and /30")
	}
	return prefix, nil
}
