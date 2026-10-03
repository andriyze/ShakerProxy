package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// When the network's router serves DHCP (a single-arm lab, an inline
// bridge), ShakerProxy's own lease file never names the lab devices, but the
// lab recording sees their DHCP broadcasts and, on a bridge, the router's
// answers. Each exchange says who the client is: the name it gives itself
// (options 12 and 81), its DHCP implementation (the vendor class, option 60,
// and the order of the options it asks for, option 55) and, when the
// router's acknowledgement is seen, the address it now holds, for how long
// and from which server.

const (
	ObservedDHCPSchema = 1
	// ObservedDHCPWindow is how far back observed exchanges are read.
	ObservedDHCPWindow = 7 * 24 * time.Hour
	// MaxObservedDHCPClients bounds the response, like the inventory's own
	// device limit bounds a lab.
	MaxObservedDHCPClients = 4096
	maxObservedDHCPRows    = 20000
	maxDHCPParameters      = 64
	maxDHCPLeaseSeconds    = math.MaxInt32
)

var dhcpParameterListPattern = regexp.MustCompile(`^[0-9]{1,3}(,[0-9]{1,3}){0,63}$`)

// ObservedDHCPClient is what the exchanges of one MAC address said, newest
// values first. AssignedAddr, AssignedAt, LeaseSeconds, Server and Router
// come from the newest acknowledgement seen; a client seen only asking has
// none of them.
type ObservedDHCPClient struct {
	HardwareAddr  string    `json:"hardware_addr"`
	HostName      string    `json:"host_name,omitempty"`
	ClientFQDN    string    `json:"client_fqdn,omitempty"`
	VendorClass   string    `json:"vendor_class,omitempty"`
	ParameterList string    `json:"parameter_list,omitempty"`
	RequestedAddr string    `json:"requested_addr,omitempty"`
	AssignedAddr  string    `json:"assigned_addr,omitempty"`
	AssignedAt    time.Time `json:"assigned_at,omitzero"`
	LeaseSeconds  int64     `json:"lease_seconds,omitempty"`
	Server        string    `json:"server,omitempty"`
	Router        string    `json:"router,omitempty"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
}

type ObservedDHCP struct {
	Schema      int                  `json:"schema"`
	GeneratedAt time.Time            `json:"generated_at"`
	Clients     []ObservedDHCPClient `json:"clients"`
}

type ObservedDHCPReader interface {
	QueryObservedDHCP(context.Context) (ObservedDHCP, error)
}

// dhcpExchange is one DHCP record from Zeek or Suricata.
type dhcpExchange struct {
	mac, hostName, fqdn, vendorClass, parameterList string
	requested, assigned, server, router             netip.Addr
	leaseSeconds                                    int64
	acknowledged                                    bool
	at                                              time.Time
}

// parseZeekDHCP reads a Zeek dhcp.log record. A record without a usable
// client MAC says nothing about a device.
func parseZeekDHCP(payload []byte, occurredAt time.Time) (dhcpExchange, bool) {
	var record struct {
		MAC            string   `json:"mac"`
		HostName       string   `json:"host_name"`
		ClientFQDN     string   `json:"client_fqdn"`
		ClientSoftware string   `json:"client_software"`
		ParamList      []int    `json:"client_param_list"`
		RequestedAddr  string   `json:"requested_addr"`
		AssignedAddr   string   `json:"assigned_addr"`
		ServerAddr     string   `json:"server_addr"`
		Routers        []string `json:"routers"`
		LeaseTime      float64  `json:"lease_time"`
		MessageTypes   []string `json:"msg_types"`
	}
	if json.Unmarshal(payload, &record) != nil {
		return dhcpExchange{}, false
	}
	exchange := dhcpExchange{at: occurredAt.UTC()}
	if exchange.mac = dhcpClientMAC(record.MAC); exchange.mac == "" {
		return dhcpExchange{}, false
	}
	exchange.hostName = dhcpText(record.HostName, 253)
	exchange.fqdn = dhcpText(record.ClientFQDN, 253)
	exchange.vendorClass = dhcpText(record.ClientSoftware, 255)
	exchange.parameterList = dhcpParameterList(record.ParamList)
	exchange.requested = dhcpAddress(record.RequestedAddr)
	acked := false
	for _, messageType := range record.MessageTypes {
		if messageType == "ACK" {
			acked = true
		}
	}
	if assigned := dhcpAddress(record.AssignedAddr); acked && assigned.IsValid() {
		exchange.acknowledged, exchange.assigned = true, assigned
		exchange.server = dhcpAddress(record.ServerAddr)
		if len(record.Routers) > 0 {
			exchange.router = dhcpAddress(record.Routers[0])
		}
		if record.LeaseTime > 0 && record.LeaseTime <= maxDHCPLeaseSeconds {
			exchange.leaseSeconds = int64(record.LeaseTime)
		}
	}
	return exchange, true
}

// parseSuricataDHCP reads a Suricata EVE dhcp record. Suricata names the
// requested options rather than numbering them, so it gives no parameter
// list.
func parseSuricataDHCP(payload []byte, occurredAt time.Time) (dhcpExchange, bool) {
	var record struct {
		SourceIP string `json:"src_ip"`
		DHCP     struct {
			Type        string   `json:"type"`
			ClientMAC   string   `json:"client_mac"`
			AssignedIP  string   `json:"assigned_ip"`
			RequestedIP string   `json:"requested_ip"`
			DHCPType    string   `json:"dhcp_type"`
			Hostname    string   `json:"hostname"`
			VendorClass string   `json:"vendor_class_identifier"`
			LeaseTime   int64    `json:"lease_time"`
			Routers     []string `json:"routers"`
		} `json:"dhcp"`
	}
	if json.Unmarshal(payload, &record) != nil {
		return dhcpExchange{}, false
	}
	exchange := dhcpExchange{at: occurredAt.UTC()}
	if exchange.mac = dhcpClientMAC(record.DHCP.ClientMAC); exchange.mac == "" {
		return dhcpExchange{}, false
	}
	exchange.hostName = dhcpText(record.DHCP.Hostname, 253)
	exchange.vendorClass = dhcpText(record.DHCP.VendorClass, 255)
	exchange.requested = dhcpAddress(record.DHCP.RequestedIP)
	if assigned := dhcpAddress(record.DHCP.AssignedIP); record.DHCP.Type == "reply" && record.DHCP.DHCPType == "ack" && assigned.IsValid() {
		exchange.acknowledged, exchange.assigned = true, assigned
		exchange.server = dhcpAddress(record.SourceIP)
		if len(record.DHCP.Routers) > 0 {
			exchange.router = dhcpAddress(record.DHCP.Routers[0])
		}
		if record.DHCP.LeaseTime > 0 && record.DHCP.LeaseTime <= maxDHCPLeaseSeconds {
			exchange.leaseSeconds = record.DHCP.LeaseTime
		}
	}
	return exchange, true
}

// dhcpClientMAC canonicalizes a client's Ethernet address; broadcast,
// multicast and all-zero addresses are not a device.
func dhcpClientMAC(value string) string {
	hardware, err := net.ParseMAC(strings.TrimSpace(value))
	if err != nil || len(hardware) != 6 || hardware[0]&1 != 0 {
		return ""
	}
	for _, octet := range hardware {
		if octet != 0 {
			return hardware.String()
		}
	}
	return ""
}

// dhcpText keeps a printable value within limit bytes and drops anything
// else: a client chooses these strings.
func dhcpText(value string, limit int) string {
	value = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if !validText(value, 1, limit) {
		return ""
	}
	return value
}

func dhcpParameterList(values []int) string {
	if len(values) == 0 || len(values) > maxDHCPParameters {
		return ""
	}
	parts := make([]string, 0, len(values))
	for _, value := range values {
		if value < 1 || value > 254 {
			return ""
		}
		parts = append(parts, strconv.Itoa(value))
	}
	return strings.Join(parts, ",")
}

// dhcpAddress accepts a unicast IPv4 address a lease could name.
func dhcpAddress(value string) netip.Addr {
	address, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil || !address.Is4() || !usableDHCPAddress(address) {
		return netip.Addr{}
	}
	return address
}

func usableDHCPAddress(address netip.Addr) bool {
	return address.Is4() && !address.IsUnspecified() && !address.IsMulticast() && !address.IsLoopback() && address != netip.AddrFrom4([4]byte{255, 255, 255, 255})
}

// mergeObservedDHCP keeps one entry per MAC: the newest value of each field,
// and the newest acknowledgement's lease.
func mergeObservedDHCP(exchanges []dhcpExchange) []ObservedDHCPClient {
	sort.SliceStable(exchanges, func(i, j int) bool { return exchanges[i].at.After(exchanges[j].at) })
	clients := map[string]*ObservedDHCPClient{}
	order := []string{}
	for _, exchange := range exchanges {
		client, seen := clients[exchange.mac]
		if !seen {
			if len(clients) >= MaxObservedDHCPClients {
				continue
			}
			client = &ObservedDHCPClient{HardwareAddr: exchange.mac, FirstSeen: exchange.at, LastSeen: exchange.at}
			clients[exchange.mac] = client
			order = append(order, exchange.mac)
		}
		if exchange.at.Before(client.FirstSeen) {
			client.FirstSeen = exchange.at
		}
		if client.HostName == "" {
			client.HostName = exchange.hostName
		}
		if client.ClientFQDN == "" {
			client.ClientFQDN = exchange.fqdn
		}
		if client.VendorClass == "" {
			client.VendorClass = exchange.vendorClass
		}
		if client.ParameterList == "" {
			client.ParameterList = exchange.parameterList
		}
		if client.RequestedAddr == "" && exchange.requested.IsValid() {
			client.RequestedAddr = exchange.requested.String()
		}
		if client.AssignedAddr == "" && exchange.acknowledged {
			client.AssignedAddr, client.AssignedAt, client.LeaseSeconds = exchange.assigned.String(), exchange.at, exchange.leaseSeconds
			if exchange.server.IsValid() {
				client.Server = exchange.server.String()
			}
			if exchange.router.IsValid() {
				client.Router = exchange.router.String()
			}
		}
	}
	result := make([]ObservedDHCPClient, 0, len(order))
	for _, mac := range order {
		result = append(result, *clients[mac])
	}
	sort.Slice(result, func(i, j int) bool {
		if !result[i].LastSeen.Equal(result[j].LastSeen) {
			return result[i].LastSeen.After(result[j].LastSeen)
		}
		return result[i].HardwareAddr < result[j].HardwareAddr
	})
	return result
}

func (o ObservedDHCP) Validate() error {
	if o.Schema != ObservedDHCPSchema || o.GeneratedAt.IsZero() || len(o.Clients) > MaxObservedDHCPClients {
		return errors.New("observed DHCP is invalid")
	}
	seen := map[string]bool{}
	for _, client := range o.Clients {
		if err := client.validate(); err != nil || seen[client.HardwareAddr] {
			return errors.New("observed DHCP client is invalid")
		}
		seen[client.HardwareAddr] = true
	}
	return nil
}

func (c ObservedDHCPClient) validate() error {
	if dhcpClientMAC(c.HardwareAddr) != c.HardwareAddr || c.FirstSeen.IsZero() || c.LastSeen.Before(c.FirstSeen) {
		return errors.New("observed DHCP client identity is invalid")
	}
	for _, text := range []struct {
		value string
		limit int
	}{{c.HostName, 253}, {c.ClientFQDN, 253}, {c.VendorClass, 255}} {
		if text.value != "" && dhcpText(text.value, text.limit) != text.value {
			return errors.New("observed DHCP client text is invalid")
		}
	}
	if c.ParameterList != "" && !dhcpParameterListPattern.MatchString(c.ParameterList) {
		return errors.New("observed DHCP parameter list is invalid")
	}
	for _, value := range []string{c.RequestedAddr, c.AssignedAddr, c.Server, c.Router} {
		if value != "" && dhcpAddress(value).String() != value {
			return errors.New("observed DHCP address is invalid")
		}
	}
	if (c.AssignedAddr == "") != c.AssignedAt.IsZero() || c.AssignedAddr == "" && (c.LeaseSeconds != 0 || c.Server != "" || c.Router != "") || c.LeaseSeconds < 0 || c.LeaseSeconds > maxDHCPLeaseSeconds {
		return errors.New("observed DHCP lease is invalid")
	}
	return nil
}

// Both halves use normalized_events_source_kind_time_idx.
const observedDHCPStatement = `SELECT occurred_at, payload FROM normalized_events
WHERE source = $1 AND kind = $2 AND occurred_at >= $3
ORDER BY occurred_at DESC
LIMIT $4`

// QueryObservedDHCP reads the DHCP exchanges of the last week that Zeek and
// Suricata recorded and merges them per client MAC.
func (s PostgresSink) QueryObservedDHCP(ctx context.Context) (ObservedDHCP, error) {
	if s.DB == nil {
		return ObservedDHCP{}, errors.New("PostgreSQL connection is required")
	}
	var generatedAt time.Time
	if err := s.DB.QueryRowContext(ctx, "SELECT clock_timestamp()").Scan(&generatedAt); err != nil {
		return ObservedDHCP{}, fmt.Errorf("read observed DHCP boundary: %w", err)
	}
	generatedAt = generatedAt.UTC()
	var exchanges []dhcpExchange
	for _, source := range []struct {
		source Source
		kind   string
		parse  func([]byte, time.Time) (dhcpExchange, bool)
	}{
		{SourceZeek, "zeek.dhcp", parseZeekDHCP},
		{SourceSuricata, "suricata.dhcp", parseSuricataDHCP},
		{SourceNetworkGear, NetworkGearDHCPKind, parseNetgearDHCP},
	} {
		rows, err := s.DB.QueryContext(ctx, observedDHCPStatement, string(source.source), source.kind, generatedAt.Add(-ObservedDHCPWindow), maxObservedDHCPRows)
		if err != nil {
			return ObservedDHCP{}, fmt.Errorf("query observed DHCP: %w", err)
		}
		for rows.Next() {
			var occurredAt time.Time
			var payload []byte
			if err := rows.Scan(&occurredAt, &payload); err != nil {
				rows.Close()
				return ObservedDHCP{}, fmt.Errorf("decode observed DHCP: %w", err)
			}
			if exchange, ok := source.parse(payload, occurredAt); ok {
				exchanges = append(exchanges, exchange)
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return ObservedDHCP{}, fmt.Errorf("read observed DHCP: %w", err)
		}
	}
	observed := ObservedDHCP{Schema: ObservedDHCPSchema, GeneratedAt: generatedAt, Clients: mergeObservedDHCP(exchanges)}
	if err := observed.Validate(); err != nil {
		return ObservedDHCP{}, err
	}
	return observed, nil
}
