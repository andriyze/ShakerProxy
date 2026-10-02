package ingest

import (
	"slices"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/querylang"
)

// A phone's HTTPS connection is reported by Zeek's conn and ssl logs and by
// Suricata, and its DNS lookup by Zeek and Suricata. The Domains facet counts
// each connection and lookup once and groups host names by domain.
func TestDomainFacetPostgresCountsConnectionsOnceAndGroupsHosts(t *testing.T) {
	_, sink, ctx := openProtocolTestDatabase(t)
	now := time.Now().UTC().Truncate(time.Second)
	phone := protocolTestCamera
	at := func(minutes int) time.Time { return now.Add(time.Duration(-minutes) * time.Minute) }
	zeek := func(minutes int, fields map[string]any) Envelope {
		return zeekTestEnvelope(t, protocolTestZeekCapture, phone, at(minutes), fields)
	}
	suricata := func(minutes int, fields map[string]any) Envelope {
		return suricataTestEnvelope(t, protocolTestZeekCapture, phone, at(minutes), fields)
	}
	https := func(uid string, port int, destination, serverName string) map[string]any {
		return map[string]any{"_path": "conn", "uid": uid, "id.orig_h": "192.168.10.201", "id.orig_p": port, "id.resp_h": destination, "id.resp_p": 443, "proto": "tcp", "service": "ssl", "server_name": serverName}
	}
	envelopes := []Envelope{
		// One HTTPS connection: conn (named by the ShakerProxy Zeek policy), ssl, and Suricata tls.
		zeek(9, https("Cconn00000000001", 41000, "142.250.1.1", "connectivitycheck.grapheneos.network")),
		zeek(9, map[string]any{"_path": "ssl", "uid": "Cconn00000000001", "id.orig_h": "192.168.10.201", "id.orig_p": 41000, "id.resp_h": "142.250.1.1", "id.resp_p": 443, "server_name": "connectivitycheck.grapheneos.network", "version": "TLSv13"}),
		suricata(9, map[string]any{"event_type": "tls", "flow_id": 3234567890123, "src_ip": "192.168.10.201", "src_port": 41000, "dest_ip": "142.250.1.1", "dest_port": 443, "proto": "TCP", "tls": map[string]any{"sni": "connectivitycheck.grapheneos.network"}}),
		// The same connection again in the next 30-second capture segment.
		zeek(8, https("Cconn00000000002", 41000, "142.250.1.1", "connectivitycheck.grapheneos.network")),
		// A second connection, to another host of the same domain.
		zeek(7, https("Cconn00000000003", 41001, "142.250.1.2", "time.grapheneos.network")),
		// One lookup seen by Zeek and Suricata.
		zeek(6, map[string]any{"_path": "dns", "uid": "Cdns000000000001", "id.orig_h": "192.168.10.201", "id.orig_p": 5300, "id.resp_h": "192.168.10.177", "id.resp_p": 53, "proto": "udp", "query": "www.googleapis.com", "qtype_name": "A", "rcode_name": "NOERROR"}),
		suricata(6, map[string]any{"event_type": "dns", "flow_id": 4234567890123, "src_ip": "192.168.10.201", "src_port": 5300, "dest_ip": "192.168.10.177", "dest_port": 53, "proto": "UDP", "dns": map[string]any{"type": "request", "rrname": "www.googleapis.com", "rrtype": "A"}}),
		// Local names are not internet domains.
		zeek(5, map[string]any{"_path": "dns", "uid": "Cdns000000000002", "id.orig_h": "192.168.10.201", "id.orig_p": 5353, "id.resp_h": "224.0.0.251", "id.resp_p": 5353, "proto": "udp", "query": "_googlecast._tcp.local", "qtype_name": "PTR"}),
		// Another device's traffic stays out of a device-filtered view.
		zeekTestEnvelope(t, protocolTestZeekCapture, protocolTestTV, at(4), map[string]any{"_path": "conn", "uid": "Cconn00000000004", "id.orig_h": "192.168.10.50", "id.orig_p": 42000, "id.resp_h": "3.3.3.3", "id.resp_p": 443, "proto": "tcp", "service": "ssl", "server_name": "api.netflix.com"}),
	}
	writeTestEnvelopes(t, ctx, sink, now, envelopes)

	filter, err := querylang.Parse("device.id:" + phone)
	if err != nil {
		t.Fatal(err)
	}
	page, err := sink.QueryRecent(ctx, RecentEventQuery{Limit: 1, Filter: filter})
	if err != nil {
		t.Fatal(err)
	}
	if page.Facets == nil {
		t.Fatal("first page has no facets")
	}
	domains := page.Facets.Domains
	if err := validateEventDomains(domains); err != nil {
		t.Fatalf("domain facet is invalid: %v", err)
	}
	if len(domains.Values) != 2 || domains.OtherCount != 0 {
		t.Fatalf("domains = %+v other=%d, want grapheneos.network and googleapis.com", domains.Values, domains.OtherCount)
	}
	graphene, google := domains.Values[0], domains.Values[1]
	if graphene.Domain != "grapheneos.network" || graphene.Count != 2 || !slices.Equal(graphene.Hosts, []string{"connectivitycheck.grapheneos.network", "time.grapheneos.network"}) {
		t.Fatalf("a connection was not counted once: %+v", graphene)
	}
	if google.Domain != "googleapis.com" || google.Count != 1 {
		t.Fatalf("a lookup seen by two analyzers was not counted once: %+v", google)
	}

	everything, err := sink.QueryRecent(ctx, RecentEventQuery{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if values := everything.Facets.Domains.Values; len(values) != 3 || !slices.ContainsFunc(values, func(value EventDomainValue) bool { return value.Domain == "netflix.com" }) {
		t.Fatalf("unfiltered domains = %+v", values)
	}
}
