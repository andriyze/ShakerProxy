package ingest

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestDeviceActivityPostgresAggregatesOneDeviceWindow(t *testing.T) {
	databaseURL := strings.TrimSpace(os.Getenv("SHAKERPROXY_TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("SHAKERPROXY_TEST_DATABASE_URL is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	database, err := sql.Open("pgx", databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	database.SetMaxOpenConns(2)
	sink := PostgresSink{DB: database}
	if err := sink.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	truncate := func(ctx context.Context) {
		_, _ = database.ExecContext(ctx, "TRUNCATE TABLE normalized_events, normalized_event_identities CASCADE")
	}
	truncate(ctx)
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		truncate(cleanup)
	})

	now := time.Now().UTC().Truncate(time.Second)
	device := "device-0123456789abcdef0123456789abcdef"
	other := "device-fedcba9876543210fedcba9876543210"
	sequence := 0
	event := func(source Source, kind, deviceID string, at time.Time, payload string) Envelope {
		sequence++
		return Envelope{
			Schema: SchemaVersion, EventID: fmt.Sprintf("device-activity-event-%04d", sequence), Source: source, Kind: kind,
			OccurredAt: at, SourceVersion: "test", ParserVersion: "shakerproxy-test-v1",
			FlowID: fmt.Sprintf("flow-device-activity-%04d", sequence), DeviceID: deviceID, Confidence: 90,
			Payload: json.RawMessage(payload),
		}
	}
	at := now.Add(-10 * time.Minute)
	conn := func(proto, service string, port int, peer string, bytes int) string {
		return fmt.Sprintf(`{"id.orig_h":"10.77.0.23","id.orig_p":50000,"id.resp_h":%q,"id.resp_p":%d,"proto":%q,"service":%q,"orig_ip_bytes":%d,"resp_ip_bytes":0}`, peer, port, proto, service, bytes)
	}
	envelopes := []Envelope{
		event(SourceZeek, "zeek.conn", device, at, conn("tcp", "http", 80, "93.184.216.34", 1000)),
		event(SourceZeek, "zeek.conn", device, at, conn("tcp", "http", 80, "93.184.216.34", 500)),
		event(SourceZeek, "zeek.conn", device, at, conn("tcp", "", 23, "203.0.113.9", 200)),
		event(SourceZeek, "zeek.conn", device, at, conn("udp", "", 51820, "198.51.100.7", 4000)),
		event(SourceZeek, "zeek.conn", device, at, conn("tcp", "ssl", 443, "203.0.113.20", 9000)),
		event(SourceSuricata, "suricata.flow", device, at, `{"src_ip":"10.77.0.23","src_port":50000,"dest_ip":"203.0.113.20","dest_port":443,"proto":"TCP","app_proto":"tls","flow":{"bytes_toserver":100,"bytes_toclient":200}}`),
		event(SourceZeek, "zeek.dns", device, at, `{"query":"API.Example.com.","qtype_name":"A","rcode_name":"NOERROR","answers":["203.0.113.20"]}`),
		event(SourceZeek, "zeek.dns", device, at, `{"query":"log.samsungacr.com","qtype_name":"A","rcode_name":"NOERROR","answers":[]}`),
		event(SourceZeek, "zeek.ssl", device, at, `{"server_name":"legacy.example.com","version":"TLSv10","id.resp_h":"203.0.113.30"}`),
		event(SourceZeek, "zeek.ssl", device, at, `{"server_name":"api.example.com","version":"TLSv13"}`),
		event(SourceZeek, "zeek.http", device, at, `{"host":"plain.example.com:8080","status_code":200,"id.resp_h":"93.184.216.34"}`),
		event(SourceMitmproxy, "tls_intercepted", device, at, `{"sni":"secure.example.com","source_ip":"10.77.0.23","destination_ip":"203.0.113.40","destination_port":443,"protocol":"tcp","service":"tls"}`),
		event(SourceMitmproxy, "tls_interception_failed", device, at, `{"sni":"pinned.example.com","reason":"probable_certificate_pinning_or_custom_trust_store","destination_ip":"203.0.113.41"}`),
		event(SourceMitmproxy, "tls_interception_failed", device, at, `{"sni":"generic.example.com","reason":"ca_not_trusted_or_pinning","destination_ip":"203.0.113.42"}`),
		event(SourceMitmproxy, "http_request", device, at, `{"http_method":"GET","http_scheme":"https","http_host":"secure.example.com","http_path":"/v1"}`),
		event(SourceMitmproxy, "http_response", device, at, `{"http_method":"GET","http_scheme":"https","http_host":"secure.example.com","http_status":404}`),
		event(SourceMitmproxy, "encrypted_dns_detected", device, at, `{"hostname":"dns.google","dns_transport":"DOH","service":"doh","protocol":"tcp","destination_ip":"8.8.8.8","destination_port":443}`),
		event(SourceSuricata, "suricata.alert", device, at, `{"src_ip":"10.77.0.23","dest_ip":"203.0.113.9","alert":{"signature":"ET POLICY Telnet login","severity":1,"category":"Policy"}}`),
		// Postgres prints IPv4-compatible IPv6 as ::1.2.3.4; Go prints ::102:304.
		event(SourceZeek, "zeek.conn", device, at, `{"id.orig_h":"fd00::23","id.orig_p":50000,"id.resp_h":"::1.2.3.4","id.resp_p":31337,"proto":"udp","service":"","orig_ip_bytes":60,"resp_ip_bytes":0}`),
		event(SourceSuricata, "suricata.dns", device, at, `{"dns":{"type":"answer","rrname":"answer-only.example.com","rrtype":"A"}}`),
		// Out of scope: another device, and the right device outside the window.
		event(SourceZeek, "zeek.dns", other, at, `{"query":"other.example.com","qtype_name":"A"}`),
		// Another lab device opens Telnet to this device; it counts only when
		// the query carries the device's addresses.
		event(SourceZeek, "zeek.conn", other, at, `{"id.orig_h":"10.77.0.26","id.orig_p":50100,"id.resp_h":"10.77.0.23","id.resp_p":23,"proto":"tcp","service":"","orig_ip_bytes":400,"resp_ip_bytes":1200}`),
		event(SourceZeek, "zeek.dns", device, now.Add(-48*time.Hour), `{"query":"old.example.com","qtype_name":"A"}`),
	}
	spool := &Spool{Root: t.TempDir(), MaxBytes: 16 << 20, ReserveBytes: 1, Now: func() time.Time { return now }}
	for _, envelope := range envelopes {
		raw, err := json.Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
		if result, err := spool.Accept(raw); err != nil || !result.Accepted {
			t.Fatalf("seed event %s was not accepted: %#v err=%v", envelope.EventID, result, err)
		}
	}
	batch, err := spool.PendingBatch(100)
	if err != nil || len(batch) != len(envelopes) {
		t.Fatalf("seed batch=%d err=%v", len(batch), err)
	}
	if err := sink.WriteBatch(ctx, batch); err != nil {
		t.Fatal(err)
	}

	query := DeviceActivityQuery{DeviceID: device, Start: now.Add(-time.Hour), End: now.Add(time.Minute)}
	activity, err := sink.QueryDeviceActivity(ctx, query)
	if err != nil {
		t.Fatal(err)
	}
	counts := activity.Counts
	if counts.Events != 20 || counts.ZeekConnections != 6 || counts.ZeekConnectionBytes != 14760 || counts.SuricataFlows != 1 || counts.SuricataFlowBytes != 300 {
		t.Fatalf("unexpected connection counts: %#v", counts)
	}
	if counts.ZeekDNS != 2 || counts.ZeekTLS != 2 || counts.InterceptorTLS != 3 || counts.TLSIntercepted != 1 || counts.TLSFailed != 2 || counts.TLSPinningSuspected != 1 {
		t.Fatalf("unexpected DNS/TLS counts: %#v", counts)
	}
	if counts.InterceptorHTTPRequests != 2 || counts.InterceptorCleartextRequests != 0 || counts.ZeekHTTP != 1 || counts.Alerts != 1 || counts.EncryptedDNSDetections != 1 {
		t.Fatalf("unexpected HTTP/alert counts: %#v", counts)
	}
	domains := map[string]bool{}
	for _, item := range activity.Domains {
		domains[item.Source+":"+item.Domain] = true
	}
	for _, want := range []string{"dns:api.example.com", "dns:log.samsungacr.com", "tls:legacy.example.com", "tls:api.example.com", "tls:secure.example.com", "tls:pinned.example.com", "http:plain.example.com", "http:secure.example.com"} {
		if !domains[want] {
			t.Errorf("missing domain observation %s in %#v", want, activity.Domains)
		}
	}
	for _, unwanted := range []string{"dns:other.example.com", "dns:old.example.com"} {
		if domains[unwanted] {
			t.Errorf("domain %s leaked across device or window scope", unwanted)
		}
	}
	if domains["dns:answer-only.example.com"] {
		t.Fatal("a Suricata DNS answer record was counted as a lookup")
	}
	var sawTelnet, sawHTTP, sawWireGuard, sawMappedPeer bool
	for _, group := range activity.FlowGroups {
		switch {
		case group.Source == SourceZeek && group.ServerPort == 23:
			sawTelnet = group.Flows == 1 && group.SamplePeer == "203.0.113.9" && !group.Inbound
		case group.Source == SourceZeek && group.ServerPort == 80:
			sawHTTP = group.Flows == 2 && group.Bytes == 1500 && group.Service == "http"
		case group.Source == SourceZeek && group.ServerPort == 51820:
			sawWireGuard = group.Transport == "udp"
		case group.Source == SourceZeek && group.ServerPort == 31337:
			sawMappedPeer = group.SamplePeer == "::102:304"
		}
	}
	if !sawTelnet || !sawHTTP || !sawWireGuard || !sawMappedPeer {
		t.Fatalf("flow groups are incomplete: %#v", activity.FlowGroups)
	}
	pinned := false
	for _, host := range activity.TLSHosts {
		if host.Host == "pinned.example.com" && host.PinningSuspected && host.State == "FAILED" {
			pinned = true
		}
		if host.Host == "generic.example.com" && host.PinningSuspected {
			t.Fatalf("generic CA failure was reported as pinning: %#v", host)
		}
	}
	if !pinned {
		t.Fatalf("pinning host missing: %#v", activity.TLSHosts)
	}
	if len(activity.TLSVersions) != 1 || activity.TLSVersions[0].Version != "TLSv1.0" || activity.TLSVersions[0].Host != "legacy.example.com" {
		t.Fatalf("unexpected legacy TLS versions: %#v", activity.TLSVersions)
	}
	if len(activity.CleartextHTTP) != 1 || activity.CleartextHTTP[0].Host != "plain.example.com" || activity.CleartextHTTP[0].SampleAddress != "93.184.216.34" {
		t.Fatalf("unexpected cleartext HTTP: %#v", activity.CleartextHTTP)
	}
	statuses := map[string]int64{}
	for _, item := range activity.HTTPStatus {
		statuses[string(item.Source)+":"+item.Class] = item.Count
	}
	if statuses["ZEEK:2xx"] != 1 || statuses["MITMPROXY:4xx"] != 1 {
		t.Fatalf("unexpected HTTP status classes: %#v", activity.HTTPStatus)
	}
	if len(activity.Alerts) != 1 || activity.Alerts[0].Signature != "ET POLICY Telnet login" || activity.Alerts[0].Severity != "HIGH" {
		t.Fatalf("unexpected alerts: %#v", activity.Alerts)
	}
	if len(activity.EncryptedDNS) != 1 || activity.EncryptedDNS[0].Host != "dns.google" || activity.EncryptedDNS[0].Transport != "DOH" {
		t.Fatalf("unexpected encrypted DNS: %#v", activity.EncryptedDNS)
	}

	empty, err := sink.QueryDeviceActivity(ctx, DeviceActivityQuery{DeviceID: "device-00000000000000000000000000000000", Start: query.Start, End: query.End})
	if err != nil || empty.Counts.Events != 0 || len(empty.Domains) != 0 {
		t.Fatalf("unknown device returned activity: %#v err=%v", empty, err)
	}

	inboundGroup := func(activity DeviceActivity) (DeviceFlowGroup, bool) {
		for _, group := range activity.FlowGroups {
			if group.Inbound && group.ServerPort == 23 && group.SamplePeer == "10.77.0.26" {
				return group, true
			}
		}
		return DeviceFlowGroup{}, false
	}
	if _, ok := inboundGroup(activity); ok {
		t.Fatal("a connection attributed to another device was counted without the device's addresses")
	}
	query.Addresses = []string{"10.77.0.23"}
	withAddresses, err := sink.QueryDeviceActivity(ctx, query)
	if err != nil {
		t.Fatal(err)
	}
	if group, ok := inboundGroup(withAddresses); !ok || group.Flows != 1 || group.Peers != 1 {
		t.Fatalf("inbound Telnet from another lab device is missing: %#v", withAddresses.FlowGroups)
	}
	if withAddresses.Counts != activity.Counts {
		t.Fatalf("device addresses changed the device's own counts: %#v vs %#v", withAddresses.Counts, activity.Counts)
	}
}
