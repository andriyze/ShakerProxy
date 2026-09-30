// Command devdemo loads a small, realistic demo lab into the development stack
// so the dashboard, protocol discovery, device reports, and findings can be
// explored without a routed appliance or physical devices.
//
// It seeds six devices into the inventory and posts Zeek, Suricata, and
// mitmproxy events for them to ingestd. All external addresses use RFC 5737
// documentation ranges. Run it with `make dev-demo` after `make dev-observe`.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"shakerproxy.dev/shakerproxy/internal/inventory"
)

type demoDevice struct {
	key      string
	name     string
	hostname string
	mac      string
	address  string
	category string
	icon     string
	tags     []string
	caTrust  string
	activity func(*generator, demoDevice, time.Time)
}

const (
	gateway    = "10.77.0.1"
	broadcast  = "10.77.0.255"
	ssdpGroup  = "239.255.255.250"
	mdnsGroup  = "224.0.0.251"
	plcAddress = "10.77.0.30"
)

var devices = []demoDevice{
	{key: "tv", name: "Living room TV", hostname: "samsung-tv", mac: "8c:79:f5:10:20:21", address: "10.77.0.21", category: "tv", icon: "tv", tags: []string{"smart-tv", "demo"}, caTrust: inventory.CATrustNotInstalled, activity: smartTV},
	{key: "phone", name: "QA Android phone", hostname: "pixel-8", mac: "3c:28:6d:10:20:22", address: "10.77.0.22", category: "phone", icon: "phone", tags: []string{"android", "demo"}, caTrust: inventory.CATrustInstalled, activity: androidPhone},
	{key: "camera", name: "Entrance camera", hostname: "ipcam-entrance", mac: "44:19:b6:10:20:23", address: "10.77.0.23", category: "camera", icon: "camera", tags: []string{"iot", "demo"}, caTrust: inventory.CATrustNotInstalled, activity: ipCamera},
	{key: "plug", name: "Smart plug", hostname: "tuya-plug", mac: "d8:1f:12:10:20:24", address: "10.77.0.24", category: "appliance", icon: "appliance", tags: []string{"iot", "demo"}, activity: smartPlug},
	{key: "plc", name: "Line PLC gateway", hostname: "plc-gw", mac: "00:1d:9c:10:20:25", address: "10.77.0.25", category: "industrial", icon: "router", tags: []string{"ot", "demo"}, activity: plcGateway},
	{key: "laptop", name: "Engineer laptop", hostname: "qa-laptop", mac: "a4:83:e7:10:20:26", address: "10.77.0.26", category: "computer", icon: "computer", tags: []string{"demo"}, activity: engineerLaptop},
}

func main() {
	inventoryPath := flag.String("inventory", "", "inventory document path (inventory.json)")
	ingestURL := flag.String("ingest", "http://ingestd:8081", "ingestd base URL")
	tokenFile := flag.String("token-file", "", "file holding the ingest write token")
	minutes := flag.Int("minutes", 90, "how many minutes of history to generate (10-1440)")
	live := flag.Bool("live", false, "send one burst of current traffic instead of history, e.g. during a running test run")
	variant := flag.Int("variant", 1, "device behaviour to simulate: 1 is the baseline, 2 behaves like a newer firmware")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "Load a demo lab into the ShakerProxy development stack.\n\nUsage: devdemo --inventory PATH --token-file FILE [--ingest URL] [--minutes N | --live [--variant 2]]\n\nRun it through `make dev-demo` or `make dev-demo-live` after `make dev-observe`.")
		flag.PrintDefaults()
	}
	flag.Parse()
	if *inventoryPath == "" || *tokenFile == "" || *minutes < 10 || *minutes > 1440 || *variant < 1 || *variant > 2 {
		flag.Usage()
		os.Exit(2)
	}
	token, err := os.ReadFile(*tokenFile)
	if err != nil {
		fail("read ingest token", err)
	}
	now := time.Now().UTC()
	history := time.Duration(*minutes) * time.Minute

	ids, err := seedInventory(*inventoryPath, now, history)
	if err != nil {
		fail("seed device inventory", err)
	}

	gen := &generator{
		client:  &http.Client{Timeout: 10 * time.Second},
		base:    strings.TrimRight(*ingestURL, "/"),
		token:   strings.TrimSpace(string(token)),
		ids:     ids,
		random:  rand.New(rand.NewPCG(uint64(now.UnixNano()), 0x1ab6a7e)),
		perKind: map[string]int{},
		variant: *variant,
	}
	if *live {
		// One compressed burst ending just before now lands inside a test run
		// that was started beforehand.
		gen.compress, gen.origin = true, now.Add(-200*time.Millisecond)
		for _, device := range devices {
			device.activity(gen, device, gen.origin)
			if gen.err != nil {
				fail("post demo events", gen.err)
			}
		}
		fmt.Printf("Sent %d live events for %d demo devices (behaviour variant %d).\n", gen.sent, len(devices), *variant)
		return
	}
	cycles := *minutes / 10
	for cycle := 0; cycle < cycles; cycle++ {
		at := now.Add(-history).Add(time.Duration(cycle) * 10 * time.Minute)
		for _, device := range devices {
			device.activity(gen, device, at.Add(time.Duration(gen.random.IntN(60))*time.Second))
			if gen.err != nil {
				fail("post demo events", gen.err)
			}
		}
	}

	fmt.Printf("Loaded %d demo devices and %d events covering the last %d minutes.\n", len(devices), gen.sent, *minutes)
	for _, device := range devices {
		fmt.Printf("  %-18s %-14s %s\n", device.name, device.address, ids[device.key])
	}
	fmt.Println("Events appear within a few seconds. Open Devices, Protocols, or a device report to explore.")
}

// seedInventory registers the demo devices with DHCP evidence that covers the
// generated history, then applies names, categories, tags, and CA trust.
func seedInventory(path string, now time.Time, history time.Duration) (map[string]string, error) {
	clock := now
	store := &inventory.Store{Path: path, Now: func() time.Time { return clock }}
	leases := make([]inventory.DHCP4Lease, 0, len(devices))
	for _, device := range devices {
		leases = append(leases, inventory.DHCP4Lease{
			Address:       netip.MustParseAddr(device.address),
			HardwareAddr:  device.mac,
			Hostname:      device.hostname,
			ValidLifetime: history + 25*time.Hour,
			ExpiresAt:     now.Add(24 * time.Hour),
		})
	}
	snapshot, err := store.ReconcileDHCP4(leases)
	if err != nil {
		return nil, err
	}
	ids := map[string]string{}
	for _, device := range devices {
		for _, existing := range snapshot.Devices {
			for _, address := range existing.Addresses {
				if address.Address == device.address && address.Active {
					ids[device.key] = existing.ID
				}
			}
		}
		id := ids[device.key]
		if id == "" {
			return nil, fmt.Errorf("device %s was not created", device.name)
		}
		clock = clock.Add(time.Millisecond)
		metadata := inventory.DeviceMetadata{FriendlyName: device.name, Category: device.category, Icon: device.icon, Tags: device.tags, Location: "Demo lab"}
		if _, err := store.UpdateMetadata(id, "devdemo", operationID("metadata", id, now), metadata); err != nil && !errors.Is(err, inventory.ErrMutationRejected) {
			return nil, fmt.Errorf("label %s: %w", device.name, err)
		}
		if device.caTrust != "" {
			clock = clock.Add(time.Millisecond)
			if _, err := store.SetCATrust(id, "devdemo", operationID("catrust", id, now), device.caTrust); err != nil && !errors.Is(err, inventory.ErrMutationRejected) {
				return nil, fmt.Errorf("record CA trust for %s: %w", device.name, err)
			}
		}
	}
	return ids, nil
}

func operationID(kind, deviceID string, now time.Time) string {
	sum := sha256.Sum256([]byte(kind + "\x00" + deviceID + "\x00" + now.Format(time.RFC3339Nano)))
	return "devdemo-" + kind + "-" + hex.EncodeToString(sum[:12])
}

type generator struct {
	client  *http.Client
	base    string
	token   string
	ids     map[string]string
	random  *rand.Rand
	sent    int
	perKind map[string]int
	variant int
	// In live mode timestamps are compressed toward origin so a whole
	// activity burst lands within about a second of "now".
	compress bool
	origin   time.Time
	err      error
}

func (g *generator) t(at time.Time) time.Time {
	if !g.compress {
		return at
	}
	return g.origin.Add(at.Sub(g.origin) / 20)
}

func (g *generator) port() int { return 40000 + g.random.IntN(20000) }

func (g *generator) uid() string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	var b strings.Builder
	b.WriteByte('C')
	for range 17 {
		b.WriteByte(alphabet[g.random.IntN(len(alphabet))])
	}
	return b.String()
}

func zeekTS(at time.Time) float64 { return float64(at.UnixNano()) / 1e9 }

// conn posts a Zeek conn.log record and returns its uid so related logs can
// share it.
func (g *generator) conn(at time.Time, src, dst string, dport int, proto, service string, sent, received int) string {
	uid := g.uid()
	record := map[string]any{
		"_path": "conn", "ts": zeekTS(g.t(at)), "uid": uid,
		"id.orig_h": src, "id.orig_p": g.port(), "id.resp_h": dst, "id.resp_p": dport,
		"proto": proto, "duration": 0.2 + g.random.Float64()*4,
		"orig_bytes": sent, "resp_bytes": received,
		"orig_ip_bytes": sent + 200, "resp_ip_bytes": received + 200,
		"conn_state": "SF",
	}
	if service != "" {
		record["service"] = service
	}
	g.post("/v1/adapters/zeek", record)
	return uid
}

func (g *generator) dns(at time.Time, src, query string, answers ...string) {
	uid := g.conn(at, src, gateway, 53, "udp", "dns", 80, 160)
	g.post("/v1/adapters/zeek", map[string]any{
		"_path": "dns", "ts": zeekTS(g.t(at)), "uid": uid,
		"id.orig_h": src, "id.orig_p": g.port(), "id.resp_h": gateway, "id.resp_p": 53,
		"proto": "udp", "trans_id": g.random.IntN(65535), "query": query,
		"qtype_name": "A", "rcode_name": "NOERROR", "answers": answers,
	})
}

func (g *generator) tls(at time.Time, src, dst, serverName, version string, sent, received int) {
	uid := g.conn(at, src, dst, 443, "tcp", "ssl", sent, received)
	g.post("/v1/adapters/zeek", map[string]any{
		"_path": "ssl", "ts": zeekTS(g.t(at.Add(50 * time.Millisecond))), "uid": uid,
		"id.orig_h": src, "id.orig_p": g.port(), "id.resp_h": dst, "id.resp_p": 443,
		"version": version, "server_name": serverName, "established": true,
	})
}

func (g *generator) http(at time.Time, src, dst, host, method, uri string, status int) {
	uid := g.conn(at, src, dst, 80, "tcp", "http", 600, 2400)
	g.post("/v1/adapters/zeek", map[string]any{
		"_path": "http", "ts": zeekTS(g.t(at.Add(20 * time.Millisecond))), "uid": uid,
		"id.orig_h": src, "id.orig_p": g.port(), "id.resp_h": dst, "id.resp_p": 80,
		"host": host, "method": method, "uri": uri, "status_code": status,
		"request_body_len": 0, "response_body_len": 1800,
	})
}

func (g *generator) alert(at time.Time, src, dst string, dport int, signature, category string, severity int) {
	g.post("/v1/adapters/suricata", map[string]any{
		"timestamp":  g.t(at).Format("2006-01-02T15:04:05.000000-0700"),
		"flow_id":    g.random.Int64N(1 << 50),
		"event_type": "alert",
		"src_ip":     src, "src_port": g.port(), "dest_ip": dst, "dest_port": dport, "proto": "TCP",
		"alert": map[string]any{"action": "allowed", "gid": 1, "signature_id": 9000000 + g.random.IntN(999), "rev": 1, "signature": signature, "category": category, "severity": severity},
	})
}

// mitm posts a mitmproxy interception event the way the addon and forwarder
// deliver it.
func (g *generator) mitm(at time.Time, device demoDevice, kind string, payload map[string]any) {
	payload["source_ip"] = device.address
	payload["source_port"] = g.port()
	payload["protocol"] = "tcp"
	payload["device_id"] = g.ids[device.key]
	raw, _ := json.Marshal(payload)
	at = g.t(at)
	sum := sha256.Sum256(append([]byte(kind+"\x00"+at.Format(time.RFC3339Nano)+"\x00"), raw...))
	g.post("/v1/events", map[string]any{
		"schema": 1, "event_id": "evt_demo_" + hex.EncodeToString(sum[:16]), "source": "MITMPROXY",
		"kind": kind, "occurred_at": at.Format(time.RFC3339Nano),
		"source_version": "mitmproxy-12.2.3-demo", "parser_version": "shakerproxy-mitm-demo-1",
		"device_id": g.ids[device.key], "confidence": 100, "payload": json.RawMessage(raw),
	})
}

func (g *generator) post(path string, body any) {
	if g.err != nil {
		return
	}
	raw, err := json.Marshal(body)
	if err != nil {
		g.err = err
		return
	}
	request, err := http.NewRequest(http.MethodPost, g.base+path, bytes.NewReader(raw))
	if err != nil {
		g.err = err
		return
	}
	request.Header.Set("Authorization", "Bearer "+g.token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-ShakerProxy-Source-Version", "shakerproxy-demo-1")
	response, err := g.client.Do(request)
	if err != nil {
		g.err = fmt.Errorf("%s: %w (is `make dev-observe` running?)", path, err)
		return
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusAccepted && response.StatusCode != http.StatusOK {
		detail, _ := io.ReadAll(io.LimitReader(response.Body, 512))
		g.err = fmt.Errorf("%s returned %d: %s", path, response.StatusCode, strings.TrimSpace(string(detail)))
		return
	}
	g.sent++
}

func smartTV(g *generator, d demoDevice, at time.Time) {
	g.dns(at, d.address, "log-config.samsungacr.com", "203.0.113.11")
	g.tls(at.Add(time.Second), d.address, "203.0.113.11", "log-config.samsungacr.com", "TLSv12", 3200, 900)
	g.dns(at.Add(2*time.Second), d.address, "ad.doubleclick.net", "203.0.113.12")
	g.tls(at.Add(3*time.Second), d.address, "203.0.113.12", "ad.doubleclick.net", "TLSv13", 1400, 5200)
	g.conn(at.Add(4*time.Second), d.address, "203.0.113.13", 443, "udp", "quic,ssl", 90000, 2400000)
	g.conn(at.Add(5*time.Second), d.address, ssdpGroup, 1900, "udp", "", 420, 0)
	g.conn(at.Add(6*time.Second), d.address, mdnsGroup, 5353, "udp", "dns", 180, 0)
	if g.variant == 1 {
		g.http(at.Add(7*time.Second), d.address, "203.0.113.14", "otn.samsungcloudsolution.com", "GET", "/firmware/check", 200)
	}
	g.mitm(at.Add(8*time.Second), d, "tls_intercepted", map[string]any{"sni": "api.samsungcloud.com", "destination_ip": "203.0.113.15", "destination_port": 443, "service": "tls", "decrypted": true})
	g.mitm(at.Add(9*time.Second), d, "tls_interception_failed", map[string]any{"sni": "api.netflix.com", "destination_ip": "203.0.113.16", "destination_port": 443, "service": "tls", "reason": "probable_certificate_pinning_or_custom_trust_store", "platform": "android-tv"})
	if g.variant == 2 {
		// A newer firmware: an extra ad partner, DNS over TLS, and a
		// firmware check that moved to HTTPS.
		g.dns(at.Add(10*time.Second), d.address, "track.adpartner.example", "203.0.113.17")
		g.tls(at.Add(11*time.Second), d.address, "203.0.113.17", "track.adpartner.example", "TLSv13", 1800, 900)
		g.conn(at.Add(12*time.Second), d.address, "192.0.2.53", 853, "tcp", "ssl", 1100, 1900)
	}
}

func androidPhone(g *generator, d demoDevice, at time.Time) {
	g.dns(at, d.address, "app-measurement.com", "198.51.100.21")
	g.mitm(at.Add(time.Second), d, "tls_intercepted", map[string]any{"sni": "app-measurement.com", "destination_ip": "198.51.100.21", "destination_port": 443, "service": "tls", "decrypted": true, "platform": "android"})
	requestBytes, responseBytes := 1800+g.random.IntN(800), 300
	for _, kind := range []string{"http_request", "http_response"} {
		payload := map[string]any{
			"destination_ip": "198.51.100.21", "destination_port": 443, "service": "https", "hostname": "app-measurement.com",
			"http_method": "POST", "http_scheme": "https", "http_host": "app-measurement.com", "http_port": 443,
			"http_path": "/a", "http_version": "HTTP/2.0", "decrypted": true, "platform": "android",
			"http_url": "https://app-measurement.com/a", "http_url_truncated": false,
		}
		if kind == "http_response" {
			payload["http_status"] = 204
			payload["request_bytes"] = requestBytes
			payload["response_bytes"] = responseBytes
		}
		g.mitm(at.Add(1500*time.Millisecond), d, kind, payload)
	}
	g.dns(at.Add(2*time.Second), d.address, "graph.facebook.com", "198.51.100.22")
	g.tls(at.Add(3*time.Second), d.address, "198.51.100.22", "graph.facebook.com", "TLSv13", 2600, 7800)
	g.conn(at.Add(4*time.Second), d.address, "198.51.100.23", 5228, "tcp", "ssl", 900, 1200)
	g.conn(at.Add(5*time.Second), d.address, "192.0.2.53", 853, "tcp", "ssl", 1400, 2100)
	g.mitm(at.Add(6*time.Second), d, "tls_interception_failed", map[string]any{"sni": "mobile.bank.example", "destination_ip": "198.51.100.24", "destination_port": 443, "service": "tls", "reason": "probable_certificate_pinning_or_custom_trust_store", "platform": "android"})
}

func ipCamera(g *generator, d demoDevice, at time.Time) {
	g.dns(at, d.address, "mqtt.camvendor.example", "203.0.113.50")
	g.conn(at.Add(time.Second), d.address, "203.0.113.50", 1883, "tcp", "mqtt", 2200, 600)
	g.alert(at.Add(1100*time.Millisecond), d.address, "203.0.113.50", 1883, "SHAKERPROXY DEMO MQTT CONNECT with cleartext credentials", "Potential Corporate Privacy Violation", 1)
	g.tls(at.Add(2*time.Second), d.address, "203.0.113.51", "update.camvendor.example", "TLSv10", 900, 48000)
	g.mitm(at.Add(3*time.Second), d, "tls_intercepted", map[string]any{"sni": "cloud.camvendor.example", "destination_ip": "203.0.113.52", "destination_port": 443, "service": "tls", "decrypted": true})
	g.http(at.Add(4*time.Second), d.address, "203.0.113.53", "time.camvendor.example", "GET", "/ntp/sync", 200)
	g.conn(at.Add(5*time.Second), d.address, broadcast, 3702, "udp", "", 700, 0)
}

func smartPlug(g *generator, d demoDevice, at time.Time) {
	g.dns(at, d.address, "m1.tuyaus.com", "198.51.100.40")
	g.conn(at.Add(time.Second), d.address, "198.51.100.40", 8883, "tcp", "ssl", 1200, 800)
	g.conn(at.Add(2*time.Second), d.address, broadcast, 6667, "udp", "", 180, 0)
	g.conn(at.Add(3*time.Second), d.address, "198.51.100.41", 45321, "udp", "", 64000, 18000)
}

func plcGateway(g *generator, d demoDevice, at time.Time) {
	g.conn(at, d.address, plcAddress, 502, "tcp", "modbus", 1400, 1400)
	g.conn(at.Add(time.Second), d.address, broadcast, 47808, "udp", "", 300, 0)
	g.conn(at.Add(2*time.Second), d.address, plcAddress, 102, "tcp", "", 2200, 2600)
}

func engineerLaptop(g *generator, d demoDevice, at time.Time) {
	g.conn(at, d.address, "198.51.100.60", 51820, "udp", "", 120000, 480000)
	g.conn(at.Add(time.Second), d.address, "10.77.0.23", 23, "tcp", "", 400, 1200)
	g.conn(at.Add(2*time.Second), d.address, "10.77.0.23", 554, "tcp", "", 3000, 1800000)
	g.conn(at.Add(3*time.Second), d.address, "198.51.100.61", 22, "tcp", "ssh", 5000, 9000)
}

func fail(action string, err error) {
	fmt.Fprintf(os.Stderr, "devdemo: %s: %v\n", action, err)
	os.Exit(1)
}
