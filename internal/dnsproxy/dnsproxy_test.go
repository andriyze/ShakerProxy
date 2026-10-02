package dnsproxy

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/trafficpolicy"
)

const testDeviceID = "device-0123456789abcdef0123456789abcdef"

func queryFor(name string) []byte {
	message := make([]byte, 12)
	binary.BigEndian.PutUint16(message[0:2], 0x1234)
	binary.BigEndian.PutUint16(message[2:4], 0x0100)
	binary.BigEndian.PutUint16(message[4:6], 1)
	for _, label := range strings.Split(name, ".") {
		message = append(message, byte(len(label)))
		message = append(message, label...)
	}
	message = append(message, 0, 0, 1, 0, 1)
	return message
}

func rcode(response []byte) uint16 { return binary.BigEndian.Uint16(response[2:4]) & 0xf }

func TestQuestionNameServfailAndNXDOMAIN(t *testing.T) {
	query := queryFor("api.example.com")
	name, err := QuestionName(query)
	if err != nil || name != "api.example.com" {
		t.Fatalf("unexpected name: %q %v", name, err)
	}
	if response := servfail(query); !validResponse(query, response) || rcode(response) != 2 {
		t.Fatalf("invalid SERVFAIL response: %x", response)
	}
	response := nxdomain(query)
	if !validResponse(query, response) || rcode(response) != 3 || binary.BigEndian.Uint16(response[4:6]) != 1 || binary.BigEndian.Uint16(response[6:8]) != 0 {
		t.Fatalf("invalid NXDOMAIN response: %x", response)
	}
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Duration(len(data)) * time.Millisecond)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
}

// Regression for "force plain DNS breaks all DNS": the forwarder must read the
// exact bytes the gateway writes for an ENFORCE_LOCAL policy.
func TestFilePolicyProviderReadsGatewayRuntimeProjection(t *testing.T) {
	policy := trafficpolicy.DefaultPolicy()
	policy.Revision = 4
	policy.Name = "Force plain DNS"
	policy.EncryptedDNS.Mode = trafficpolicy.EncryptedDNSEnforceLocal
	policy.EncryptedDNS.RedirectPlainDNS = true
	policy.EncryptedDNS.UpstreamServers = []string{"192.0.2.53:53", "198.51.100.53:53"}
	policy.TLS.Enabled = true
	policy.TLS.SelectedDeviceIDs = []string{testDeviceID}
	policy.DeviceControls = []trafficpolicy.DeviceControl{{DeviceID: testDeviceID, HardwareAddresses: []string{"AA-BB-CC-DD-EE-01"}, BlockedDomains: []string{"*.Tracker.Example."}}}
	runtime, err := trafficpolicy.ProjectStandaloneProxyRuntimeWithIdentity(policy, trafficpolicy.EmptyStandaloneDeviceRuntime(), map[string]trafficpolicy.DeviceMatch{testDeviceID: {IPv4: []string{"10.77.0.23"}}})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := trafficpolicy.EncodeStandaloneProxyRuntime(runtime)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "aa:bb:cc") {
		t.Fatal("hardware addresses leaked into the shared runtime document")
	}
	path := filepath.Join(t.TempDir(), "policy.json")
	writeFile(t, path, encoded)
	provider := &FilePolicyProvider{Path: path, ResolvConfPaths: []string{filepath.Join(t.TempDir(), "absent")}}
	parsed, err := provider.Runtime()
	if err != nil {
		t.Fatalf("forwarder rejected the gateway runtime projection: %v", err)
	}
	if parsed.HostResolver || len(parsed.Upstreams) != 2 || parsed.Upstreams[0] != "192.0.2.53:53" || parsed.Revision != 4 {
		t.Fatalf("unexpected runtime: %#v", parsed)
	}
	if _, domain, blocked := parsed.Blocked(netip.MustParseAddr("10.77.0.23"), "cdn.tracker.example"); !blocked || domain != "tracker.example" {
		t.Fatal("subdomain of a blocked domain was not blocked for the device")
	}
	if _, _, blocked := parsed.Blocked(netip.MustParseAddr("10.77.0.24"), "tracker.example"); blocked {
		t.Fatal("domain block leaked to another client")
	}
	if _, _, blocked := parsed.Blocked(netip.MustParseAddr("10.77.0.23"), "nottracker.example"); blocked {
		t.Fatal("suffix match crossed a label boundary")
	}
}

func TestFilePolicyProviderFallsBackToHostResolver(t *testing.T) {
	root := t.TempDir()
	resolv := filepath.Join(root, "resolv.conf")
	writeFile(t, resolv, []byte("# generated\nnameserver 127.0.0.53\nnameserver fe80::1%eth0\noptions edns0\n"))
	// Fleet snapshot: compiled schema, redirect on, no upstreams, unknown fields.
	fleet := `{"schema_version":1,"policy_id":"fleet-1","revision":9,"digest":"x","enabled":true,
	  "tls":{"mode":"off"},"encrypted_dns":{"mode":"strict","redirect_plain_dns":true,"future_field":1},
	  "resolver_hostnames":[],"device_by_ip":{"10.0.0.2":"fleet-device"},"generated_at":"2026-09-29T00:00:00Z"}`
	path := filepath.Join(root, "policy.json")
	writeFile(t, path, []byte(fleet))
	provider := &FilePolicyProvider{Path: path, ResolvConfPaths: []string{filepath.Join(root, "absent"), resolv}}
	runtime, err := provider.Runtime()
	if err != nil {
		t.Fatal(err)
	}
	if !runtime.HostResolver || len(runtime.Upstreams) != 1 || runtime.Upstreams[0] != "127.0.0.53:53" {
		t.Fatalf("host resolver fallback not used: %#v", runtime)
	}
	provider = &FilePolicyProvider{Path: path, FallbackUpstreams: []string{"192.0.2.1:53"}}
	runtime, err = provider.Runtime()
	if err != nil || runtime.Upstreams[0] != "192.0.2.1:53" {
		t.Fatalf("configured fallback not used: %#v %v", runtime, err)
	}
}

func TestFilePolicyProviderLegacyPolicyAndRejections(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "policy.json")
	policy := trafficpolicy.DefaultPolicy()
	policy.EncryptedDNS.Mode = trafficpolicy.EncryptedDNSEnforceLocal
	policy.EncryptedDNS.RedirectPlainDNS = true
	policy.EncryptedDNS.UpstreamServers = []string{"192.0.2.53:53"}
	encoded, _ := json.Marshal(policy)
	writeFile(t, path, encoded)
	runtime, err := (&FilePolicyProvider{Path: path}).Runtime()
	if err != nil || runtime.Upstreams[0] != "192.0.2.53:53" {
		t.Fatalf("legacy standalone policy rejected: %#v %v", runtime, err)
	}
	// The netlab DNS proof feeds the daemon this legacy fixture.
	fixture, err := os.ReadFile(filepath.Join("..", "..", "tests", "netlab", "fixtures", "dns-policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	if runtime, err := ParseRuntime(fixture); err != nil || len(runtime.Upstreams) != 1 || runtime.Upstreams[0] != "10.81.0.53:53" {
		t.Fatalf("netlab fixture rejected: %#v %v", runtime, err)
	}
	for name, document := range map[string]string{
		"both schemas":      `{"schema":1,"schema_version":1,"encrypted_dns":{}}`,
		"no schema":         `{"encrypted_dns":{}}`,
		"no dns section":    `{"schema_version":1}`,
		"loopback upstream": `{"schema_version":1,"encrypted_dns":{"upstream_servers":["127.0.0.1:53"]}}`,
		"non-53 upstream":   `{"schema_version":1,"encrypted_dns":{"upstream_servers":["192.0.2.1:5353"]}}`,
		"bad block":         `{"schema_version":1,"encrypted_dns":{"blocked_domains":{"device-x":["a.example"]}}}`,
		"trailing":          `{"schema_version":1,"encrypted_dns":{}} {}`,
	} {
		if _, err := ParseRuntime([]byte(document)); err == nil {
			t.Fatalf("%s: invalid runtime accepted", name)
		}
	}
}

type staticProvider struct{ runtime *Runtime }

func (p staticProvider) Runtime() (*Runtime, error) { return p.runtime, nil }

func startUpstream(t *testing.T, answer bool) string {
	t.Helper()
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		buffer := make([]byte, maximumDNSMessage)
		for {
			n, peer, readErr := listener.ReadFrom(buffer)
			if readErr != nil {
				return
			}
			if !answer {
				continue
			}
			response := append([]byte(nil), buffer[:n]...)
			binary.BigEndian.PutUint16(response[2:4], binary.BigEndian.Uint16(response[2:4])|0x8080)
			_, _ = listener.WriteTo(response, peer)
		}
	}()
	return listener.LocalAddr().String()
}

func startServer(t *testing.T, server *Server) net.Addr {
	t.Helper()
	server.Bind = "127.0.0.1:0"
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan [2]net.Addr, 1)
	done := make(chan error, 1)
	go func() { done <- server.serve(ctx, ready) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	select {
	case addresses := <-ready:
		return addresses[0]
	case err := <-done:
		t.Fatal(err)
	}
	return nil
}

func ask(t *testing.T, server net.Addr, name string) []byte {
	t.Helper()
	connection, err := net.Dial("udp", server.String())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := connection.Write(queryFor(name)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, maximumDNSMessage)
	n, err := connection.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	return buffer[:n]
}

func TestServerBlocksDomainsPerDeviceAndForwardsOthers(t *testing.T) {
	upstream := startUpstream(t, true)
	runtime, err := ParseRuntime([]byte(`{"schema_version":1,"encrypted_dns":{"redirect_plain_dns":true,"blocked_domains":{"` + testDeviceID + `":["blocked.example"]}},"device_by_ip":{"127.0.0.1":"` + testDeviceID + `"}}`))
	if err != nil {
		t.Fatal(err)
	}
	runtime.Upstreams = []string{upstream}
	address := startServer(t, &Server{Provider: staticProvider{runtime}, Timeout: 2 * time.Second})
	if response := ask(t, address, "www.blocked.example"); rcode(response) != 3 {
		t.Fatalf("blocked subdomain was not NXDOMAIN: rcode %d", rcode(response))
	}
	if response := ask(t, address, "allowed.example"); rcode(response) != 0 {
		t.Fatalf("allowed name was not forwarded: rcode %d", rcode(response))
	}
}

func TestServerHedgesPastSilentUpstreamAndMarksItDown(t *testing.T) {
	silent := startUpstream(t, false)
	healthy := startUpstream(t, true)
	server := &Server{Provider: staticProvider{&Runtime{Upstreams: []string{silent, healthy}}}, Timeout: 3 * time.Second, HedgeDelay: 100 * time.Millisecond}
	started := time.Now()
	response, err := server.forward(context.Background(), "udp", queryFor("example.com"), []string{silent, healthy})
	if err != nil || rcode(response) != 0 {
		t.Fatalf("hedged exchange failed: %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("silent first upstream still cost %s", elapsed)
	}
	server.health.down(silent, time.Now())
	if order := server.health.order([]string{silent, healthy}, 0, time.Now()); order[0] != healthy {
		t.Fatalf("down upstream was not ordered last: %v", order)
	}
}

func closedUDPPort(t *testing.T) string {
	t.Helper()
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.LocalAddr().String()
	_ = listener.Close()
	return address
}

func TestServerTriesEveryUpstreamWhenEarlyOnesFail(t *testing.T) {
	healthy := startUpstream(t, true)
	upstreams := []string{closedUDPPort(t), closedUDPPort(t), closedUDPPort(t), healthy}
	server := &Server{Provider: staticProvider{&Runtime{Upstreams: upstreams}}, Timeout: 3 * time.Second, HedgeDelay: time.Second}
	response, err := server.forward(context.Background(), "udp", queryFor("example.com"), upstreams)
	if err != nil || rcode(response) != 0 {
		t.Fatalf("fourth upstream was never tried: %v", err)
	}
}

func TestServerIgnoresClientsOutsideTheLab(t *testing.T) {
	upstream := startUpstream(t, true)
	runtime, err := ParseRuntime([]byte(`{"schema_version":1,"encrypted_dns":{},"lab_sources":["2001:db8:1::/64"]}`))
	if err != nil {
		t.Fatal(err)
	}
	runtime.Upstreams = []string{upstream}
	server := &Server{Provider: staticProvider{runtime}, Timeout: 2 * time.Second}
	query := queryFor("example.com")
	for _, client := range []string{"8.8.8.8", "2001:db8:2::5", "::ffff:198.51.100.1"} {
		if response, _ := server.answer(context.Background(), "udp", query, netip.MustParseAddr(client)); response != nil {
			t.Fatalf("answered a query from %s", client)
		}
	}
	for _, client := range []string{"127.0.0.1", "10.77.0.23", "fd12::5", "fe80::1", "100.64.1.1", "2001:db8:1::5"} {
		if response, _ := server.answer(context.Background(), "udp", query, netip.MustParseAddr(client)); response == nil || rcode(response) != 0 {
			t.Fatalf("refused a lab client %s", client)
		}
	}
}

// The default bind is a wildcard so IPv6 lab clients (RDNSS points them at
// the lab IPv6 gateway) are answered too.
func TestWildcardBindAnswersIPv4AndIPv6(t *testing.T) {
	if probe, err := net.ListenPacket("udp", "[::1]:0"); err != nil {
		t.Skip("IPv6 loopback is unavailable")
	} else {
		_ = probe.Close()
	}
	upstream := startUpstream(t, true)
	server := &Server{Bind: ":0", Provider: staticProvider{&Runtime{Upstreams: []string{upstream}}}, Timeout: 2 * time.Second}
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan [2]net.Addr, 1)
	done := make(chan error, 1)
	go func() { done <- server.serve(ctx, ready) }()
	defer func() {
		cancel()
		<-done
	}()
	var bound net.Addr
	select {
	case addresses := <-ready:
		bound = addresses[0]
	case err := <-done:
		t.Fatal(err)
	}
	port := bound.(*net.UDPAddr).Port
	for _, host := range []string{"127.0.0.1", "::1"} {
		address := &net.UDPAddr{IP: net.ParseIP(host), Port: port}
		if response := ask(t, address, "example.com"); rcode(response) != 0 {
			t.Fatalf("no answer over %s", host)
		}
	}
}

func TestUDPExchangePreservesTransaction(t *testing.T) {
	upstream := startUpstream(t, true)
	query := queryFor("example.com")
	response, err := exchangeDNS(context.Background(), "udp", upstream, query)
	if err != nil || !validResponse(query, response) {
		t.Fatalf("exchange failed: %v %x", err, response)
	}
}
