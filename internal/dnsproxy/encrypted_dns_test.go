package dnsproxy

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/trafficpolicy"
)

// defaultRuntime is the forwarder's view of the default visibility policy,
// encoded and parsed exactly as the gateway and dnsd do.
func defaultRuntime(t *testing.T) *Runtime {
	t.Helper()
	projected, err := trafficpolicy.ProjectStandaloneProxyRuntimeWithDevices(trafficpolicy.BlockingPolicy(), trafficpolicy.EmptyStandaloneDeviceRuntime())
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := trafficpolicy.EncodeStandaloneProxyRuntime(projected)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := ParseRuntime(encoded)
	if err != nil {
		t.Fatalf("forwarder rejected the default runtime: %v", err)
	}
	return runtime
}

func TestEncryptedDNSNamesAndCanariesAreRefused(t *testing.T) {
	runtime := defaultRuntime(t)
	for name, want := range map[string]string{
		"dns.google":                 trafficpolicy.BlockReasonDoHName,
		"mozilla.cloudflare-dns.com": trafficpolicy.BlockReasonDoHName,
		"chrome.cloudflare-dns.com":  trafficpolicy.BlockReasonDoHName,
		"one.one.one.one":            trafficpolicy.BlockReasonDoHName,
		"abc123.dns.nextdns.io":      trafficpolicy.BlockReasonDoHName,
		"doh.opendns.com":            trafficpolicy.BlockReasonDoHName,
		"use-application-dns.net":    trafficpolicy.BlockReasonCanary,
		"mask.icloud.com":            trafficpolicy.BlockReasonCanary,
		"mask-h2.icloud.com":         trafficpolicy.BlockReasonCanary,
	} {
		if _, reason, blocked := runtime.BlockedResolverName(name); !blocked || reason != want {
			t.Fatalf("%s: blocked=%v reason=%q, want %q", name, blocked, reason, want)
		}
	}
	for _, name := range []string{"www.google.com", "google.com", "icloud.com", "www.icloud.com", "cloudflare.com", "example.com"} {
		if refused, _, blocked := runtime.BlockedResolverName(name); blocked {
			t.Fatalf("%s was refused as %s", name, refused)
		}
	}
	off, err := ParseRuntime([]byte(`{"schema_version":1,"encrypted_dns":{"mode":"observe"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, blocked := off.BlockedResolverName("dns.google"); blocked {
		t.Fatal("a runtime without encrypted-DNS blocking refused a resolver name")
	}
}

func TestTheForwarderAnswersNXDOMAINForDoHNamesAndRecordsWhy(t *testing.T) {
	upstream := startUpstream(t, true)
	runtime := defaultRuntime(t)
	runtime.Upstreams = []string{upstream}
	observed := &collector{}
	address := startServer(t, &Server{Provider: staticProvider{runtime}, Timeout: 2 * time.Second, Observer: observed})
	if response := ask(t, address, "dns.google"); rcode(response) != 3 {
		t.Fatalf("dns.google was not refused: rcode %d", rcode(response))
	}
	if response := ask(t, address, "use-application-dns.net"); rcode(response) != 3 {
		t.Fatalf("the Firefox canary was not refused: rcode %d", rcode(response))
	}
	if response := ask(t, address, "www.google.com"); rcode(response) != 0 {
		t.Fatalf("an ordinary name was not forwarded: rcode %d", rcode(response))
	}
	lookups := observed.wait(t, 3)
	if !lookups[0].Blocked || lookups[0].BlockedReason != trafficpolicy.BlockReasonDoHName || lookups[0].BlockedDomain != "dns.google" {
		t.Fatalf("DoH name lookup = %+v", lookups[0])
	}
	if !lookups[1].Blocked || lookups[1].BlockedReason != trafficpolicy.BlockReasonCanary {
		t.Fatalf("canary lookup = %+v", lookups[1])
	}
	if lookups[2].Blocked || lookups[2].BlockedReason != "" {
		t.Fatalf("forwarded lookup = %+v", lookups[2])
	}
	encoded, err := LookupEvent("evt_00000000000000000001_00000001_000000000000", lookups[1])
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Payload map[string]any `json:"payload"`
	}
	if err := json.Unmarshal(encoded, &envelope); err != nil || envelope.Payload["blocked"] != true || envelope.Payload["blocked_reason"] != trafficpolicy.BlockReasonCanary {
		t.Fatalf("event = %s err=%v", encoded, err)
	}
	if !strings.Contains(string(encoded), `"blocked_domain":"use-application-dns.net"`) {
		t.Fatalf("event lacks the refused name: %s", encoded)
	}
}
