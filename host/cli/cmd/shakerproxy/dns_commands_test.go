package main

import (
	"strings"
	"testing"
)

const dnsVisibilityOn = `{"schema":1,"policy_revision":2,"force_plain_dns":true,"block_encrypted_dns":true,"mode":"ENFORCE_LOCAL","upstream_servers":[],
 "blocked_resolvers":[{"id":"cloudflare","provider":"Cloudflare Public DNS","hostnames":["cloudflare-dns.com"],"ipv4":["1.1.1.1"],"ipv6":[]},{"id":"google","provider":"Google Public DNS","hostnames":["dns.google"],"ipv4":["8.8.8.8"],"ipv6":[]}],
 "blocked_addresses":2,"blocked_names":["cloudflare-dns.com","dns.google","use-application-dns.net"],"canaries":["use-application-dns.net"],
 "notes":["Android Private DNS set to a specific provider (strict) will lose internet while this is on: set Private DNS to Automatic or Off."]}`

func TestDNSShowsAndChangesTheVisibilitySwitches(t *testing.T) {
	api := newFakeAPI(t)
	api.json("GET /api/v1/dns-visibility", 200, dnsVisibilityOn)
	api.json("PUT /api/v1/dns-visibility", 200, strings.Replace(strings.Replace(dnsVisibilityOn, `"block_encrypted_dns":true`, `"block_encrypted_dns":false`, 1), `"policy_revision":2`, `"policy_revision":3`, 1))
	c, _, _ := testCLI()
	code, stdout, stderr := runCLI(t, c, "dns")
	if code != exitOK || !strings.Contains(stdout, "Force plain DNS through ShakerProxy") || !strings.Contains(stdout, "Block encrypted DNS") || !strings.Contains(stdout, "2 resolver addresses blocked (Cloudflare Public DNS, Google Public DNS)") || !strings.Contains(stdout, "Android Private DNS") || !strings.Contains(stdout, "this host's DNS servers") {
		t.Fatalf("dns status: %d\n%s\n%s", code, stdout, stderr)
	}
	code, stdout, stderr = runCLI(t, c, "dns", "block-encrypted", "off")
	if code != exitOK || strings.Contains(stdout, "resolver addresses blocked") {
		t.Fatalf("dns block-encrypted off: %d\n%s\n%s", code, stdout, stderr)
	}
	puts := api.find("PUT", "/api/v1/dns-visibility")
	if len(puts) != 1 || string(puts[0].Body) != `{"block_encrypted_dns":false}` {
		t.Fatalf("PUT body = %v", puts)
	}
	code, _, stderr = runCLI(t, c, "dns", "enforce", "maybe")
	if code == exitOK || !strings.Contains(stderr, "not on or off") {
		t.Fatalf("bad value: %d %s", code, stderr)
	}
	code, stdout, _ = runCLI(t, c, "dns", "--json")
	if code != exitOK || !strings.Contains(strings.ReplaceAll(stdout, " ", ""), `"force_plain_dns":true`) {
		t.Fatalf("dns --json: %d %s", code, stdout)
	}
}
