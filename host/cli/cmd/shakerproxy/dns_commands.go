package main

import (
	"encoding/json"
	"net/http"
	"strings"
)

// dnsVisibility mirrors GET/PUT /api/v1/dns-visibility.
type dnsVisibility struct {
	PolicyRevision    uint64   `json:"policy_revision"`
	ForcePlainDNS     bool     `json:"force_plain_dns"`
	BlockEncryptedDNS bool     `json:"block_encrypted_dns"`
	Mode              string   `json:"mode"`
	UpstreamServers   []string `json:"upstream_servers"`
	BlockedResolvers  []struct {
		Provider string `json:"provider"`
	} `json:"blocked_resolvers"`
	BlockedAddresses int      `json:"blocked_addresses"`
	BlockedNames     []string `json:"blocked_names"`
	Notes            []string `json:"notes"`
}

func (c *cli) dnsCommand(args []string) error {
	positional, err := parseFlags("dns", newFlags("dns"), args)
	if err != nil {
		return err
	}
	if len(positional) == 0 {
		positional = []string{"status"}
	}
	change := map[string]bool{}
	switch strings.ToLower(positional[0]) {
	case "status", "show":
		if err := expectArgs("dns", positional, 1, 1); err != nil {
			return err
		}
	case "enforce", "force", "force-plain":
		if err := expectArgs("dns", positional, 2, 2, "enforce", "on or off"); err != nil {
			return err
		}
		enabled, err := onOff("dns", positional[1])
		if err != nil {
			return err
		}
		change["force_plain_dns"] = enabled
	case "block-encrypted", "block-encrypted-dns", "block":
		if err := expectArgs("dns", positional, 2, 2, "block-encrypted", "on or off"); err != nil {
			return err
		}
		enabled, err := onOff("dns", positional[1])
		if err != nil {
			return err
		}
		change["block_encrypted_dns"] = enabled
	default:
		return usagef("dns", "Use `shakerproxy dns status`, `shakerproxy dns enforce on|off` or `shakerproxy dns block-encrypted on|off`.")
	}
	session, err := c.openAPI()
	if err != nil {
		return err
	}
	defer session.close()
	var view dnsVisibility
	var raw []byte
	if len(change) == 0 {
		raw, err = session.getJSON("/api/v1/dns-visibility", &view)
	} else {
		raw, err = session.do(http.MethodPut, "/api/v1/dns-visibility", change)
		if err == nil {
			err = json.Unmarshal(raw, &view)
		}
	}
	if err != nil {
		return err
	}
	if c.jsonOutput {
		return c.printRawJSON(raw)
	}
	onOffLabel := func(value bool) string {
		if value {
			return c.style(styleGreen, "on")
		}
		return c.style(styleYellow, "off")
	}
	c.printf("Force plain DNS through ShakerProxy  %s\n", onOffLabel(view.ForcePlainDNS))
	c.printf("Block encrypted DNS (DoH, DoT, DoQ)  %s\n", onOffLabel(view.BlockEncryptedDNS))
	if view.BlockEncryptedDNS {
		providers := []string{}
		for _, resolver := range view.BlockedResolvers {
			providers = append(providers, resolver.Provider)
		}
		c.printf("  %d resolver addresses blocked (%s)\n", view.BlockedAddresses, sanitize(strings.Join(providers, ", ")))
		c.printf("  %d resolver names answered with NXDOMAIN\n", len(view.BlockedNames))
	}
	upstream := "this host's DNS servers"
	if len(view.UpstreamServers) != 0 {
		upstream = strings.Join(view.UpstreamServers, ", ")
	}
	c.printf("Lookups are forwarded to %s.\n", sanitize(upstream))
	for _, note := range view.Notes {
		c.printf("  %s %s\n", c.dim("•"), sanitize(note))
	}
	return nil
}

func onOff(command, value string) (bool, error) {
	switch strings.ToLower(value) {
	case "on", "enable", "yes", "true":
		return true, nil
	case "off", "disable", "no", "false":
		return false, nil
	}
	return false, usagef(command, "%q is not on or off.", value)
}
