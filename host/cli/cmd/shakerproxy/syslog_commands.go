package main

import (
	"encoding/json"
	"net/http"
	"strings"
)

// syslogCollector mirrors GET/PUT /api/v1/integrations/syslog-collector.
type syslogCollector struct {
	Available      bool     `json:"available"`
	Enabled        bool     `json:"enabled"`
	BindAddress    string   `json:"bind_address"`
	TCP            bool     `json:"tcp"`
	UDP            bool     `json:"udp"`
	AllowedSources []string `json:"allowed_sources"`
	Revision       int      `json:"revision"`
	UpdatedBy      string   `json:"updated_by"`
	Setup          string   `json:"setup"`
	Status         *struct {
		Received  uint64 `json:"received"`
		Parsed    uint64 `json:"parsed"`
		Unparsed  uint64 `json:"unparsed"`
		Delivered uint64 `json:"delivered"`
		Dropped   uint64 `json:"dropped_rate_limited"`
		Rejected  uint64 `json:"rejected_not_allowed"`
	} `json:"status"`
}

func (c *cli) syslogCommand(args []string) error {
	flags := newFlags("syslog")
	bind := flags.String("bind", "", "listen address host:port (default :1514)")
	sources := flags.String("sources", "", "comma-separated device IPs to accept (the router's address)")
	udp := flags.Bool("udp", false, "also accept UDP (spoofable; prefer TCP)")
	passwordFile := flags.String("password-file", "", "administrator password file")
	user := flags.String("user", "admin", "administrator username")
	positional, err := parseFlags("syslog", flags, args)
	if err != nil {
		return err
	}
	if len(positional) == 0 {
		positional = []string{"status"}
	}
	action := strings.ToLower(positional[0])
	switch action {
	case "status", "show":
		if err := expectArgs("syslog", positional, 1, 1); err != nil {
			return err
		}
		return c.syslogStatus()
	case "enable", "on", "disable", "off":
		if err := expectArgs("syslog", positional, 1, 1, action); err != nil {
			return err
		}
		enable := action == "enable" || action == "on"
		return c.syslogSetEnabled(enable, *bind, *sources, *udp, *passwordFile, *user)
	default:
		return usagef("syslog", "Use `shakerproxy syslog status`, `shakerproxy syslog enable --sources <router IP>` or `shakerproxy syslog disable`.")
	}
}

func (c *cli) syslogStatus() error {
	session, err := c.openAPI()
	if err != nil {
		return err
	}
	defer session.close()
	var view syslogCollector
	raw, err := session.getJSON("/api/v1/integrations/syslog-collector", &view)
	if err != nil {
		return err
	}
	if c.jsonOutput {
		return c.printRawJSON(raw)
	}
	c.renderSyslog(view)
	return nil
}

func (c *cli) syslogSetEnabled(enable bool, bind, sources string, udp bool, passwordFile, user string) error {
	prompt := "Admin password (to disable the log collector): "
	if enable {
		prompt = "Admin password (to enable the log collector): "
	}
	password, err := c.obtainPassword(passwordFile, false, prompt)
	if err != nil {
		return err
	}
	admin, err := c.adminSession(user, password)
	if err != nil {
		return err
	}
	defer admin.close()
	var current syslogCollector
	if _, err := admin.getJSON("/api/v1/integrations/syslog-collector", &current); err != nil {
		return err
	}
	allowed := current.AllowedSources
	if trimmed := strings.TrimSpace(sources); trimmed != "" {
		allowed = splitSources(trimmed)
	}
	bindAddress := current.BindAddress
	if strings.TrimSpace(bind) != "" {
		bindAddress = strings.TrimSpace(bind)
	}
	payload := map[string]any{
		"enabled":           enable,
		"bind_address":      bindAddress,
		"tcp":               true,
		"udp":               udp || current.UDP,
		"allowed_sources":   allowed,
		"expected_revision": current.Revision,
		"password":          password,
	}
	raw, err := admin.do(http.MethodPut, "/api/v1/integrations/syslog-collector", payload)
	if err != nil {
		return err
	}
	var view syslogCollector
	if err := json.Unmarshal(raw, &view); err != nil {
		return err
	}
	if c.jsonOutput {
		return c.printRawJSON(raw)
	}
	c.renderSyslog(view)
	return nil
}

func (c *cli) renderSyslog(view syslogCollector) {
	state := c.style(styleYellow, "off")
	if view.Enabled {
		state = c.style(styleGreen, "on")
	}
	c.printf("Network-gear log collector  %s\n", state)
	c.printf("  Listening on %s (%s)\n", sanitize(view.BindAddress), transportLabel(view.TCP, view.UDP))
	if len(view.AllowedSources) == 0 {
		c.printf("  Allowed sources: %s\n", c.style(styleYellow, "none set — add the router's IP with --sources"))
	} else {
		c.printf("  Allowed sources: %s\n", sanitize(strings.Join(view.AllowedSources, ", ")))
	}
	if view.Status != nil {
		c.printf("  Received %d · parsed %d · unparsed %d · delivered %d · dropped %d · rejected %d\n",
			view.Status.Received, view.Status.Parsed, view.Status.Unparsed, view.Status.Delivered, view.Status.Dropped, view.Status.Rejected)
	}
	if !view.Enabled && view.Setup != "" {
		c.printf("  %s %s\n", c.dim("•"), sanitize(view.Setup))
	}
}

func transportLabel(tcp, udp bool) string {
	switch {
	case tcp && udp:
		return "TCP and UDP"
	case udp:
		return "UDP"
	default:
		return "TCP"
	}
}

func splitSources(value string) []string {
	parts := strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ' ' })
	sources := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			sources = append(sources, part)
		}
	}
	return sources
}
