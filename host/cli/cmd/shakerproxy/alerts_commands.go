package main

import (
	"fmt"
	"strings"
)

// notificationList mirrors GET /api/v1/notifications.
type notificationList struct {
	Unread        int `json:"unread"`
	Notifications []struct {
		CreatedAt string `json:"created_at"`
		Trigger   string `json:"trigger"`
		Severity  string `json:"severity"`
		Title     string `json:"title"`
		Body      string `json:"body"`
		Read      bool   `json:"read"`
		Subject   struct {
			DeviceName string `json:"device_name"`
			Host       string `json:"host"`
		} `json:"subject"`
	} `json:"notifications"`
}

func (c *cli) alertsCommand(args []string) error {
	flags := newFlags("alerts")
	positional, err := parseFlags("alerts", flags, args)
	if err != nil {
		return err
	}
	if len(positional) == 0 {
		positional = []string{"list"}
	}
	switch strings.ToLower(positional[0]) {
	case "list", "status", "show":
		if err := expectArgs("alerts", positional, 1, 1); err != nil {
			return err
		}
		return c.alertsList()
	default:
		return usagef("alerts", "Use `shakerproxy alerts` to list recent notifications. Configure channels and rules in the web UI under Integrations.")
	}
}

func (c *cli) alertsList() error {
	session, err := c.openAPI()
	if err != nil {
		return err
	}
	defer session.close()
	var list notificationList
	raw, err := session.getJSON("/api/v1/notifications?limit=50", &list)
	if err != nil {
		return err
	}
	if c.jsonOutput {
		return c.printRawJSON(raw)
	}
	if len(list.Notifications) == 0 {
		fmt.Fprintln(c.stdout, "No notifications. Turn on alerts in the web UI under Integrations.")
		return nil
	}
	fmt.Fprintf(c.stdout, "%d notification(s), %d unread\n\n", len(list.Notifications), list.Unread)
	for _, n := range list.Notifications {
		mark := " "
		if !n.Read {
			mark = "*"
		}
		fmt.Fprintf(c.stdout, "%s %-8s %-19s %s\n", mark, n.Severity, n.CreatedAt, n.Title)
		if n.Body != "" {
			fmt.Fprintf(c.stdout, "            %s\n", n.Body)
		}
	}
	return nil
}
