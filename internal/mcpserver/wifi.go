package mcpserver

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"shakerproxy.dev/shakerproxy/internal/agentapi"
	"shakerproxy.dev/shakerproxy/internal/ingest"
	"shakerproxy.dev/shakerproxy/internal/wifi"
)

type WiFiActivityArgs struct {
	Device string `json:"device,omitempty" jsonschema:"friendly name, IP address, MAC address or device ID; omit for the whole lab"`
	Window string `json:"window,omitempty" jsonschema:"5m, 15m, 1h, 6h, 24h (default), 7d or 30d"`
}

type wifiNetwork struct {
	SSID     string    `json:"ssid"`
	Searches int       `json:"searches"`
	LastSeen time.Time `json:"last_seen"`
}

type wifiConnection struct {
	Time      time.Time `json:"time"`
	Device    string    `json:"device,omitempty"`
	Summary   string    `json:"summary"`
	SSID      string    `json:"ssid,omitempty"`
	BSSID     string    `json:"bssid,omitempty"`
	ClientMAC string    `json:"client_mac,omitempty"`
}

type wifiAddress struct {
	MAC        string    `json:"mac"`
	Randomized bool      `json:"randomized"`
	Possible   bool      `json:"possible_match,omitempty"`
	LastSeen   time.Time `json:"last_seen"`
}

type wifiActivityResult struct {
	Summary string `json:"summary"`
	// Monitoring says whether ShakerProxy listens on the radio now.
	Monitoring string `json:"monitoring"`
	Query      string `json:"query"`
	// SearchedFor are the networks the device looked for by name (probe
	// requests): often its saved networks, so where it has been.
	SearchedFor []wifiNetwork    `json:"searched_for"`
	Connections []wifiConnection `json:"connections"`
	Disconnects []wifiConnection `json:"disconnects"`
	Addresses   []wifiAddress    `json:"addresses"`
	Truncated   bool             `json:"truncated,omitempty"`
}

const wifiActivityPage = 100

func (s *Service) wifiActivity(ctx context.Context, _ *mcp.CallToolRequest, args WiFiActivityArgs) (*mcp.CallToolResult, any, error) {
	window, relative, err := searchWindow(args.Window)
	if err != nil {
		return nil, nil, err
	}
	monitoring := "Wi-Fi visibility status is unavailable."
	if view, err := s.backend.WiFiVisibility(ctx); err == nil {
		monitoring = wifiMonitoringLine(view)
	}
	parts := []string{"time:" + relative, "kind:" + ingest.HostWiFiKindPattern, "NOT kind:" + wifi.KindBeaconSummary}
	scope := "on the lab in the last " + windowNames[window]
	if strings.TrimSpace(args.Device) != "" {
		device, err := s.resolveDevice(ctx, args.Device)
		if err != nil {
			return nil, nil, err
		}
		parts = append(parts, "device.id:"+device.DeviceID)
		scope = "for " + device.FriendlyName + " in the last " + windowNames[window]
	}
	query := strings.Join(parts, " AND ")
	page, err := s.backend.TrafficSearch(ctx, agentapi.TrafficSearchRequest{Query: query, Limit: wifiActivityPage})
	if err != nil {
		return nil, nil, fmt.Errorf("read Wi-Fi activity: %w", err)
	}
	if err := checkPageBound(len(page.Events), wifiActivityPage); err != nil {
		return nil, nil, err
	}
	result := wifiActivityResult{Monitoring: monitoring, Query: query, SearchedFor: []wifiNetwork{}, Connections: []wifiConnection{}, Disconnects: []wifiConnection{}, Addresses: []wifiAddress{}, Truncated: page.NextCursor != ""}
	networks := map[string]*wifiNetwork{}
	addresses := map[string]*wifiAddress{}
	for _, event := range page.Events {
		fields := event.WiFi
		if fields == nil {
			continue
		}
		if fields.ClientMAC != "" {
			address, ok := addresses[fields.ClientMAC]
			if !ok {
				address = &wifiAddress{MAC: fields.ClientMAC, Randomized: fields.Randomized, Possible: fields.PossibleMAC != ""}
				addresses[fields.ClientMAC] = address
			}
			if event.OccurredAt.After(address.LastSeen) {
				address.LastSeen = event.OccurredAt
			}
		}
		line := wifiConnection{Time: event.OccurredAt, Device: event.DeviceFriendlyName, Summary: recentEventSummary(event), SSID: fields.SSID, BSSID: fields.BSSID, ClientMAC: fields.ClientMAC}
		switch event.Kind {
		case wifi.KindProbe:
			if fields.SSID == "" {
				continue
			}
			network, ok := networks[fields.SSID]
			if !ok {
				network = &wifiNetwork{SSID: fields.SSID}
				networks[fields.SSID] = network
			}
			network.Searches++
			if event.OccurredAt.After(network.LastSeen) {
				network.LastSeen = event.OccurredAt
			}
		case wifi.KindAssoc, wifi.KindAuth:
			result.Connections = append(result.Connections, line)
		case wifi.KindDeauth, wifi.KindDisassoc:
			result.Disconnects = append(result.Disconnects, line)
		}
	}
	for _, network := range networks {
		result.SearchedFor = append(result.SearchedFor, *network)
	}
	sort.Slice(result.SearchedFor, func(left, right int) bool {
		if result.SearchedFor[left].Searches != result.SearchedFor[right].Searches {
			return result.SearchedFor[left].Searches > result.SearchedFor[right].Searches
		}
		return result.SearchedFor[left].SSID < result.SearchedFor[right].SSID
	})
	for _, address := range addresses {
		result.Addresses = append(result.Addresses, *address)
	}
	sort.Slice(result.Addresses, func(left, right int) bool {
		return result.Addresses[left].LastSeen.After(result.Addresses[right].LastSeen)
	})
	result.Summary = fmt.Sprintf("%s %s: searched for %s, %s, %s, using %s.", "Wi-Fi activity", scope,
		countNoun(len(result.SearchedFor), "named network", "named networks"), countNoun(len(result.Connections), "join or authentication", "joins or authentications"),
		countNoun(len(result.Disconnects), "disconnect", "disconnects"), countNoun(len(result.Addresses), "hardware address", "hardware addresses"))
	if len(page.Events) == 0 {
		result.Summary = "No Wi-Fi activity " + scope + ". " + monitoring
	}
	if result.Truncated {
		result.Summary += " Only the newest 100 events were read; use search_traffic with the query for more."
	}
	return textResult(result)
}

func wifiMonitoringLine(view agentapi.WiFiVisibility) string {
	switch {
	case view.Active:
		where := fmt.Sprintf("channel %d", view.Channel)
		if view.ChannelMode == "hop" {
			where = "hopping across channels"
		}
		line := fmt.Sprintf("ShakerProxy is listening with %s (%s).", view.Adapter, where)
		if view.Settings.Nearby {
			line += " Nearby devices are recorded too (kept 24 hours)."
		}
		return line
	case view.Settings.Enabled:
		return boundText("Wi-Fi visibility is on but not running. "+view.Reason+" "+view.LastError, 400)
	case !view.Available:
		return boundText("Wi-Fi visibility is off and cannot run: "+view.Reason, 400)
	}
	return "Wi-Fi visibility is off; the tester can turn it on with `shakerproxy wifi on` or on the System page."
}
