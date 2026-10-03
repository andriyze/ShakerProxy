package mcpserver

import (
	"context"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/agentapi"
)

func (f *fakeBackend) LabRouting(context.Context) (agentapi.LabRouting, error) {
	return f.labRouting, nil
}

// The owner's iPhone on the test VM's lab Wi-Fi: the agent must learn at
// once that its traffic never reached ShakerProxy, and why.
func TestLabRoutingPutsBypassingDevicesFirstWithTheFix(t *testing.T) {
	backend := newFakeBackend()
	now := time.Date(2026, 10, 2, 23, 52, 30, 0, time.UTC)
	backend.labRouting = agentapi.LabRouting{Schema: 1, GeneratedAt: now, Available: true, Topology: "SINGLE_ARM", Prefix: "192.168.10.0/24", SubnetMask: "255.255.255.0",
		ShakerProxyAddress: "192.168.10.177", RouterAddress: "192.168.10.1", ThresholdSeconds: 120, Devices: []agentapi.LabRoutingDevice{
			{Address: "192.168.10.201", Routing: "THROUGH_SHAKERPROXY", DisplayName: "Pixel", Since: now.Add(-time.Hour), LastSeen: now, Evidence: []string{"380 connections and lookups through ShakerProxy"}},
			{Address: "192.168.10.130", Routing: "BYPASSING", DisplayName: "iPhone", Since: now.Add(-4 * time.Minute), LastSeen: now, Evidence: []string{"no connections or DNS lookups through ShakerProxy"},
				Reason: "It got its address from your router's DHCP, so it uses the router (192.168.10.1) as its gateway, not ShakerProxy."},
		}}
	result, _, err := (&Service{backend: backend}).labRouting(context.Background(), nil, LabRoutingArgs{})
	if err != nil {
		t.Fatal(err)
	}
	var data labRoutingResult
	decodeToolResult(t, result, &data)
	if len(data.Devices) != 2 || data.Devices[0].Address != "192.168.10.130" || data.Devices[0].Title != "iPhone · 192.168.10.130" {
		t.Fatalf("devices = %+v", data.Devices)
	}
	for _, fragment := range []string{"1 device bypasses ShakerProxy: iPhone · 192.168.10.130", "uses the router (192.168.10.1) as its gateway", "gateway and DNS to 192.168.10.177", "VPN mode", "1 goes through ShakerProxy: Pixel · 192.168.10.201"} {
		if !strings.Contains(data.Summary, fragment) {
			t.Errorf("summary %q lacks %q", data.Summary, fragment)
		}
	}
	backend.labRouting = agentapi.LabRouting{Schema: 1, GeneratedAt: now, Unavailable: "No lab network routes through ShakerProxy right now.", Devices: []agentapi.LabRoutingDevice{}}
	result, _, err = (&Service{backend: backend}).labRouting(context.Background(), nil, LabRoutingArgs{})
	if err != nil {
		t.Fatal(err)
	}
	decodeToolResult(t, result, &data)
	if !strings.Contains(data.Summary, "No lab network routes through ShakerProxy") {
		t.Fatalf("summary = %q", data.Summary)
	}
}
