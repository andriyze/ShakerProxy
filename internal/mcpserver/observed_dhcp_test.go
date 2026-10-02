package mcpserver

import (
	"context"
	"strings"
	"testing"

	"shakerproxy.dev/shakerproxy/internal/agentapi"
)

// In a single-arm lab the router answers the phone's DHCP: list_devices and
// find_device say what its request said, and the summary names the platform
// when the MAC vendor is unknown (a private MAC).
func TestDeviceToolsShowTheObservedDHCPIdentity(t *testing.T) {
	backend := newFakeBackend()
	phoneID := "device-00000000000000000000000000000201"
	backend.devicePage = agentapi.DevicePage{Schema: 1, GeneratedAt: fakeNow, Matched: 1, Returned: 1, Devices: []agentapi.Device{
		{Schema: 1, ID: phoneID, DisplayName: "Pixel-7", Online: true, Addresses: []agentapi.DeviceAddress{{Address: "192.168.10.201", Active: true}},
			DHCP: &agentapi.DeviceDHCP{HostName: "Pixel-7", VendorClass: "android-dhcp-14", Platform: "Android device", Server: "192.168.10.1", LastSeen: fakeNow}},
	}}
	backend.resolutions["pixel"] = agentapi.DeviceResolution{Schema: 1, Query: "pixel", Unique: true, Matches: []agentapi.DeviceMatch{
		{DeviceID: phoneID, FriendlyName: "Pixel-7", Addresses: []string{"192.168.10.201"}, HardwareAddresses: []string{"b6:53:83:65:54:a2"}, Online: true, Match: "name_prefix",
			DHCPHostName: "Pixel-7", DHCPVendorClass: "android-dhcp-14", DHCPPlatform: "Android device"},
	}}
	service := &Service{backend: backend}
	result, _, err := service.listDevices(context.Background(), nil, ListDevicesArgs{})
	if err != nil {
		t.Fatal(err)
	}
	var devices deviceList
	decodeToolResult(t, result, &devices)
	line := devices.Devices[0]
	if line.DHCP == nil || line.DHCP.Platform != "Android device" || line.DHCP.VendorClass != "android-dhcp-14" || line.Summary != "Pixel-7 (Android device, 192.168.10.201, online)" {
		t.Fatalf("list devices: %#v", line)
	}
	result, _, err = service.findDevice(context.Background(), nil, FindDeviceArgs{Device: "pixel"})
	if err != nil {
		t.Fatal(err)
	}
	var found findDeviceResult
	decodeToolResult(t, result, &found)
	if found.Matches[0].DHCP == nil || found.Matches[0].DHCP.HostName != "Pixel-7" || found.Summary != `"pixel" is Pixel-7 (Android device, 192.168.10.201, online) (matched by start of name).` || strings.Contains(rawToolText(t, result), "b6:53") {
		t.Fatalf("find device: %#v %s", found, rawToolText(t, result))
	}
}
