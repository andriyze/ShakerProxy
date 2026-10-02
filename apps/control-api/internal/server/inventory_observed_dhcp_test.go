package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/ingest"
	"shakerproxy.dev/shakerproxy/internal/inventory"
)

type observedDHCPReaderStub struct {
	observed ingest.ObservedDHCP
	hints    ingest.DevicePlatformHints
	err      error
	calls    int
}

func (stub *observedDHCPReaderStub) QueryRecent(context.Context, ingest.RecentEventQuery) (ingest.RecentEventPage, error) {
	return ingest.RecentEventPage{}, nil
}

func (stub *observedDHCPReaderStub) QueryObservedDHCP(context.Context) (ingest.ObservedDHCP, error) {
	stub.calls++
	return stub.observed, stub.err
}

func (stub *observedDHCPReaderStub) QueryDevicePlatformHints(context.Context) (ingest.DevicePlatformHints, error) {
	return stub.hints, nil
}

// A single-arm lab: the router leased the phone its address and the iPad asked
// from a neighbouring network. The phone becomes a device named by its own
// DHCP name and fingerprint; the iPad is not added.
func TestDevicesListNamesTheRoutersDHCPClients(t *testing.T) {
	server, session := configuredAPIServer(t, filepath.Join(t.TempDir(), "absent.sock"))
	directory := t.TempDir()
	server.inventory = &inventory.Store{Path: filepath.Join(directory, "inventory.json")}
	// A single-arm lab has no ShakerProxy lease file.
	server.keaLeasePath = filepath.Join(directory, "kea-leases4.csv")
	at := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	stub := &observedDHCPReaderStub{observed: ingest.ObservedDHCP{Schema: ingest.ObservedDHCPSchema, GeneratedAt: at, Clients: []ingest.ObservedDHCPClient{
		{HardwareAddr: "0e:47:eb:9f:1b:6a", HostName: "iPad", ParameterList: "1,121,3,6,15,108,114,119,252,95,44,46", RequestedAddr: "192.168.100.196", FirstSeen: at, LastSeen: at},
		{HardwareAddr: "3c:28:6d:65:54:a2", HostName: "Pixel-7", VendorClass: "android-dhcp-14", ParameterList: "1,3,6,15,26,28,51,58,59,43,114,108", RequestedAddr: "192.168.10.201",
			AssignedAddr: "192.168.10.201", AssignedAt: at, LeaseSeconds: 86400, Server: "192.168.10.1", Router: "192.168.10.1", FirstSeen: at, LastSeen: at},
	}}}
	server.eventReader = stub
	// The background refresh adds the evidence; the list reads the snapshot.
	if _, err := server.refreshInventory(); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/devices", nil)
	request.Host = "shakerproxy.test"
	request.Header.Set("Authorization", "Bearer "+session)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("devices returned %d: %s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Devices       []inventory.Device            `json:"devices"`
		PlatformHints map[string]devicePlatformHint `json:"platform_hints"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil || len(response.Devices) != 1 {
		t.Fatalf("devices response = %s err=%v", recorder.Body.String(), err)
	}
	phone := response.Devices[0]
	if phone.ObservedDHCP == nil || phone.ObservedDHCP.HostName != "Pixel-7" || phone.ObservedDHCP.VendorClass != "android-dhcp-14" || len(phone.SuggestedNames) != 1 || phone.SuggestedNames[0].Name != "pixel-7" {
		t.Fatalf("phone = %+v", phone)
	}
	if hint := response.PlatformHints[phone.ID]; hint.Platform != "Android device" || hint.Source != "dhcp" || hint.Detail != "android-dhcp-14" || hint.Domain != "" {
		t.Fatalf("platform hint = %+v", hint)
	}
	if name := deviceDisplayName(phone); name != "Pixel-7" {
		t.Fatalf("display name = %q", name)
	}
	if match := newDeviceMatch(phone, deviceMatchName); match.DHCPHostName != "Pixel-7" || match.DHCPPlatform != "Android device" || match.FriendlyName != "Pixel-7" {
		t.Fatalf("match = %+v", match)
	}
	if agent := projectAgentDeviceForTest(t, phone); agent.DHCP == nil || agent.DHCP.Platform != "Android device" || agent.DHCP.Server != "192.168.10.1" {
		t.Fatalf("agent device = %+v", agent)
	}
	// Within the cache interval the exchanges are not fetched again.
	if _, err := server.refreshInventory(); err != nil || stub.calls != 1 {
		t.Fatalf("observed DHCP was fetched %d times err=%v", stub.calls, err)
	}
}

// A lease outside the lab's prefix names a known MAC but creates nothing, and
// an unavailable ingestd leaves the inventory as it was.
func TestObservedDHCPStaysInsideTheLabPrefixAndIsBestEffort(t *testing.T) {
	prefix := netip.MustParsePrefix("192.168.10.0/24")
	at := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	clients := observedDHCPClients([]ingest.ObservedDHCPClient{
		{HardwareAddr: "3c:28:6d:65:54:a2", AssignedAddr: "192.168.10.201", AssignedAt: at, LeaseSeconds: 60, Server: "192.168.10.1", FirstSeen: at, LastSeen: at},
		{HardwareAddr: "0e:47:eb:9f:1b:6a", HostName: "iPad", AssignedAddr: "192.168.100.196", AssignedAt: at, LeaseSeconds: 60, Server: "192.168.100.1", FirstSeen: at, LastSeen: at},
	}, prefix)
	if !clients[0].AssignedAddr.IsValid() || clients[0].LeaseTime != time.Minute || clients[0].Server.String() != "192.168.10.1" {
		t.Fatalf("lab client = %+v", clients[0])
	}
	if clients[1].AssignedAddr.IsValid() || clients[1].Server.IsValid() || clients[1].HostName != "iPad" {
		t.Fatalf("neighbouring client = %+v", clients[1])
	}
	server, _ := configuredAPIServer(t, filepath.Join(t.TempDir(), "absent.sock"))
	directory := t.TempDir()
	server.inventory = &inventory.Store{Path: filepath.Join(directory, "inventory.json")}
	server.keaLeasePath = filepath.Join(directory, "kea-leases4.csv")
	server.eventReader = &observedDHCPReaderStub{err: errors.New("ingestd is down")}
	if snapshot, err := server.refreshInventory(); err != nil || len(snapshot.Devices) != 0 {
		t.Fatalf("an unavailable ingestd failed the refresh: %+v err=%v", snapshot, err)
	}
}

// A connectivity check names a device more specifically than its DHCP
// request; a DHCP fingerprint outranks a less specific check.
func TestPlatformHintsWeighDHCPFingerprintsAgainstChecks(t *testing.T) {
	at := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	device := func(id, vendor, list string) inventory.Device {
		return inventory.Device{ID: id, ObservedDHCP: &inventory.ObservedDHCPIdentity{HardwareAddr: "3c:28:6d:65:54:a2", VendorClass: vendor, ParameterList: list, LastSeen: at}}
	}
	graphene := "device-00000000000000000000000000000001"
	windows := "device-00000000000000000000000000000002"
	apple := "device-00000000000000000000000000000003"
	hints := platformHintsFor(
		[]inventory.Device{device(graphene, "android-dhcp-14", ""), device(windows, "MSFT 5.0", ""), device(apple, "", "1,121,3,6,15,119,252")},
		[]ingest.DevicePlatformHint{
			{DeviceID: graphene, Platform: "GrapheneOS phone", Domain: "connectivitycheck.grapheneos.network", LastSeen: at},
			{DeviceID: windows, Platform: "Android device", Domain: "connectivitycheck.gstatic.com", LastSeen: at},
		},
	)
	if hint := hints[graphene]; hint.Platform != "GrapheneOS phone" || hint.Source != "" {
		t.Fatalf("GrapheneOS = %+v", hint)
	}
	if hint := hints[windows]; hint.Platform != "Windows PC" || hint.Source != "dhcp" || hint.Detail != "MSFT 5.0" {
		t.Fatalf("Windows = %+v", hint)
	}
	if hint := hints[apple]; hint.Platform != "Apple device" || hint.Detail != "options 1,121,3,6,15,119,252" {
		t.Fatalf("Apple = %+v", hint)
	}
}

func projectAgentDeviceForTest(t *testing.T, device inventory.Device) agentDevice {
	t.Helper()
	return projectAgentDevice(device)
}
