package server

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/ingest"
	"shakerproxy.dev/shakerproxy/internal/inventory"
	"shakerproxy.dev/shakerproxy/internal/labrouting"
)

type labPresenceReaderStub struct {
	presence ingest.LabPresence
	prefix   netip.Prefix
	calls    int
}

func (stub *labPresenceReaderStub) QueryRecent(context.Context, ingest.RecentEventQuery) (ingest.RecentEventPage, error) {
	return ingest.RecentEventPage{}, nil
}

func (stub *labPresenceReaderStub) QueryLabPresence(_ context.Context, prefix netip.Prefix) (ingest.LabPresence, error) {
	stub.calls++
	stub.prefix = prefix
	return stub.presence, nil
}

// startLabGateway answers GetManagedState as the test VM's single-arm lab.
func startLabGateway(t *testing.T, socketPath string) {
	t.Helper()
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func(connection net.Conn) {
				defer connection.Close()
				var request gatewayprotocol.Request
				if json.NewDecoder(connection).Decode(&request) != nil {
					return
				}
				var result any = map[string]any{}
				if request.Method == "GetManagedState" {
					result = gatewayprotocol.Status{
						OperatingMode: gatewayprotocol.ModeRouted, LabInterface: "ens18", LabTopology: "SINGLE_ARM", LabScopePlanHash: "37060b93fa71" + "0000000000000000000000000000000000000000000000000000",
						LabIPv4Prefix: "192.168.10.0/24", LabIPv4Gateway: "192.168.10.177", LabIPv4Router: "192.168.10.1",
					}
				}
				_ = json.NewEncoder(connection).Encode(gatewayprotocol.Response{JSONRPC: gatewayprotocol.JSONRPCVersion, ID: request.ID, Result: result})
			}(connection)
		}
	}()
}

// The owner joined an iPhone to the lab Wi-Fi of the test VM and browsed;
// ShakerProxy showed nothing. The report must name it, say why, and the
// device list must show it as a device that bypasses ShakerProxy.
func TestLabRoutingNamesTheIPhoneThatBypassesShakerProxy(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "gatewayd.sock")
	server, session := configuredAPIServer(t, socket)
	startLabGateway(t, socket)
	server.inventory = &inventory.Store{Path: filepath.Join(t.TempDir(), "inventory.json")}
	now := time.Now().UTC().Truncate(time.Second)
	stub := &labPresenceReaderStub{presence: ingest.LabPresence{Schema: ingest.LabPresenceSchema, GeneratedAt: now, Prefix: "192.168.10.0/24", Since: now.Add(-30 * time.Minute), Hosts: []ingest.LabPresenceHost{
		{Address: "192.168.10.130", HardwareAddrs: []string{"62:bc:f1:bc:1d:8d"}, HostName: "iPhone", FirstSeen: now.Add(-4 * time.Minute), LastSeen: now.Add(-20 * time.Second), Events: 31, DiscoveryEvents: 30, DHCPLastSeen: now.Add(-4 * time.Minute)},
		{Address: "192.168.10.1", FirstSeen: now.Add(-29 * time.Minute), LastSeen: now, Events: 900, DiscoveryEvents: 900},
	}}}
	server.eventReader = stub

	get := func(path string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.Host = "shakerproxy.test"
		request.Header.Set("Authorization", "Bearer "+session)
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, request)
		return recorder
	}
	recorder := get("/api/v1/lab-routing")
	if recorder.Code != http.StatusOK {
		t.Fatalf("lab routing returned %d: %s", recorder.Code, recorder.Body.String())
	}
	var report labRoutingReport
	if err := json.Unmarshal(recorder.Body.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if !report.Available || report.ShakerProxyAddress != "192.168.10.177" || report.RouterAddress != "192.168.10.1" || report.SubnetMask != "255.255.255.0" || report.Counts.Bypassing != 1 || len(report.Devices) != 1 || stub.prefix.String() != "192.168.10.0/24" {
		t.Fatalf("report = %+v", report)
	}
	iphone := report.Devices[0]
	if iphone.Routing != labrouting.Bypassing || iphone.DisplayName != "iPhone" || iphone.DeviceID == "" || iphone.Reason != "It got its address from your router's DHCP, so it uses the router (192.168.10.1) as its gateway, not ShakerProxy." {
		t.Fatalf("iPhone = %+v", iphone)
	}
	if title := labDeviceTitle(iphone); title != "iPhone · 192.168.10.130" {
		t.Fatalf("title = %q", title)
	}

	recorder = get("/api/v1/devices")
	if recorder.Code != http.StatusOK {
		t.Fatalf("devices returned %d: %s", recorder.Code, recorder.Body.String())
	}
	var devices struct {
		Devices    []inventory.Device          `json:"devices"`
		LabRouting map[string]labRoutingDevice `json:"lab_routing"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &devices); err != nil || len(devices.Devices) != 1 {
		t.Fatalf("devices = %s err=%v", recorder.Body.String(), err)
	}
	device := devices.Devices[0]
	if device.ID != iphone.DeviceID || devices.LabRouting[device.ID].Routing != labrouting.Bypassing || device.Identities[0].Value != "62:bc:f1:bc:1d:8d" || device.Identities[0].Source != inventory.SourceObservedLAN {
		t.Fatalf("device = %+v routing = %+v", device, devices.LabRouting)
	}
	if stub.calls != 1 {
		t.Fatalf("the report was not cached: %d lookups", stub.calls)
	}
}

// Without a routed lab there is nothing to judge, and the report says so.
func TestLabRoutingWithoutALabIsUnavailable(t *testing.T) {
	server, session := configuredAPIServer(t, filepath.Join(t.TempDir(), "absent.sock"))
	server.eventReader = &labPresenceReaderStub{}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/lab-routing", nil)
	request.Host = "shakerproxy.test"
	request.Header.Set("Authorization", "Bearer "+session)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	var report labRoutingReport
	if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &report) != nil || report.Available || report.Unavailable == "" || report.Devices == nil {
		t.Fatalf("report = %d %s", recorder.Code, recorder.Body.String())
	}
}
