package ingest

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// zeekDHCPFixture is real Zeek 8.2.1 output, with the site script, for an
// Android phone's DISCOVER/OFFER/REQUEST/ACK from the router and an iPad's
// lone REQUEST.
func zeekDHCPFixture(t *testing.T) []dhcpExchange {
	t.Helper()
	file, err := os.Open("testdata/zeek_dhcp.ndjson")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var exchanges []dhcpExchange
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		envelope, err := NormalizeZeekJSON(scanner.Bytes(), "8.2.1", "")
		if err != nil || envelope.Kind != "zeek.dhcp" {
			t.Fatalf("fixture line %q: %v", scanner.Text(), err)
		}
		exchange, ok := parseZeekDHCP(envelope.Payload, envelope.OccurredAt)
		if !ok {
			t.Fatalf("fixture line was not read: %s", scanner.Text())
		}
		exchanges = append(exchanges, exchange)
	}
	return exchanges
}

func TestObservedDHCPFromZeekNamesTheRoutersClients(t *testing.T) {
	clients := mergeObservedDHCP(zeekDHCPFixture(t))
	if len(clients) != 2 {
		t.Fatalf("clients = %+v", clients)
	}
	ipad, phone := clients[0], clients[1]
	if ipad.HardwareAddr != "0e:47:eb:9f:1b:6a" || ipad.HostName != "iPad" || ipad.RequestedAddr != "192.168.100.196" || ipad.AssignedAddr != "" || !ipad.AssignedAt.IsZero() || ipad.Server != "" ||
		ipad.ParameterList != "1,121,3,6,15,108,114,119,252,95,44,46" || ipad.VendorClass != "" {
		t.Fatalf("a client seen only asking: %+v", ipad)
	}
	at := time.Unix(1790952000, 0).UTC()
	want := ObservedDHCPClient{
		HardwareAddr: "b6:53:83:65:54:a2", HostName: "Pixel-7", VendorClass: "android-dhcp-14", ParameterList: "1,3,6,15,26,28,51,58,59,43,114,108",
		RequestedAddr: "192.168.10.201", AssignedAddr: "192.168.10.201", AssignedAt: at, LeaseSeconds: 86400, Server: "192.168.10.1", Router: "192.168.10.1",
		FirstSeen: at, LastSeen: at,
	}
	if phone != want {
		t.Fatalf("the router's client:\n got %+v\nwant %+v", phone, want)
	}
	observed := ObservedDHCP{Schema: ObservedDHCPSchema, GeneratedAt: at, Clients: clients}
	if err := observed.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestObservedDHCPKeepsTheNewestValuesAndTheNewestLease(t *testing.T) {
	at := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	old := dhcpExchange{mac: "b6:53:83:65:54:a2", hostName: "android-1234", vendorClass: "android-dhcp-13", acknowledged: true, assigned: dhcpAddress("192.168.10.150"), leaseSeconds: 3600, at: at}
	renamed := dhcpExchange{mac: "b6:53:83:65:54:a2", hostName: "Pixel-7", at: at.Add(time.Hour)}
	renewed := dhcpExchange{mac: "b6:53:83:65:54:a2", acknowledged: true, assigned: dhcpAddress("192.168.10.201"), leaseSeconds: 86400, at: at.Add(2 * time.Hour)}
	clients := mergeObservedDHCP([]dhcpExchange{old, renewed, renamed})
	if len(clients) != 1 {
		t.Fatalf("clients = %+v", clients)
	}
	client := clients[0]
	if client.HostName != "Pixel-7" || client.VendorClass != "android-dhcp-13" || client.AssignedAddr != "192.168.10.201" || !client.AssignedAt.Equal(at.Add(2*time.Hour)) ||
		client.LeaseSeconds != 86400 || !client.FirstSeen.Equal(at) || !client.LastSeen.Equal(at.Add(2*time.Hour)) {
		t.Fatalf("client = %+v", client)
	}
}

func TestObservedDHCPDropsWhatIsNotADeviceOrNotPrintable(t *testing.T) {
	at := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	for _, payload := range []string{
		`{"mac":"ff:ff:ff:ff:ff:ff","host_name":"x","msg_types":["REQUEST"]}`,
		`{"mac":"00:00:00:00:00:00","host_name":"x","msg_types":["REQUEST"]}`,
		`{"mac":"01:00:5e:00:00:01","host_name":"x","msg_types":["REQUEST"]}`,
		`{"host_name":"no MAC","msg_types":["REQUEST"]}`,
		`not json`,
	} {
		if _, ok := parseZeekDHCP([]byte(payload), at); ok {
			t.Fatalf("accepted %s", payload)
		}
	}
	exchange, ok := parseZeekDHCP([]byte(`{"mac":"B6:53:83:65:54:A2","host_name":"bad\u0007name","client_software":" android-dhcp-14 ","client_param_list":[1,0,3],"requested_addr":"255.255.255.255","assigned_addr":"192.168.10.201","msg_types":["OFFER"],"routers":["192.168.10.1"]}`), at)
	if !ok || exchange.mac != "b6:53:83:65:54:a2" || exchange.hostName != "" || exchange.vendorClass != "android-dhcp-14" || exchange.parameterList != "" || exchange.requested.IsValid() || exchange.acknowledged || exchange.router.IsValid() {
		t.Fatalf("exchange = %+v ok=%v", exchange, ok)
	}
	tooMany := make([]int, maxDHCPParameters+1)
	for index := range tooMany {
		tooMany[index] = 1
	}
	if dhcpParameterList(tooMany) != "" {
		t.Fatal("an over-long parameter list was kept")
	}
	invalid := ObservedDHCP{Schema: ObservedDHCPSchema, GeneratedAt: at, Clients: []ObservedDHCPClient{{HardwareAddr: "b6:53:83:65:54:a2", Server: "192.168.10.1", FirstSeen: at, LastSeen: at}}}
	if invalid.Validate() == nil {
		t.Fatal("a server without a lease was accepted")
	}
	duplicate := ObservedDHCP{Schema: ObservedDHCPSchema, GeneratedAt: at, Clients: []ObservedDHCPClient{{HardwareAddr: "b6:53:83:65:54:a2", FirstSeen: at, LastSeen: at}, {HardwareAddr: "b6:53:83:65:54:a2", FirstSeen: at, LastSeen: at}}}
	if duplicate.Validate() == nil {
		t.Fatal("a duplicate client was accepted")
	}
}

func TestObservedDHCPFromSuricataReadsTheAcknowledgement(t *testing.T) {
	at := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	exchange, ok := parseSuricataDHCP([]byte(`{"src_ip":"192.168.10.1","dhcp":{"type":"reply","id":1,"client_mac":"b6:53:83:65:54:a2","assigned_ip":"192.168.10.201","dhcp_type":"ack","hostname":"Pixel-7","lease_time":86400,"routers":["192.168.10.1"]}}`), at)
	if !ok || !exchange.acknowledged || exchange.assigned.String() != "192.168.10.201" || exchange.server.String() != "192.168.10.1" || exchange.router.String() != "192.168.10.1" || exchange.leaseSeconds != 86400 || exchange.hostName != "Pixel-7" {
		t.Fatalf("exchange = %+v ok=%v", exchange, ok)
	}
	request, ok := parseSuricataDHCP([]byte(`{"src_ip":"0.0.0.0","dhcp":{"type":"request","client_mac":"b6:53:83:65:54:a2","assigned_ip":"0.0.0.0","dhcp_type":"request","requested_ip":"192.168.10.201","vendor_class_identifier":"android-dhcp-14"}}`), at)
	if !ok || request.acknowledged || request.requested.String() != "192.168.10.201" || request.vendorClass != "android-dhcp-14" {
		t.Fatalf("request = %+v ok=%v", request, ok)
	}
}

func TestDHCPPlatformNamesOnlyUnambiguousClients(t *testing.T) {
	for _, test := range []struct {
		vendor, list, platform, evidence string
	}{
		{"android-dhcp-14", "1,3,6,15,26,28,51,58,59,43,114,108", "Android device", "android-dhcp-14"},
		{"MSFT 5.0", "1,3,6,15,31,33,43,44,46,47,119,121,249,252", "Windows PC", "MSFT 5.0"},
		{"dhcpcd-9.4.1:Linux-6.1.0-rpi7-rpi-v8:aarch64:BCM2835", "1,121,33,3,6,28,51,58,59", "Linux or Android device", "dhcpcd-9.4.1:Linux-6.1.0-rpi7-rpi-v8:aarch64:BCM2835"},
		{"udhcp 1.36.1", "1,3,6,12,15,28,42", "Embedded Linux device", "udhcp 1.36.1"},
		{"", "1,121,3,6,15,108,114,119,252,95,44,46", "Apple device", "options 1,121,3,6,15,108,114,119,252,95,44,46"},
		{"", "1,121,3,6,15,119,252", "Apple device", "options 1,121,3,6,15,119,252"},
		{"", "1,3,6,15,119,252", "", ""},
		{"", "", "", ""},
		{"SomeVendor", "1,121,3,6,15,119,252", "", ""},
	} {
		platform, evidence, _, ok := DHCPPlatform(test.vendor, test.list)
		if platform != test.platform || evidence != test.evidence || ok != (test.platform != "") {
			t.Fatalf("DHCPPlatform(%q, %q) = %q %q %v", test.vendor, test.list, platform, evidence, ok)
		}
	}
	if _, _, android, _ := DHCPPlatform("android-dhcp-14", ""); android >= platformChecks["connectivitycheck.grapheneos.network"].rank {
		t.Fatal("a DHCP fingerprint outranks GrapheneOS's own connectivity check")
	}
}

func TestQueryClientDecodesObservedDHCPStrictly(t *testing.T) {
	at := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	body := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/observed-dhcp" || r.URL.RawQuery != "" || r.Header.Get("Authorization") != "Bearer "+strings.Repeat("q", 43) {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()
	endpoint, _ := url.Parse(server.URL)
	client := &QueryClient{endpoint: endpoint, token: []byte(strings.Repeat("q", 43)), client: server.Client()}
	valid, _ := json.Marshal(ObservedDHCP{Schema: ObservedDHCPSchema, GeneratedAt: at, Clients: []ObservedDHCPClient{{HardwareAddr: "b6:53:83:65:54:a2", HostName: "Pixel-7", FirstSeen: at, LastSeen: at}}})
	body = string(valid)
	observed, err := client.QueryObservedDHCP(context.Background())
	if err != nil || len(observed.Clients) != 1 || observed.Clients[0].HostName != "Pixel-7" {
		t.Fatalf("observed = %+v err=%v", observed, err)
	}
	body = strings.Replace(string(valid), `"clients"`, `"extra":1,"clients"`, 1)
	if _, err := client.QueryObservedDHCP(context.Background()); err == nil {
		t.Fatal("an unknown field was accepted")
	}
	body = strings.Replace(string(valid), "b6:53:83:65:54:a2", "ff:ff:ff:ff:ff:ff", 1)
	if _, err := client.QueryObservedDHCP(context.Background()); err == nil {
		t.Fatal("a broadcast client was accepted")
	}
}
