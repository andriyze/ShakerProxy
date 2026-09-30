package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

const activityTestDevice = "device-0123456789abcdef0123456789abcdef"

func activityTestQuery() DeviceActivityQuery {
	end := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	return DeviceActivityQuery{DeviceID: activityTestDevice, Start: end.Add(-24 * time.Hour), End: end}
}

func emptyDeviceActivity(query DeviceActivityQuery) DeviceActivity {
	return DeviceActivity{
		Schema: SchemaVersion, GeneratedAt: query.End.Add(time.Second), DeviceID: query.DeviceID, Start: query.Start, End: query.End,
		Domains: []DeviceDomainObservation{}, FlowGroups: []DeviceFlowGroup{}, TLSHosts: []DeviceTLSHost{},
		TLSVersions: []DeviceTLSVersion{}, CleartextHTTP: []DeviceHTTPHost{}, HTTPStatus: []DeviceHTTPStatusCount{},
		Alerts: []DeviceAlertGroup{}, EncryptedDNS: []DeviceResolver{},
	}
}

func TestParseInternalDeviceActivityQueryValidatesBounds(t *testing.T) {
	query := activityTestQuery()
	values := url.Values{}
	values.Set("device_id", query.DeviceID)
	values.Set("start", query.Start.Format(time.RFC3339Nano))
	values.Set("end", query.End.Format(time.RFC3339Nano))
	parsed, err := ParseInternalDeviceActivityQuery(values)
	if err != nil || !reflect.DeepEqual(parsed, query) {
		t.Fatalf("valid query parsed as %#v err=%v", parsed, err)
	}
	encoded, err := encodeDeviceActivityQuery(query)
	if err != nil || encoded.Encode() != values.Encode() {
		t.Fatalf("encoded %v err=%v", encoded, err)
	}
	cases := map[string]func(url.Values){
		"missing device":     func(v url.Values) { v.Del("device_id") },
		"bad device":         func(v url.Values) { v.Set("device_id", "Living room TV") },
		"unknown parameter":  func(v url.Values) { v.Set("q", "x") },
		"repeated parameter": func(v url.Values) { v.Add("start", query.Start.Format(time.RFC3339)) },
		"end before start":   func(v url.Values) { v.Set("end", query.Start.Add(-time.Second).Format(time.RFC3339)) },
		"range over 31 days": func(v url.Values) { v.Set("start", query.End.Add(-32*24*time.Hour).Format(time.RFC3339)) },
		"not a timestamp":    func(v url.Values) { v.Set("start", "yesterday") },
		"nanosecond precision": func(v url.Values) {
			v.Set("start", query.Start.Add(time.Nanosecond).Format(time.RFC3339Nano))
		},
		"zoned address":         func(v url.Values) { v.Add("address", "fe80::1%eth0") },
		"mapped address":        func(v url.Values) { v.Add("address", "::ffff:10.77.0.23") },
		"non-canonical address": func(v url.Values) { v.Add("address", "010.77.0.23") },
		"too many addresses": func(v url.Values) {
			for index := 0; index <= MaxDeviceActivityAddresses; index++ {
				v.Add("address", fmt.Sprintf("10.77.1.%d", index))
			}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			copied := url.Values{}
			for key, entries := range values {
				copied[key] = append([]string(nil), entries...)
			}
			mutate(copied)
			if _, err := ParseInternalDeviceActivityQuery(copied); err == nil {
				t.Fatalf("query was accepted: %v", copied)
			}
		})
	}
}

func TestActivityHostNormalizesNamesAndAddresses(t *testing.T) {
	cases := []struct {
		input string
		want  string
		ok    bool
	}{
		{"API.Example.COM.", "api.example.com", true},
		{"plain.example.com:8080", "plain.example.com", true},
		{"[2001:db8::1]:443", "2001:db8::1", true},
		{"2001:db8::1", "2001:db8::1", true},
		{"::ffff:192.0.2.1", "192.0.2.1", true},
		{"_dns.resolver.arpa", "_dns.resolver.arpa", true},
		{"", "", false},
		{"bad host.example", "", false},
		{"evil.example/path", "", false},
		{"a..b", "", false},
		{strings.Repeat("a", 64) + ".example", "", false},
		{strings.Repeat("a.", 130) + "com", "", false},
	}
	for _, item := range cases {
		got, ok := ActivityHost(item.input)
		if got != item.want || ok != item.ok {
			t.Errorf("ActivityHost(%q) = %q, %v; want %q, %v", item.input, got, ok, item.want, item.ok)
		}
	}
}

func TestLegacyTLSVersionLabelMapsSensorSpellings(t *testing.T) {
	for input, want := range map[string]string{
		"TLSv10": "TLSv1.0", "TLS 1.0": "TLSv1.0", "TLSv1": "TLSv1.0", "TLSV11": "TLSv1.1", "TLS 1.1": "TLSv1.1",
		"SSLv3": "SSLv3", "SSLv2": "SSLv2", "DTLSv10": "DTLSv1.0", "TLSv12": "", "TLS 1.3": "", "": "",
	} {
		if got := LegacyTLSVersionLabel(input); got != want {
			t.Errorf("LegacyTLSVersionLabel(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestFindingSeverityLabelMapsSuricataPrioritiesAndDetections(t *testing.T) {
	for _, item := range []struct{ engine, value, want string }{
		{"SURICATA", "1", "HIGH"}, {"SURICATA", "2", "MEDIUM"}, {"SURICATA", "3", "LOW"}, {"SURICATA", "", "LOW"},
		{"SHAKERPROXY", "CRITICAL", "CRITICAL"}, {"SHAKERPROXY", "HIGH", "HIGH"}, {"SHAKERPROXY", "WARNING", "MEDIUM"},
	} {
		if got := findingSeverityLabel(item.engine, item.value); got != item.want {
			t.Errorf("findingSeverityLabel(%q, %q) = %q, want %q", item.engine, item.value, got, item.want)
		}
	}
}

func TestDeviceActivityValidateRejectsOutOfContractSections(t *testing.T) {
	query := activityTestQuery()
	inside := query.Start.Add(time.Hour)
	if err := emptyDeviceActivity(query).Validate(query); err != nil {
		t.Fatalf("empty activity rejected: %v", err)
	}
	cases := map[string]func(*DeviceActivity){
		"wrong device":    func(a *DeviceActivity) { a.DeviceID = "device-fedcba9876543210fedcba9876543210" },
		"negative count":  func(a *DeviceActivity) { a.Counts.Events = -1 },
		"missing section": func(a *DeviceActivity) { a.Domains = nil },
		"domain not canonical": func(a *DeviceActivity) {
			a.Domains = []DeviceDomainObservation{{Domain: "API.example.com", Source: "dns", Events: 1, FirstSeen: inside, LastSeen: inside}}
		},
		"domain bad source": func(a *DeviceActivity) {
			a.Domains = []DeviceDomainObservation{{Domain: "api.example.com", Source: "ftp", Events: 1, FirstSeen: inside, LastSeen: inside}}
		},
		"domain outside range": func(a *DeviceActivity) {
			a.Domains = []DeviceDomainObservation{{Domain: "api.example.com", Source: "dns", Events: 1, FirstSeen: query.End, LastSeen: query.End}}
		},
		"flow bad client port": func(a *DeviceActivity) {
			a.FlowGroups = []DeviceFlowGroup{{Source: SourceZeek, Transport: "tcp", ClientPort: 5000, Flows: 1, FirstSeen: inside, LastSeen: inside}}
		},
		"flow bad peer": func(a *DeviceActivity) {
			a.FlowGroups = []DeviceFlowGroup{{Source: SourceZeek, Transport: "tcp", Flows: 1, SamplePeer: "not-an-ip", FirstSeen: inside, LastSeen: inside}}
		},
		"tls bad state": func(a *DeviceActivity) {
			a.TLSHosts = []DeviceTLSHost{{Host: "api.example.com", State: "MAYBE", Events: 1, FirstSeen: inside, LastSeen: inside}}
		},
		"tls modern version": func(a *DeviceActivity) {
			a.TLSVersions = []DeviceTLSVersion{{Version: "TLSv1.3", Host: "api.example.com", Events: 1, FirstSeen: inside, LastSeen: inside}}
		},
		"http status class": func(a *DeviceActivity) {
			a.HTTPStatus = []DeviceHTTPStatusCount{{Source: SourceZeek, Class: "6xx", Count: 1}}
		},
		"alert severity": func(a *DeviceActivity) {
			a.Alerts = []DeviceAlertGroup{{Engine: "SURICATA", Signature: "x", Severity: "URGENT", Count: 1, FirstSeen: inside, LastSeen: inside}}
		},
		"alert control characters": func(a *DeviceActivity) {
			a.Alerts = []DeviceAlertGroup{{Engine: "SURICATA", Signature: "x\ny", Severity: "LOW", Count: 1, FirstSeen: inside, LastSeen: inside}}
		},
		"resolver transport": func(a *DeviceActivity) {
			a.EncryptedDNS = []DeviceResolver{{Host: "dns.google", Transport: "DNSCRYPT", Events: 1, FirstSeen: inside, LastSeen: inside}}
		},
		"too many domains": func(a *DeviceActivity) {
			a.Domains = make([]DeviceDomainObservation, MaxDeviceActivityDomainRows+1)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			activity := emptyDeviceActivity(query)
			mutate(&activity)
			if err := activity.Validate(query); err == nil {
				t.Fatal("invalid activity was accepted")
			}
		})
	}
}

func TestQueryClientReadsDeviceActivityWithQueryToken(t *testing.T) {
	query := activityTestQuery()
	inside := query.Start.Add(time.Hour)
	activity := emptyDeviceActivity(query)
	activity.Counts.Events = 3
	activity.Domains = []DeviceDomainObservation{{Domain: "api.example.com", Source: "dns", Events: 3, FirstSeen: inside, LastSeen: inside}}
	token := strings.Repeat("q", 40)
	var requested *http.Request
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested = r
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(activity)
	}))
	defer server.Close()
	client, err := NewQueryClient(server.URL, []byte(token), nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := client.QueryDeviceActivity(context.Background(), query)
	if err != nil {
		t.Fatal(err)
	}
	if requested.URL.Path != "/v1/device-activity" || requested.Header.Get("Authorization") != "Bearer "+token || requested.URL.Query().Get("device_id") != query.DeviceID {
		t.Fatalf("unexpected request %s %v", requested.URL, requested.Header)
	}
	if got.Counts.Events != 3 || len(got.Domains) != 1 || got.Domains[0].Domain != "api.example.com" {
		t.Fatalf("unexpected activity %#v", got)
	}

	for name, body := range map[string]string{
		"unknown field": `{"schema":1,"surprise":true}`,
		"wrong device":  strings.Replace(mustJSON(t, activity), activityTestDevice, "device-fedcba9876543210fedcba9876543210", 1),
	} {
		t.Run(name, func(t *testing.T) {
			bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, body)
			}))
			defer bad.Close()
			client, err := NewQueryClient(bad.URL, []byte(token), nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.QueryDeviceActivity(context.Background(), query); err == nil {
				t.Fatal("invalid response was accepted")
			}
		})
	}
	if _, err := client.QueryDeviceActivity(context.Background(), DeviceActivityQuery{DeviceID: "bad"}); err == nil {
		t.Fatal("invalid query was sent")
	}
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func TestDeviceActivityQueryCarriesDeviceAddresses(t *testing.T) {
	query := activityTestQuery()
	query.Addresses = []string{"10.77.0.23", "fd12:3456:789a:1::23"}
	encoded, err := encodeDeviceActivityQuery(query)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseInternalDeviceActivityQuery(encoded)
	if err != nil || !reflect.DeepEqual(parsed, query) {
		t.Fatalf("addresses did not round-trip: %#v err=%v", parsed, err)
	}
}
