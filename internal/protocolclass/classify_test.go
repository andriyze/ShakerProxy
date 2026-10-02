package protocolclass

import "testing"

func TestAnalyzerAliasesTargetCatalogEntries(t *testing.T) {
	for name, id := range analyzerAliases {
		if !ValidID(id) {
			t.Fatalf("alias %q targets unknown protocol %q", name, id)
		}
	}
	for id, carrier := range carriers {
		if !ValidID(id) || !ValidID(carrier) {
			t.Fatalf("carrier mapping %q -> %q uses an unknown protocol", id, carrier)
		}
	}
	for _, protocol := range Catalog() {
		if protocol.Label == "" || protocol.Description == "" || !ValidCategory(string(protocol.Category)) || !ValidVisibility(string(protocol.Visibility)) {
			t.Fatalf("incomplete catalog entry: %#v", protocol)
		}
	}
}

func TestNormalizeServicePrefersSpecificAnalyzers(t *testing.T) {
	cases := map[string]string{
		"":                "",
		"ssl":             "tls",
		"quic,ssl":        "quic",
		"ssl,quic":        "quic",
		"http,websocket":  "websocket",
		"ssl,http":        "http",
		"-ssl,mqtt":       "mqtt",
		"failed":          "",
		"unknown":         "",
		"spicy::openvpn":  "openvpn",
		"DNS":             "dns",
		"krb_tcp":         "kerberos",
		"made-up-service": "",
	}
	for input, want := range cases {
		if got := NormalizeService(input); got != want {
			t.Errorf("NormalizeService(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestClassifyUsesAnalyzerThenPortThenUnknown(t *testing.T) {
	cases := []struct {
		name        string
		observation Observation
		protocol    string
		evidence    Evidence
		visibility  Visibility
		exotic      bool
	}{
		{"analyzer wins over port", Observation{Transport: "tcp", Service: "mqtt", ServerPort: 443}, "mqtt", EvidenceAnalyzer, VisibilityCleartext, true},
		{"well-known port", Observation{Transport: "udp", ServerPort: 51820}, "wireguard", EvidencePort, VisibilityOpaque, true},
		{"transport-specific port", Observation{Transport: "udp", ServerPort: 443}, "quic", EvidencePort, VisibilityEncryptedMetadata, false},
		{"tcp 443 is tls", Observation{Transport: "TCP", ServerPort: 443}, "tls", EvidencePort, VisibilityEncryptedMetadata, false},
		{"intercepted tls is decrypted", Observation{Transport: "tcp", Service: "ssl", ServerPort: 443, Intercepted: true}, "tls", EvidenceAnalyzer, VisibilityDecrypted, false},
		{"intercepting does not decrypt vpn", Observation{Transport: "udp", ServerPort: 1194, Intercepted: true}, "openvpn", EvidencePort, VisibilityOpaque, true},
		{"reversed privileged port", Observation{Transport: "udp", ServerPort: 50123, ClientPort: 123}, "ntp", EvidencePort, VisibilityCleartext, false},
		{"ephemeral client port ignored", Observation{Transport: "tcp", ServerPort: 40000, ClientPort: 5432}, UnknownTCP, EvidenceUnclassified, VisibilityOpaque, true},
		{"unknown udp", Observation{Transport: "udp", ServerPort: 34567}, UnknownUDP, EvidenceUnclassified, VisibilityOpaque, true},
		{"icmp", Observation{Transport: "icmp"}, "icmp", EvidenceAnalyzer, VisibilityCleartext, false},
		{"zeek names icmpv6 icmp", Observation{Transport: "icmp", IPv6: true}, "icmpv6", EvidenceAnalyzer, VisibilityCleartext, false},
		{"suricata names icmpv6", Observation{Transport: "IPv6-ICMP"}, "icmpv6", EvidenceAnalyzer, VisibilityCleartext, false},
		{"no evidence", Observation{}, UnknownIP, EvidenceUnclassified, VisibilityOpaque, true},
		{"failed analyzer falls back to port", Observation{Transport: "tcp", Service: "failed", ServerPort: 502}, "modbus", EvidencePort, VisibilityCleartext, true},
		{"tls on 853 is dns over tls", Observation{Transport: "tcp", Service: "ssl", ServerPort: 853}, "dot", EvidenceAnalyzer, VisibilityEncryptedMetadata, true},
		{"tls on 5228 is google push", Observation{Transport: "tcp", Service: "ssl", ServerPort: 5228}, "fcm", EvidenceAnalyzer, VisibilityEncryptedMetadata, true},
		{"quic on udp 853 is dns over quic", Observation{Transport: "udp", Service: "quic,ssl", ServerPort: 853}, "doq", EvidenceAnalyzer, VisibilityEncryptedMetadata, true},
		{"dns wire format on 5353 is mdns", Observation{Transport: "udp", Service: "dns", ServerPort: 5353}, "mdns", EvidenceAnalyzer, VisibilityCleartext, false},
		{"carrier must match the analyzer", Observation{Transport: "tcp", Service: "http", ServerPort: 853}, "http", EvidenceAnalyzer, VisibilityCleartext, false},
		{"specific analyzer beats a carrier port", Observation{Transport: "tcp", Service: "mqtt", ServerPort: 8883}, "mqtt", EvidenceAnalyzer, VisibilityCleartext, true},
	}
	for _, test := range cases {
		got := Classify(test.observation)
		if got.Protocol != test.protocol || got.Evidence != test.evidence || got.Visibility != test.visibility || got.Exotic != test.exotic || got.Label == "" {
			t.Errorf("%s: Classify(%+v) = %+v", test.name, test.observation, got)
		}
	}
}

func TestCatalogIsDefensiveCopy(t *testing.T) {
	first := Catalog()
	for index := range first {
		if len(first[index].Ports) > 0 {
			first[index].Ports[0].Number = 1
			break
		}
	}
	protocol, _ := Lookup("http")
	protocol.Ports[0].Number = 2
	if Classify(Observation{Transport: "tcp", ServerPort: 80}).Protocol != "http" {
		t.Fatal("catalog mutation leaked into classification")
	}
	again, _ := Lookup("http")
	if again.Ports[0].Number != 80 {
		t.Fatal("Lookup returned shared port slice")
	}
}

// On the test VM the single-arm recording now keeps the network's broadcast:
// UniFi gear announcing itself on UDP 10001, and devices broadcasting on
// ports no known protocol uses. Both are local discovery, not servers.
func TestBroadcastChatterIsLocalDiscovery(t *testing.T) {
	ubnt := Classify(Observation{Transport: "udp", ServerPort: 10001, ToBroadcast: true})
	if ubnt.Protocol != "ubnt-discovery" || ubnt.Category != CategoryLocalDiscovery {
		t.Fatalf("UDP 10001 = %+v", ubnt)
	}
	unknown := Classify(Observation{Transport: "udp", ServerPort: 58866, ToBroadcast: true})
	if unknown.Protocol != LocalBroadcast || unknown.Category != CategoryLocalDiscovery {
		t.Fatalf("broadcast to an unknown port = %+v", unknown)
	}
	if unicast := Classify(Observation{Transport: "udp", ServerPort: 58866}); unicast.Protocol != UnknownUDP {
		t.Fatalf("unicast to an unknown port = %+v", unicast)
	}
}
