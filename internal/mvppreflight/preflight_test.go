package mvppreflight

import "testing"

func TestEvaluateIPv4MVPPassesOnlyWithoutIPv6Path(t *testing.T) {
	report, err := EvaluateIPv4MVP(Snapshot{Interface: "lab0"})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Supported {
		t.Fatalf("clean IPv4-only snapshot failed: %#v", report)
	}
	if len(report.Checks) != 5 {
		t.Fatalf("unexpected check count: %d", len(report.Checks))
	}
}

func TestEvaluateIPv4MVPRejectsIPv6BypassSignals(t *testing.T) {
	report, err := EvaluateIPv4MVP(Snapshot{
		Interface:        "lab0",
		IPv6Addresses:    []string{"fe80::1", "2001:db8::2"},
		IPv6DefaultRoute: true,
		AcceptRA:         1,
		Autoconf:         1,
		IPv6Forwarding:   1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Supported {
		t.Fatal("IPv6-capable test interface was accepted for IPv4-only MVP")
	}
	for _, check := range report.Checks {
		if check.Status != "FAIL" {
			t.Fatalf("expected every deliberately unsafe check to fail: %#v", report.Checks)
		}
	}
}

func TestEvaluateIPv4MVPRejectsInvalidSnapshot(t *testing.T) {
	if _, err := EvaluateIPv4MVP(Snapshot{Interface: "bad iface"}); err == nil {
		t.Fatal("unsafe interface name was accepted")
	}
	if _, err := EvaluateIPv4MVP(Snapshot{Interface: "lab0", IPv6Addresses: []string{"not-an-ip"}}); err == nil {
		t.Fatal("invalid IPv6 evidence was accepted")
	}
}
