//go:build linux

package daemon

import "testing"

func TestParseSSHSocketsFindsCustomPortAndMapsInterface(t *testing.T) {
	output := "0 0 10.23.0.15:2222 192.0.2.100:49153 users:((\"sshd\",pid=42,fd=4))\n" +
		"0 0 10.23.0.15:22 192.0.2.101:49154 users:((\"not-ssh\",pid=43,fd=4))\n"
	sessions, err := parseSSHSockets(output, map[string][]string{"wan0": {"10.23.0.15/24"}}, map[uint16]bool{2222: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 {
		t.Fatalf("unexpected sessions: %+v", sessions)
	}
	got := sessions[0]
	if got.SourceAddress != "192.0.2.100" || got.SourcePort != 49153 || got.DestinationAddress != "10.23.0.15" || got.DestinationPort != 2222 || got.DestinationInterface != "wan0" {
		t.Fatalf("unexpected SSH session: %+v", got)
	}
}

func TestParseSSHSocketsSupportsIPv6SessionProcessName(t *testing.T) {
	output := "0 0 [2001:db8::10]:22 [2001:db8::20]:49153 users:((\"sshd-session\",pid=42,fd=4))\n"
	sessions, err := parseSSHSockets(output, map[string][]string{"mgmt0": {"2001:db8::10/64"}}, map[uint16]bool{22: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || sessions[0].DestinationInterface != "mgmt0" || sessions[0].SourceAddress != "2001:db8::20" {
		t.Fatalf("unexpected IPv6 SSH session: %+v", sessions)
	}
}

func TestParseSSHSocketsRejectsMalformedSSHEvidence(t *testing.T) {
	output := "0 0 broken 192.0.2.100:49153 users:((\"sshd\",pid=42,fd=4))\n"
	if _, err := parseSSHSockets(output, nil, map[uint16]bool{22: true}); err == nil {
		t.Fatal("malformed SSH-owned socket row was accepted")
	}
}
