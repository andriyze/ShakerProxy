package capture

import "testing"

func TestSystemdCommandAllowlist(t *testing.T) {
	unit := "shakerproxy-capture@00112233445566778899aabbccddeeff.service"
	for _, arguments := range [][]string{{"start", unit}, {"stop", "--no-block", unit}, {"is-active", "--quiet", unit}} {
		if !allowedSystemdCommand("/usr/bin/systemctl", arguments) {
			t.Fatalf("expected command to be allowed: %#v", arguments)
		}
	}
	for _, arguments := range [][]string{{"start", "ssh.service"}, {"restart", unit}, {"stop", "shakerproxy-capture@../../ssh.service"}} {
		if allowedSystemdCommand("/usr/bin/systemctl", arguments) {
			t.Fatalf("unsafe command unexpectedly allowed: %#v", arguments)
		}
	}
}
