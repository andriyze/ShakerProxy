//go:build linux

package analyzer

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestParserCredentialIsolationClearsGroupsAndSecretAccess(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("credential transition proof requires a root-owned test container")
	}
	secretDirectory := t.TempDir()
	secret := filepath.Join(secretDirectory, "broker-token")
	if err := os.WriteFile(secret, []byte(strings.Repeat("s", 32)), 0o400); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("/bin/sh", "-c", `test "$(id -u)" = 65533 && test "$(id -g)" = 65533 && test "$(id -G)" = 65533 && test ! -r "$1"`, "parser-proof", secret)
	if err := isolateParserCommand(command); err != nil {
		t.Fatal(err)
	}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("isolated parser credentials did not hold: %v: %s", err, output)
	}
}
