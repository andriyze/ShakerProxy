package secretfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadTokenUsesDescriptorBoundRegularFile(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "token")
	value := strings.Repeat("a", 32)
	if err := os.WriteFile(target, []byte(value+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	token, err := LoadToken(target)
	if err != nil || string(token) != value {
		t.Fatalf("safe token was not loaded: %q %v", token, err)
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadToken(link); err == nil {
		t.Fatal("symlink token was accepted")
	}
	short := filepath.Join(directory, "short")
	if err := os.WriteFile(short, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadToken(short); err == nil {
		t.Fatal("short token was accepted")
	}
}

func TestLoadPrivateTokenValidatesOpenedDescriptorPermissionsAndOwner(t *testing.T) {
	directory := t.TempDir()
	value := "lgt_" + strings.Repeat("p", 40)
	private := filepath.Join(directory, "private-token")
	if err := os.WriteFile(private, []byte(value+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	token, err := LoadPrivateToken(private, uint32(os.Geteuid()))
	if err != nil || string(token) != value {
		t.Fatalf("private token was not loaded: %q %v", token, err)
	}

	for _, mode := range []os.FileMode{0o640, 0o604, 0o644, 0o660} {
		if err := os.Chmod(private, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadPrivateToken(private, uint32(os.Geteuid())); err == nil {
			t.Fatalf("token with permissions %04o was accepted", mode)
		}
	}
	if err := os.Chmod(private, 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivateToken(private, uint32(os.Geteuid()+1)); err == nil && os.Geteuid() != 0 {
		t.Fatal("token owned by an unexpected non-root user was accepted")
	}

	link := filepath.Join(directory, "private-link")
	if err := os.Symlink(private, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivateToken(link, uint32(os.Geteuid())); err == nil {
		t.Fatal("private-token symlink was accepted")
	}
}
