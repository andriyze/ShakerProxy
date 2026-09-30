package main

import (
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func TestAPIBaseIsPinnedToHTTPSLoopback(t *testing.T) {
	accepted := []string{"https://127.0.0.1:8443", "https://[::1]:8443", "https://localhost:8443"}
	for _, value := range accepted {
		parsed, _ := url.Parse(value)
		if !validLocalAPIBase(parsed) {
			t.Fatalf("rejected safe local API base %q", value)
		}
	}
	for _, value := range []string{"http://127.0.0.1:8443", "https://example.com", "https://user@localhost:8443", "https://localhost:8443/path", "https://localhost:8443?x=1"} {
		parsed, _ := url.Parse(value)
		if validLocalAPIBase(parsed) {
			t.Fatalf("accepted unsafe API base %q", value)
		}
	}
}

func TestPrivateCredentialFileRejectsBroadPermissionsAndSymlinks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("lgt_secret\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readBoundedRegularFile(path, 512, true); err == nil {
		t.Fatal("accepted broadly readable credential file")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if data, err := readBoundedRegularFile(path, 512, true); err != nil || string(data) != "lgt_secret\n" {
		t.Fatalf("safe credential rejected: %q %v", data, err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readBoundedRegularFile(link, 512, true); err == nil {
		t.Fatal("accepted credential symlink")
	}
}
