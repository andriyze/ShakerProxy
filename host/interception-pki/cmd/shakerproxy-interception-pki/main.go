package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"shakerproxy.dev/shakerproxy/internal/interceptionpki"
)

const version = "0.1.0-dev.1"

func main() {
	if len(os.Args) == 2 && os.Args[1] == "version" {
		fmt.Println(version)
		return
	}
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: shakerproxy-interception-pki [version]")
		os.Exit(2)
	}
	owner, err := privateOwner()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	status, err := interceptionpki.Ensure(interceptionpki.Options{
		PrivateRoot:  envOr("SHAKERPROXY_INTERCEPTION_PKI_ROOT", "/var/lib/shakerproxy/mitmproxy"),
		PublicRoot:   envOr("SHAKERPROXY_PUBLIC_ROOT", "/var/lib/shakerproxy/public"),
		CommonName:   envOr("SHAKERPROXY_INTERCEPTION_CA_NAME", "ShakerProxy Interception CA"),
		PrivateOwner: owner,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	encoded, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(string(encoded))
}

func privateOwner() (*interceptionpki.FileOwner, error) {
	uid, err := strconv.Atoi(envOr("SHAKERPROXY_INTERCEPTION_UID", "65532"))
	if err != nil || uid < 0 {
		return nil, fmt.Errorf("SHAKERPROXY_INTERCEPTION_UID must be a non-negative integer")
	}
	gid, err := strconv.Atoi(envOr("SHAKERPROXY_INTERCEPTION_GID", "65532"))
	if err != nil || gid < 0 {
		return nil, fmt.Errorf("SHAKERPROXY_INTERCEPTION_GID must be a non-negative integer")
	}
	return &interceptionpki.FileOwner{UID: uid, GID: gid}, nil
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
