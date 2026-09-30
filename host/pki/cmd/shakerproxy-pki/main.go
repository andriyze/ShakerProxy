package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"

	"shakerproxy.dev/shakerproxy/internal/managementpki"
)

func main() {
	flags := flag.NewFlagSet("shakerproxy-pki", flag.ExitOnError)
	etcRoot := flags.String("etc-root", "/etc/shakerproxy", "ShakerProxy configuration root")
	dataRoot := flags.String("data-root", "/var/lib/shakerproxy", "ShakerProxy data root")
	edgeGID := flags.Int("edge-gid", -1, "numeric shakerproxy-edge group ID")
	testing := flags.Bool("testing", false, "allow unprivileged test ownership")
	_ = flags.Parse(os.Args[1:])
	if flags.NArg() != 1 || flags.Arg(0) != "ensure" {
		fmt.Fprintln(os.Stderr, "usage: shakerproxy-pki [options] ensure")
		os.Exit(2)
	}
	if value := os.Getenv("SHAKERPROXY_EDGE_GID"); *edgeGID < 0 && value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			fmt.Fprintln(os.Stderr, "invalid SHAKERPROXY_EDGE_GID")
			os.Exit(2)
		}
		*edgeGID = parsed
	}
	status, err := managementpki.Ensure(managementpki.Options{EtcRoot: *etcRoot, DataRoot: *dataRoot, EdgeGID: *edgeGID, Testing: *testing})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	_ = json.NewEncoder(os.Stdout).Encode(status)
}
