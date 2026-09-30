package main

import (
	"flag"
	"fmt"
	"os"

	"shakerproxy.dev/shakerproxy/internal/capabilityregistry"
	"shakerproxy.dev/shakerproxy/internal/recoveryobjectives"
)

func main() {
	root := flag.String("root", ".", "repository root")
	flag.Parse()
	bundle, err := capabilityregistry.Load(*root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "capability registry invalid:", err)
		os.Exit(1)
	}
	recovery, err := recoveryobjectives.Load(*root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "recovery objective registry invalid:", err)
		os.Exit(1)
	}
	fmt.Printf("capability registry %s valid: %d features, %d glossary terms, %d certified environments; recovery registry %s valid: %d objectives\n", bundle.Revision, len(bundle.Features), len(bundle.Glossary), len(bundle.SupportMatrix.Environments), recovery.Revision, len(recovery.Objectives))
}
