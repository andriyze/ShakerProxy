package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"shakerproxy.dev/shakerproxy/internal/capture"
)

func main() {
	root := flag.String("root", capture.DefaultRoot, "capture state root")
	sessionID := flag.String("session-id", "", "validated capture session ID")
	flag.Parse()
	if *root != capture.DefaultRoot || !capture.ValidSessionID(*sessionID) {
		fmt.Fprintln(os.Stderr, "capture worker requires the fixed state root and a valid session ID")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	worker := capture.Worker{Store: capture.Store{Root: *root}}
	if err := worker.Run(ctx, *sessionID); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
