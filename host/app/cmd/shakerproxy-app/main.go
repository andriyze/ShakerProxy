package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"shakerproxy.dev/shakerproxy/internal/applifecycle"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: shakerproxy-app validate|start|stop|status")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	timeout := 3 * time.Minute
	if os.Args[1] == "status" || os.Args[1] == "validate" {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	output, err := (applifecycle.Controller{}).Execute(ctx, os.Args[1])
	if len(output) > 0 {
		_, _ = os.Stdout.Write(output)
		if output[len(output)-1] != '\n' {
			fmt.Println()
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
