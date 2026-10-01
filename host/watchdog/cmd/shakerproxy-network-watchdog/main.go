package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"shakerproxy.dev/shakerproxy/internal/configlock"
	"shakerproxy.dev/shakerproxy/internal/networkapply"
	"shakerproxy.dev/shakerproxy/internal/networktransaction"
)

const usage = `Usage: shakerproxy-network-watchdog --apply-id <apply-id>

Internal helper that shakerproxy-gatewayd starts while a network change is being
applied. It rolls the change back if it is not confirmed in time. You should
not need to run it by hand; check progress with "shakerproxy status" and
"shakerproxy logs gatewayd".
`

func main() {
	flags := flag.NewFlagSet("shakerproxy-network-watchdog", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	applyID := flags.String("apply-id", "", "daemon-generated network apply ID")
	parseErr := flags.Parse(os.Args[1:])
	if errors.Is(parseErr, flag.ErrHelp) {
		fmt.Fprint(os.Stdout, usage)
		return
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if parseErr != nil || !networktransaction.ValidApplyID(*applyID) || flags.NArg() != 0 {
		logger.Error("invalid watchdog invocation")
		switch {
		case parseErr != nil:
			fmt.Fprintf(os.Stderr, "shakerproxy-network-watchdog: %v\n\n", parseErr)
		case *applyID == "":
			fmt.Fprint(os.Stderr, "shakerproxy-network-watchdog: --apply-id is required\n\n")
		case flags.NArg() != 0:
			fmt.Fprintf(os.Stderr, "shakerproxy-network-watchdog: unexpected argument %q\n\n", flags.Arg(0))
		default:
			fmt.Fprintf(os.Stderr, "shakerproxy-network-watchdog: %q is not a valid apply ID (it looks like apply-<hex>)\n\n", *applyID)
		}
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	store := networktransaction.FileStore{Root: networktransaction.DefaultTransactionRoot}
	executor := networkapply.RollbackExecutor{Store: store, HostRoot: "/", Machine: networkapply.OSRollbackMachine{}, DHCP4: networkapply.OSDHCP4Service{}, AccessPoint: networkapply.OSAccessPointService{}, IPv6: networkapply.OSIPv6Machine{}}
	rollback := func(rollbackContext context.Context, manifest networktransaction.WatchdogManifest) error {
		// The gateway daemon holds the lock while it finishes its own health
		// checks and rollback; wait long enough for that to end.
		lockContext, cancel := context.WithTimeout(context.WithoutCancel(rollbackContext), 2*time.Minute)
		defer cancel()
		guard, err := (configlock.Manager{}).Acquire(lockContext, configlock.Request{OperationID: "network-" + strings.TrimPrefix(*applyID, "apply-"), Category: configlock.CategoryNetwork, Actor: "watchdog"})
		if err != nil {
			return err
		}
		defer guard.Release()
		return executor.Execute(rollbackContext, manifest)
	}
	watchdog := networktransaction.Watchdog{Store: store, Waiter: networktransaction.RealDeadlineWaiter{}, Rollback: rollback}
	outcome, err := watchdog.Run(ctx, *applyID)
	if err != nil {
		logger.Error("network watchdog failed", "apply_id", *applyID, "status", outcome.Status, "error", err)
		os.Exit(1)
	}
	logger.Info("network watchdog finished", "apply_id", *applyID, "status", outcome.Status)
}
