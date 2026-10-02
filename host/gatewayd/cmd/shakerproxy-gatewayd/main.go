package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"shakerproxy.dev/shakerproxy/host/gatewayd/internal/daemon"
)

func main() {
	socket := flag.String("socket", "/run/shakerproxy/gatewayd.sock", "Unix socket path")
	trafficSocket := flag.String("traffic-socket", "/run/shakerproxy-cloud-policy/policy.sock", "traffic policy Unix socket path")
	trafficSocketGroup := flag.String("traffic-socket-group", "shakerproxy-cloud", "group allowed to use the traffic policy socket")
	statePath := flag.String("state", "/var/lib/shakerproxy/gatewayd/state.json", "managed state path")
	trafficPolicyPath := flag.String("traffic-policy", "/var/lib/shakerproxy/gatewayd/traffic-policy.json", "durable traffic policy path")
	trafficRuntimePath := flag.String("traffic-runtime", "/var/lib/shakerproxy/traffic/policy.json", "unprivileged traffic runtime policy path")
	cloudTrafficPolicyStatusPath := flag.String("cloud-traffic-policy-status", "/var/lib/shakerproxy/traffic-policy/status.json", "Fleet traffic policy ownership status path")
	trafficPolicyLockPath := flag.String("traffic-policy-lock", "/run/lock/shakerproxy/traffic-policy.lock", "cross-process traffic policy coordination lock")
	onboardingEndpointsPath := flag.String("onboarding-endpoints", daemon.DefaultOnboardingEndpointsPath, "public lab-side CA onboarding endpoints projection")
	enableNetworkApply := flag.Bool("enable-network-apply", false, "enable production-gated transactional network activation")
	flag.Parse()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	store, err := daemon.OpenStateStore(*statePath)
	if err != nil {
		logger.Error("open state", "error", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	server := daemon.NewServer(store, logger)
	var traffic *daemon.TrafficPolicyManager
	if *enableNetworkApply {
		activation, err := daemon.NewProductionNetworkActivation(store)
		if activation != nil {
			activation.Logger = logger
		}
		if err != nil {
			logger.Error("network activation unavailable", "error", err)
			os.Exit(1)
		}
		// Startup recovery has settled the transaction; re-establish a
		// confirmed plan's runtime state now and keep it in place.
		go activation.KeepConfirmedRuntime(ctx, logger)
		captures, err := daemon.NewProductionCaptureManager()
		if err != nil {
			logger.Error("capture unavailable", "error", err)
			os.Exit(1)
		}
		server = daemon.NewServerWithHostServices(store, logger, activation, captures)
		// Record lab traffic whenever a confirmed lab plan routes.
		go server.RecordLabTraffic(ctx)
		traffic = daemon.NewProductionTrafficPolicyManager(store, *trafficPolicyPath, *trafficRuntimePath, *cloudTrafficPolicyStatusPath, *trafficPolicyLockPath, logger)
		traffic.OnboardingPath = *onboardingEndpointsPath
		if err := traffic.Ensure(ctx); err != nil {
			logger.Error("traffic policy manager unavailable", "error", err)
			os.Exit(1)
		}
		server.SetTrafficPolicyManager(traffic)
	}

	if traffic == nil {
		logger.Info("gateway daemon starting", "socket", *socket)
		if err := server.Serve(ctx, *socket); err != nil {
			logger.Error("gateway daemon stopped", "error", err)
			os.Exit(1)
		}
		return
	}

	errors := make(chan error, 2)
	go func() { errors <- server.Serve(ctx, *socket) }()
	go func() { errors <- traffic.Serve(ctx, *trafficSocket, *trafficSocketGroup) }()
	logger.Info("gateway daemon starting", "socket", *socket, "traffic_socket", *trafficSocket)
	if err := <-errors; err != nil {
		stop()
		logger.Error("gateway daemon stopped", "error", err)
		os.Exit(1)
	}
}
