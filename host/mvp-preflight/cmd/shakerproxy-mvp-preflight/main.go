package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"shakerproxy.dev/shakerproxy/internal/mvppreflight"
)

func main() {
	flags := flag.NewFlagSet("shakerproxy-mvp-preflight", flag.ExitOnError)
	interfaceName := flags.String("test-interface", "", "ShakerProxy client/test interface")
	_ = flags.Parse(os.Args[1:])
	if flags.NArg() != 0 || strings.TrimSpace(*interfaceName) == "" {
		fmt.Fprintln(os.Stderr, "usage: shakerproxy-mvp-preflight --test-interface <interface>")
		os.Exit(2)
	}
	snapshot, err := collect(strings.TrimSpace(*interfaceName))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	report, err := mvppreflight.EvaluateIPv4MVP(snapshot)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	encoded, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(encoded))
	if !report.Supported {
		os.Exit(3)
	}
}

func collect(interfaceName string) (mvppreflight.Snapshot, error) {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return mvppreflight.Snapshot{}, fmt.Errorf("find test interface: %w", err)
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return mvppreflight.Snapshot{}, fmt.Errorf("read test-interface addresses: %w", err)
	}
	ipv6 := make([]string, 0)
	for _, raw := range addresses {
		value := raw.String()
		if separator := strings.LastIndexByte(value, '/'); separator >= 0 {
			value = value[:separator]
		}
		ip := net.ParseIP(value)
		if ip != nil && ip.To4() == nil {
			ipv6 = append(ipv6, ip.String())
		}
	}
	acceptRA, err := readIPv6Sysctl(interfaceName, "accept_ra")
	if err != nil {
		return mvppreflight.Snapshot{}, err
	}
	autoconf, err := readIPv6Sysctl(interfaceName, "autoconf")
	if err != nil {
		return mvppreflight.Snapshot{}, err
	}
	forwarding, err := readIPv6Sysctl(interfaceName, "forwarding")
	if err != nil {
		return mvppreflight.Snapshot{}, err
	}
	defaultRoute, err := hasIPv6DefaultRoute(interfaceName)
	if err != nil {
		return mvppreflight.Snapshot{}, err
	}
	return mvppreflight.Snapshot{
		Interface:        interfaceName,
		IPv6Addresses:    ipv6,
		IPv6DefaultRoute: defaultRoute,
		AcceptRA:         acceptRA,
		Autoconf:         autoconf,
		IPv6Forwarding:   forwarding,
	}, nil
}

func readIPv6Sysctl(interfaceName, key string) (int, error) {
	if strings.ContainsAny(interfaceName, "/\x00") || strings.ContainsAny(key, "/\x00") {
		return 0, errors.New("invalid IPv6 sysctl path component")
	}
	path := filepath.Join("/proc/sys/net/ipv6/conf", interfaceName, key)
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("read %s: %w", path, err)
	}
	value, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", path, err)
	}
	return value, nil
}

func hasIPv6DefaultRoute(interfaceName string) (bool, error) {
	ipBinary, err := exec.LookPath("ip")
	if err != nil {
		return false, errors.New("iproute2 is required for MVP preflight")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, ipBinary, "-6", "route", "show", "default", "dev", interfaceName)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8"}
	output, err := command.Output()
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && len(exit.Stderr) == 0 {
			return false, nil
		}
		return false, fmt.Errorf("inspect IPv6 default route: %w", err)
	}
	return strings.TrimSpace(string(output)) != "", nil
}
