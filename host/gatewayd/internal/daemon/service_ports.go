package daemon

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
)

var ssProcessPattern = regexp.MustCompile(`\(\("([^"\r\n]{1,64})"`)

// managementCAPath is the public management CA; a listener on 8443 whose
// certificate chains to it is ShakerProxy's own edge.
var (
	managementCAPath = "/var/lib/shakerproxy/public/management-ca.crt"
	managementPort   = 8443
)

func inspectServicePortPlan(ctx context.Context) (gatewayprotocol.ServicePortPlan, error) {
	command := exec.CommandContext(ctx, "/usr/bin/ss", "-H", "-lntup")
	var output diagnosticCommandOutput
	command.Stdout, command.Stderr = &output, &output
	err := command.Run()
	var listeners []gatewayprotocol.PortListener
	if errors.Is(err, os.ErrNotExist) {
		listeners, err = inspectProcNetListeners()
	} else if err == nil && !output.Truncated {
		listeners, err = parseSSListeners(string(output.Bytes))
	} else {
		return gatewayprotocol.ServicePortPlan{}, errors.New("fixed socket-owner inspection failed")
	}
	if err != nil {
		return gatewayprotocol.ServicePortPlan{}, err
	}
	plan := gatewayprotocol.ServicePortPlan{Schema: 1, GeneratedAt: time.Now().UTC(), Reservations: []gatewayprotocol.PortReservation{}}
	for _, listener := range listeners {
		if isResolvedStubListener(listener) {
			plan.SystemdResolvedStub = true
		}
	}
	plan.ResolverHandling = "NO_STUB_DETECTED"
	if plan.SystemdResolvedStub {
		plan.ResolverHandling = "PRESERVE_STUB_BIND_LAB_ADDRESS_ONLY"
	}
	needs := []struct {
		transport        string
		port             int
		purpose, binding string
	}{{"udp", 53, "local plain DNS", "lab-interface-only"}, {"tcp", 53, "local plain DNS", "lab-interface-only"}, {"tcp", 443, "local DNS-over-HTTPS", "lab-interface-only"}, {"udp", 443, "local DNS-over-QUIC", "lab-interface-only"}, {"tcp", 853, "local DNS-over-TLS", "lab-interface-only"}, {"udp", 853, "local DNS-over-QUIC", "lab-interface-only"}, {"tcp", 8443, "management HTTPS", "configured-management-address"}}
	for _, need := range needs {
		entry := gatewayprotocol.PortReservation{Transport: need.transport, Port: need.port, Purpose: need.purpose, IntendedBinding: need.binding, State: "FREE", Action: "AVAILABLE", Listeners: []gatewayprotocol.PortListener{}}
		for _, listener := range listeners {
			if listener.Transport != need.transport || listener.Port != need.port {
				continue
			}
			entry.Listeners = append(entry.Listeners, listener)
			if strings.HasPrefix(listener.Process, "shakerproxy") || listener.Process == "caddy" || isShakerProxyManagementListener(ctx, listener) {
				entry.State = "OWNED_EXPECTED"
				entry.Action = "PRESERVE_SHAKERPROXY_OWNER"
			} else if isResolvedStubListener(listener) {
				if entry.State == "FREE" {
					entry.State = "COEXIST"
					entry.Action = "PRESERVE_STUB_BIND_LAB_ADDRESS_ONLY"
				}
			} else {
				entry.State = "POTENTIAL_CONFLICT"
				entry.Action = "REVIEW_OR_REBIND_BEFORE_ENABLE"
			}
		}
		plan.Reservations = append(plan.Reservations, entry)
	}
	return plan, nil
}

func inspectProcNetListeners() ([]gatewayprotocol.PortListener, error) {
	files := []struct {
		path      string
		transport string
		ipv6      bool
	}{
		{"/proc/net/tcp", "tcp", false},
		{"/proc/net/tcp6", "tcp", true},
		{"/proc/net/udp", "udp", false},
		{"/proc/net/udp6", "udp", true},
	}
	listeners := []gatewayprotocol.PortListener{}
	for _, file := range files {
		contents, err := readBoundedDiagnosticFile(file.path, 1<<20)
		if err != nil {
			return nil, errors.New("kernel socket inventory is unavailable")
		}
		parsed, err := parseProcNetListeners(string(contents), file.transport, file.ipv6)
		if err != nil {
			return nil, err
		}
		if len(listeners)+len(parsed) > 4096 {
			return nil, errors.New("kernel socket inventory is too large")
		}
		listeners = append(listeners, parsed...)
	}
	return listeners, nil
}

func parseProcNetListeners(value, transport string, ipv6 bool) ([]gatewayprotocol.PortListener, error) {
	result := []gatewayprotocol.PortListener{}
	lines := strings.Split(value, "\n")
	for index, line := range lines {
		if index == 0 || strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			return nil, errors.New("kernel socket inventory is malformed")
		}
		state := strings.ToUpper(fields[3])
		if (transport == "tcp" && state != "0A") || (transport == "udp" && state != "07" && state != "0A") {
			continue
		}
		address, port, ok := splitProcNetAddress(fields[1], ipv6)
		if !ok {
			return nil, errors.New("kernel socket address is malformed")
		}
		result = append(result, gatewayprotocol.PortListener{Transport: transport, Address: address, Port: port})
	}
	return result, nil
}

func splitProcNetAddress(value string, ipv6 bool) (string, int, bool) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 || (len(parts[0]) != 8 && len(parts[0]) != 32) {
		return "", 0, false
	}
	raw, err := hex.DecodeString(parts[0])
	if err != nil || ipv6 != (len(raw) == net.IPv6len) {
		return "", 0, false
	}
	for start := 0; start < len(raw); start += 4 {
		raw[start], raw[start+3] = raw[start+3], raw[start]
		raw[start+1], raw[start+2] = raw[start+2], raw[start+1]
	}
	portValue, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil || portValue == 0 {
		return "", 0, false
	}
	return net.IP(raw).String(), int(portValue), true
}

func parseSSListeners(value string) ([]gatewayprotocol.PortListener, error) {
	if len(value) > 64<<10 {
		return nil, errors.New("socket-owner output exceeds limit")
	}
	result := []gatewayprotocol.PortListener{}
	for _, line := range strings.Split(value, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) < 5 || len(result) >= 4096 {
			return nil, errors.New("socket-owner output is invalid or too large")
		}
		transport := strings.ToLower(fields[0])
		if transport != "tcp" && transport != "udp" {
			continue
		}
		address, port, ok := splitSSAddress(fields[4])
		if !ok {
			continue
		}
		process := ""
		if matches := ssProcessPattern.FindStringSubmatch(line); len(matches) == 2 {
			process = matches[1]
		}
		result = append(result, gatewayprotocol.PortListener{Transport: transport, Address: address, Port: port, Process: process})
	}
	return result, nil
}

func splitSSAddress(value string) (string, int, bool) {
	index := strings.LastIndex(value, ":")
	if index < 0 {
		return "", 0, false
	}
	port, err := strconv.Atoi(value[index+1:])
	if err != nil || port < 1 || port > 65535 {
		return "", 0, false
	}
	address := strings.Trim(value[:index], "[]")
	if percent := strings.LastIndex(address, "%"); percent >= 0 {
		address = address[:percent]
	}
	if address == "" {
		address = "*"
	}
	return address, port, true
}
func isLoopbackBinding(value string) bool {
	address := net.ParseIP(value)
	return address != nil && address.IsLoopback()
}
func isResolvedProcess(value string) bool {
	return value == "systemd-resolve" || value == "systemd-resolved"
}

// isResolvedStubListener recognises the systemd-resolved stub listeners. The
// hardened gateway service usually cannot see other processes' sockets, so ss
// reports no owner; the stub's dedicated loopback addresses (127.0.0.53 and
// the 127.0.0.54 proxy stub) identify it then.
func isResolvedStubListener(listener gatewayprotocol.PortListener) bool {
	if listener.Port != 53 || !isLoopbackBinding(listener.Address) {
		return false
	}
	if listener.Process != "" {
		return isResolvedProcess(listener.Process)
	}
	return listener.Address == "127.0.0.53" || listener.Address == "127.0.0.54"
}

// isShakerProxyManagementListener recognises the ShakerProxy edge that Docker
// publishes on loopback 8443 (docker-proxy, or no visible owner under the
// hardened service) by verifying its certificate against the management CA.
func isShakerProxyManagementListener(ctx context.Context, listener gatewayprotocol.PortListener) bool {
	if listener.Transport != "tcp" || listener.Port != managementPort || !isLoopbackBinding(listener.Address) {
		return false
	}
	if listener.Process != "" && listener.Process != "docker-proxy" {
		return false
	}
	authority, err := os.ReadFile(managementCAPath)
	if err != nil {
		return false
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(authority) {
		return false
	}
	dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 2 * time.Second}, Config: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: listener.Address}}
	probeContext, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	connection, err := dialer.DialContext(probeContext, "tcp", net.JoinHostPort(listener.Address, strconv.Itoa(listener.Port)))
	if err != nil {
		return false
	}
	_ = connection.Close()
	return true
}

func probeConnectivity(ctx context.Context) gatewayprotocol.ConnectivityReport {
	report := gatewayprotocol.ConnectivityReport{Schema: 1, GeneratedAt: time.Now().UTC(), Probes: []gatewayprotocol.ConnectivityProbe{}}
	for _, target := range []struct{ name, address string }{{"dns-independent-https-ipv4", "1.1.1.1:443"}, {"plain-dns-tcp-ipv4", "1.1.1.1:53"}} {
		started := time.Now()
		probe := gatewayprotocol.ConnectivityProbe{Name: target.name, Target: target.address, Status: gatewayprotocol.DiagnosticFail}
		var err error
		if target.name == "dns-independent-https-ipv4" {
			err = probeFixedHTTPS(ctx, target.address)
		} else {
			dialer := net.Dialer{Timeout: 3 * time.Second}
			var connection net.Conn
			connection, err = dialer.DialContext(ctx, "tcp", target.address)
			if err == nil {
				err = connection.Close()
			}
		}
		probe.LatencyMillis = time.Since(started).Milliseconds()
		if err == nil {
			probe.Status = gatewayprotocol.DiagnosticPass
			probe.Detail = "protocol connection succeeded without DNS resolution"
		} else {
			probe.Detail = boundedDiagnosticText(err.Error(), 160)
		}
		report.Probes = append(report.Probes, probe)
	}
	report.DNSIndependentHTTPS = report.Probes[0].Status == gatewayprotocol.DiagnosticPass
	report.PlainDNSPort53 = report.Probes[1].Status == gatewayprotocol.DiagnosticPass
	report.RestrictedPort53 = report.DNSIndependentHTTPS && !report.PlainDNSPort53
	return report
}

func probeFixedHTTPS(ctx context.Context, address string) error {
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	transport := &http.Transport{
		Proxy: nil,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: "one.one.one.one",
		},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, address)
		},
		ResponseHeaderTimeout: 3 * time.Second,
		DisableCompression:    true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodHead, "https://one.one.one.one/", nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 100 || response.StatusCode > 599 {
		return errors.New("fixed-address HTTPS returned an invalid status")
	}
	return nil
}
