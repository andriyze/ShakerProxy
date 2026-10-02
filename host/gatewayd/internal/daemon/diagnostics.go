package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"shakerproxy.dev/shakerproxy/internal/capture"
	"shakerproxy.dev/shakerproxy/internal/firewall"
	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/networkplan"
	"shakerproxy.dev/shakerproxy/internal/resourcepressure"
)

const diagnosticSchema = 1

func (s *Server) inspectDiagnostics(ctx context.Context) gatewayprotocol.DiagnosticReport {
	state := s.store.Get()
	report := gatewayprotocol.DiagnosticReport{Schema: diagnosticSchema, GeneratedAt: time.Now().UTC(), Overall: gatewayprotocol.DiagnosticPass, Checks: []gatewayprotocol.DiagnosticCheck{}}
	add := func(check gatewayprotocol.DiagnosticCheck) {
		check.Summary = boundedDiagnosticText(check.Summary, 256)
		if len(check.Observations) > 8 {
			check.Observations = check.Observations[:8]
		}
		for index := range check.Observations {
			check.Observations[index] = boundedDiagnosticText(check.Observations[index], 256)
		}
		report.Checks = append(report.Checks, check)
		if check.Status == gatewayprotocol.DiagnosticFail {
			report.Overall = gatewayprotocol.DiagnosticFail
		} else if report.Overall == gatewayprotocol.DiagnosticPass && (check.Status == gatewayprotocol.DiagnosticWarning || check.Status == gatewayprotocol.DiagnosticUnknown) {
			report.Overall = gatewayprotocol.DiagnosticWarning
		}
	}

	inspection, inspectionErr := inspectHost(ctx)
	if inspectionErr != nil {
		add(diagnosticCheck("interfaces", gatewayprotocol.DiagnosticFail, "Host interfaces could not be inspected", inspectionErr.Error()))
		add(diagnosticCheck("firewall", gatewayprotocol.DiagnosticFail, "Firewall coexistence could not be inspected", inspectionErr.Error()))
	} else {
		managed := map[string]bool{networkplan.LabBridgeName: true, networkplan.InlineBridgeName: true}
		if active := state.activeNetworkPlan(); active != nil {
			for _, planned := range active.Plan.Interfaces {
				managed[planned.CurrentName] = true
			}
		}
		up, down, idleVirtual := countInterfaces(inspection.Interfaces, managed)
		status := gatewayprotocol.DiagnosticPass
		if up == 0 {
			status = gatewayprotocol.DiagnosticFail
		} else if down > 0 {
			status = gatewayprotocol.DiagnosticWarning
		}
		var interfaceNotes []string
		if idleVirtual > 0 {
			interfaceNotes = append(interfaceNotes, fmt.Sprintf("%d idle virtual interface(s), such as unused Docker bridges, are not counted", idleVirtual))
		}
		add(diagnosticCheck("interfaces", status, fmt.Sprintf("%d non-loopback interface(s) up; %d down", up, down), interfaceNotes...))
		firewallStatus := gatewayprotocol.DiagnosticPass
		if inspection.Firewall.SelectedBackend == "" || !inspection.Firewall.ApplyReady {
			firewallStatus = gatewayprotocol.DiagnosticWarning
			if state.OperatingMode == gatewayprotocol.ModeRouted {
				firewallStatus = gatewayprotocol.DiagnosticFail
			}
		}
		add(diagnosticCheck("firewall", firewallStatus, "Firewall backend and coexistence evidence inspected", "selected backend: "+diagnosticValue(inspection.Firewall.SelectedBackend, "unavailable"), fmt.Sprintf("blocking issues: %d", blockingFirewallIssues(inspection.Firewall.Issues))))
	}

	ipv4Default, ipv6Default, routeErr := diagnosticDefaultRoutes()
	if routeErr != nil {
		add(diagnosticCheck("routes", gatewayprotocol.DiagnosticUnknown, "Kernel route tables could not be read", routeErr.Error()))
	} else {
		status := gatewayprotocol.DiagnosticPass
		if ipv4Default == 0 && ipv6Default == 0 {
			status = gatewayprotocol.DiagnosticWarning
		}
		add(diagnosticCheck("routes", status, "Kernel default-route inventory inspected", fmt.Sprintf("IPv4 defaults: %d", ipv4Default), fmt.Sprintf("IPv6 defaults: %d", ipv6Default)))
	}

	nameservers, dnsErr := diagnosticNameserverCount()
	if dnsErr != nil {
		add(diagnosticCheck("dns", gatewayprotocol.DiagnosticUnknown, "Resolver configuration could not be read", dnsErr.Error()))
	} else if nameservers == 0 {
		add(diagnosticCheck("dns", gatewayprotocol.DiagnosticWarning, "No nameserver is declared in resolv.conf"))
	} else {
		add(diagnosticCheck("dns", gatewayprotocol.DiagnosticPass, fmt.Sprintf("%d resolver nameserver(s) configured", nameservers)))
	}
	if portPlan, err := inspectServicePortPlan(ctx); err != nil {
		add(diagnosticCheck("service_ports", gatewayprotocol.DiagnosticUnknown, "Service port ownership could not be inspected", err.Error()))
	} else {
		conflicts := 0
		for _, reservation := range portPlan.Reservations {
			if reservation.State == "POTENTIAL_CONFLICT" {
				conflicts++
			}
		}
		status := gatewayprotocol.DiagnosticPass
		if conflicts > 0 {
			status = gatewayprotocol.DiagnosticWarning
		}
		add(diagnosticCheck("service_ports", status, fmt.Sprintf("%d planned local binding conflict(s); systemd-resolved stub: %t", conflicts, portPlan.SystemdResolvedStub), "resolver handling: "+portPlan.ResolverHandling))
	}

	ipv4Forwarding := readDiagnosticScalar("/proc/sys/net/ipv4/ip_forward")
	ipv6Forwarding := readDiagnosticScalar("/proc/sys/net/ipv6/conf/all/forwarding")
	forwardingStatus := gatewayprotocol.DiagnosticPass
	forwardingSummary := "Forwarding matches the managed operating mode"
	if state.OperatingMode == gatewayprotocol.ModeRouted && ipv4Forwarding != "1" {
		forwardingStatus = gatewayprotocol.DiagnosticFail
		forwardingSummary = "IPv4 forwarding is disabled while routed mode is recorded"
	} else if state.OperatingMode != gatewayprotocol.ModeRouted && ipv4Forwarding == "1" && ipv6Forwarding != "1" && dockerEnablesForwarding(ctx) {
		// Docker turns IPv4 forwarding on for its own containers.
		forwardingSummary = "IPv4 forwarding is on for Docker; ShakerProxy routes no lab traffic until a network plan is confirmed"
	} else if state.OperatingMode != gatewayprotocol.ModeRouted && (ipv4Forwarding == "1" || ipv6Forwarding == "1") {
		forwardingStatus = gatewayprotocol.DiagnosticWarning
		forwardingSummary = "Kernel forwarding is enabled outside confirmed routed mode"
	} else if ipv4Forwarding == "" {
		forwardingStatus = gatewayprotocol.DiagnosticUnknown
		forwardingSummary = "Kernel forwarding state is unavailable"
	}
	add(diagnosticCheck("forwarding", forwardingStatus, forwardingSummary, "IPv4: "+diagnosticValue(ipv4Forwarding, "unknown"), "IPv6: "+diagnosticValue(ipv6Forwarding, "unknown")))

	active := state.activeNetworkPlan()
	dhcpRequired := state.OperatingMode == gatewayprotocol.ModeRouted && active != nil && active.Plan.IPv4.Enabled
	dhcpActive, dhcpKnown := diagnosticServiceActive(ctx, "shakerproxy-dhcp4.service")
	if keaDirectoryBlocked() {
		// Network plans back up and write the DHCPv4 file in /etc/kea.
		add(diagnosticCheck("dhcp", gatewayprotocol.DiagnosticFail, "The gateway service cannot open /etc/kea, so network plans cannot be applied", "Kea 3 makes /etc/kea owned by _kea; fix it with: sudo chown root /etc/kea"))
	} else if !dhcpRequired {
		add(diagnosticCheck("dhcp", gatewayprotocol.DiagnosticPass, "Managed DHCPv4 is not required by the active mode"))
	} else if !dhcpKnown {
		add(diagnosticCheck("dhcp", gatewayprotocol.DiagnosticUnknown, "Managed DHCPv4 service state is unavailable"))
	} else if !dhcpActive {
		add(diagnosticCheck("dhcp", gatewayprotocol.DiagnosticFail, "Managed DHCPv4 is inactive while required"))
	} else {
		add(diagnosticCheck("dhcp", gatewayprotocol.DiagnosticPass, "Managed DHCPv4 service is active"))
	}
	if check, ok := wirelessDiagnostic(ctx, state); ok {
		add(check)
	}

	dockerActive, dockerKnown := diagnosticServiceActive(ctx, "docker.service")
	if !dockerKnown {
		add(diagnosticCheck("docker", gatewayprotocol.DiagnosticUnknown, "Docker service state is unavailable without granting socket access"))
	} else if !dockerActive {
		add(diagnosticCheck("docker", gatewayprotocol.DiagnosticWarning, "Docker service is inactive; packet forwarding remains independent"))
	} else {
		add(diagnosticCheck("docker", gatewayprotocol.DiagnosticPass, "Docker service is active; no Docker socket was opened"))
	}
	add(diagnosticCheck("services", gatewayprotocol.DiagnosticPass, "The privileged gateway service is responding", "network apply: "+enabledDiagnosticValue(s.activation != nil), "capture service: "+enabledDiagnosticValue(s.captures != nil)))

	diskPath := filepath.Dir(s.store.path)
	if s.captures != nil && s.captures.Store.Root != "" {
		diskPath = s.captures.Store.Root
	}
	if disk, err := diagnosticDisk(diskPath); err != nil {
		add(diagnosticCheck("disk", gatewayprotocol.DiagnosticUnknown, "Managed storage capacity is unavailable", err.Error()))
	} else {
		status := gatewayprotocol.DiagnosticPass
		if disk.FreeBytes < capture.DefaultReserveBytes {
			status = gatewayprotocol.DiagnosticFail
		} else if disk.FreeBytes < 2*capture.DefaultReserveBytes || disk.TotalInodes > 0 && disk.FreeInodes*20 < disk.TotalInodes {
			status = gatewayprotocol.DiagnosticWarning
		}
		add(diagnosticCheck("disk", status, "Managed filesystem capacity inspected", fmt.Sprintf("free bytes: %d", disk.FreeBytes), fmt.Sprintf("free inodes: %d", disk.FreeInodes)))
	}
	report.Pressure = inspectResourcePressure(diskPath, report.GeneratedAt)
	pressureStatus := gatewayprotocol.DiagnosticPass
	if report.Pressure.Level == resourcepressure.LevelCritical {
		pressureStatus = gatewayprotocol.DiagnosticFail
	} else if report.Pressure.Level == resourcepressure.LevelDegraded {
		pressureStatus = gatewayprotocol.DiagnosticWarning
	} else if report.Pressure.Level == resourcepressure.LevelUnknown {
		pressureStatus = gatewayprotocol.DiagnosticUnknown
	}
	add(diagnosticCheck("resource_pressure", pressureStatus, "CPU, memory, and disk degradation ladder evaluated", append(append([]string{}, report.Pressure.Causes...), report.Pressure.Actions...)...))

	if synchronized, known := diagnosticTimeSynchronized(ctx); !known {
		add(diagnosticCheck("time_sync", gatewayprotocol.DiagnosticUnknown, "Time synchronization state is unavailable"))
	} else if !synchronized {
		add(diagnosticCheck("time_sync", gatewayprotocol.DiagnosticWarning, "System clock is not reported synchronized"))
	} else {
		add(diagnosticCheck("time_sync", gatewayprotocol.DiagnosticPass, "System clock is reported synchronized"))
	}

	if s.captures == nil {
		add(diagnosticCheck("capture", gatewayprotocol.DiagnosticUnknown, "Capture service is unavailable in this daemon profile"))
		add(diagnosticCheck("packet_drops", gatewayprotocol.DiagnosticUnknown, "No capture-worker drop evidence is available"))
	} else if captures, err := s.captures.List(ctx); err != nil {
		add(diagnosticCheck("capture", gatewayprotocol.DiagnosticFail, "Capture sessions could not be inspected", err.Error()))
		add(diagnosticCheck("packet_drops", gatewayprotocol.DiagnosticUnknown, "Capture-worker drop evidence could not be read"))
	} else {
		active, failed := 0, 0
		var drops, feedEvictions uint64
		for _, item := range captures {
			if item.Active {
				active++
			}
			if item.State == capture.StateFailed || item.State == capture.StateStoragePressure {
				failed++
			}
			if item.Worker != nil {
				drops += item.Worker.KernelDrops + item.Worker.DumpcapDrops
				feedEvictions += item.Worker.AnalyzerFeedEvicted
			}
		}
		captureStatus := gatewayprotocol.DiagnosticPass
		if failed > 0 {
			captureStatus = gatewayprotocol.DiagnosticWarning
		}
		add(diagnosticCheck("capture", captureStatus, fmt.Sprintf("%d capture session(s); %d active; %d failed or storage-limited", len(captures), active, failed), fmt.Sprintf("analyzer feed evictions: %d", feedEvictions)))
		dropStatus := gatewayprotocol.DiagnosticPass
		if drops > 0 {
			dropStatus = gatewayprotocol.DiagnosticWarning
		}
		add(diagnosticCheck("packet_drops", dropStatus, fmt.Sprintf("%d capture-worker packet drop(s) recorded", drops)))
	}
	return report
}

type diagnosticDiskEvidence struct {
	FreeBytes, FreeInodes, TotalInodes uint64
}

func inspectResourcePressure(diskPath string, now time.Time) resourcepressure.Report {
	evidence := resourcepressure.Evidence{DiskReserveBytes: capture.DefaultReserveBytes}
	if cpu, err := diagnosticCPUStall(); err == nil {
		evidence.CPUKnown = true
		evidence.CPUStallPercent = cpu
	}
	if available, total, err := diagnosticMemory(); err == nil {
		evidence.MemoryKnown = true
		evidence.MemoryAvailableBytes = available
		evidence.MemoryTotalBytes = total
	}
	if disk, err := diagnosticDisk(diskPath); err == nil {
		evidence.DiskKnown = true
		evidence.DiskAvailableBytes = disk.FreeBytes
	}
	return resourcepressure.Evaluate(evidence, now)
}

func diagnosticCPUStall() (float64, error) {
	contents, err := readBoundedDiagnosticFile("/proc/pressure/cpu", 4096)
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(contents), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "some" {
			continue
		}
		for _, field := range fields[1:] {
			if strings.HasPrefix(field, "avg10=") {
				value, parseErr := strconv.ParseFloat(strings.TrimPrefix(field, "avg10="), 64)
				if parseErr != nil || value < 0 || value > 100 {
					return 0, errors.New("CPU pressure value is invalid")
				}
				return value, nil
			}
		}
	}
	return 0, errors.New("CPU pressure average is unavailable")
}

func diagnosticMemory() (uint64, uint64, error) {
	contents, err := readBoundedDiagnosticFile("/proc/meminfo", 64<<10)
	if err != nil {
		return 0, 0, err
	}
	values := map[string]uint64{}
	for _, line := range strings.Split(string(contents), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || (fields[0] != "MemTotal:" && fields[0] != "MemAvailable:") {
			continue
		}
		value, parseErr := strconv.ParseUint(fields[1], 10, 64)
		if parseErr != nil || value > math.MaxUint64/1024 {
			return 0, 0, errors.New("memory pressure value is invalid")
		}
		values[fields[0]] = value * 1024
	}
	if values["MemTotal:"] == 0 || values["MemAvailable:"] > values["MemTotal:"] {
		return 0, 0, errors.New("memory pressure evidence is unavailable")
	}
	return values["MemAvailable:"], values["MemTotal:"], nil
}

func diagnosticDisk(path string) (diagnosticDiskEvidence, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return diagnosticDiskEvidence{}, err
	}
	blockSize := uint64(stat.Bsize)
	if blockSize == 0 || stat.Bavail > math.MaxUint64/blockSize {
		return diagnosticDiskEvidence{}, errors.New("managed filesystem capacity overflowed")
	}
	return diagnosticDiskEvidence{FreeBytes: stat.Bavail * blockSize, FreeInodes: stat.Ffree, TotalInodes: stat.Files}, nil
}

func diagnosticDefaultRoutes() (int, int, error) {
	ipv4, ipv6, err := diagnosticDefaultRouteInterfaces()
	return len(ipv4), len(ipv6), err
}

func diagnosticDefaultRouteInterfaces() (map[string]bool, map[string]bool, error) {
	ipv4, ipv4Err := readBoundedDiagnosticFile("/proc/net/route", 1<<20)
	ipv6, ipv6Err := readBoundedDiagnosticFile("/proc/net/ipv6_route", 1<<20)
	if ipv4Err != nil || ipv6Err != nil {
		return nil, nil, errors.Join(ipv4Err, ipv6Err)
	}
	return parseDefaultRouteInterfaces(string(ipv4), string(ipv6))
}

func parseDefaultRouteInterfaces(ipv4, ipv6 string) (map[string]bool, map[string]bool, error) {
	default4, default6 := map[string]bool{}, map[string]bool{}
	for _, line := range strings.Split(ipv4, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[1] == "00000000" {
			flags, _ := strconv.ParseUint(fields[3], 16, 32)
			if flags&1 != 0 {
				default4[fields[0]] = true
			}
		}
	}
	for _, line := range strings.Split(ipv6, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 10 && fields[0] == strings.Repeat("0", 32) && fields[1] == "00" {
			flags, _ := strconv.ParseUint(fields[8], 16, 32)
			if flags&1 != 0 {
				default6[fields[9]] = true
			}
		}
	}
	return default4, default6, nil
}

func diagnosticNameserverCount() (int, error) {
	contents, err := readBoundedDiagnosticFile("/etc/resolv.conf", 64<<10)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, line := range strings.Split(string(contents), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" {
			count++
		}
	}
	return count, nil
}

func readBoundedDiagnosticFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(contents)) > limit {
		return nil, errors.New("diagnostic file exceeded its read limit")
	}
	return contents, nil
}

func readDiagnosticScalar(path string) string {
	contents, err := readBoundedDiagnosticFile(path, 128)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(contents))
}

func diagnosticServiceActive(ctx context.Context, service string) (bool, bool) {
	allowed := map[string]bool{"docker.service": true, "shakerproxy-dhcp4.service": true, "shakerproxy-hostapd.service": true}
	if !allowed[service] {
		return false, false
	}
	command := exec.CommandContext(ctx, "/usr/bin/systemctl", "is-active", service)
	var output diagnosticCommandOutput
	command.Stdout = &output
	command.Stderr = &output
	err := command.Run()
	state := strings.TrimSpace(string(output.Bytes))
	if output.Truncated {
		return false, false
	}
	if err == nil {
		return state == "active", true
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && (state == "inactive" || state == "failed" || state == "activating" || state == "deactivating") {
		return false, true
	}
	return false, false
}

func diagnosticTimeSynchronized(ctx context.Context) (bool, bool) {
	command := exec.CommandContext(ctx, "/usr/bin/timedatectl", "show", "--property=NTPSynchronized", "--value")
	var output diagnosticCommandOutput
	command.Stdout = &output
	command.Stderr = &output
	err := command.Run()
	if err != nil || output.Truncated || len(output.Bytes) > 128 {
		return false, false
	}
	switch strings.ToLower(strings.TrimSpace(string(output.Bytes))) {
	case "yes":
		return true, true
	case "no":
		return false, true
	default:
		return false, false
	}
}

type diagnosticCommandOutput struct {
	Bytes     []byte
	Truncated bool
}

func (b *diagnosticCommandOutput) Write(value []byte) (int, error) {
	original := len(value)
	remaining := (4 << 10) - len(b.Bytes)
	if remaining <= 0 {
		b.Truncated = true
		return original, nil
	}
	if len(value) > remaining {
		value = value[:remaining]
		b.Truncated = true
	}
	b.Bytes = append(b.Bytes, value...)
	return original, nil
}

// countInterfaces counts non-loopback interfaces that are up or down. Idle
// virtual interfaces ShakerProxy does not manage (Docker bridges without
// containers report no carrier) are counted separately: they carry no lab
// traffic.
func countInterfaces(interfaces []gatewayprotocol.Interface, managed map[string]bool) (up, down, idleVirtual int) {
	for _, iface := range interfaces {
		if containsDiagnosticValue(iface.Flags, "loopback") {
			continue
		}
		switch {
		case containsDiagnosticValue(iface.Flags, "up") && iface.OperState != "down":
			up++
		case strings.Contains(iface.StableID, "path:virtual:") && !managed[iface.Name]:
			idleVirtual++
		default:
			down++
		}
	}
	return up, down, idleVirtual
}

func diagnosticCheck(name string, status gatewayprotocol.DiagnosticStatus, summary string, observations ...string) gatewayprotocol.DiagnosticCheck {
	return gatewayprotocol.DiagnosticCheck{Name: name, Status: status, Summary: summary, Observations: observations}
}

func boundedDiagnosticText(value string, limit int) string {
	value = strings.TrimSpace(strings.ToValidUTF8(value, "?"))
	value = strings.Map(func(char rune) rune {
		if char < 0x20 || char == 0x7f {
			return ' '
		}
		return char
	}, value)
	if len(value) > limit {
		value = value[:limit]
		for !utf8.ValidString(value) {
			value = value[:len(value)-1]
		}
	}
	return strings.TrimSpace(value)
}

func containsDiagnosticValue(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func blockingFirewallIssues(issues []firewall.Issue) int {
	count := 0
	for _, issue := range issues {
		if issue.Blocking {
			count++
		}
	}
	return count
}

func diagnosticValue(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

// dockerEnablesForwarding is replaceable in tests.
var dockerEnablesForwarding = func(ctx context.Context) bool {
	active, known := diagnosticServiceActive(ctx, "docker.service")
	return known && active
}

func enabledDiagnosticValue(value bool) string {
	if value {
		return "available"
	}
	return "unavailable"
}

// keaDirectoryBlocked reports whether this daemon, which runs without
// CAP_DAC_OVERRIDE, is denied access to the managed DHCPv4 file's directory.
func keaDirectoryBlocked() bool {
	_, err := os.Lstat("/etc/kea/kea-dhcp4.conf")
	return errors.Is(err, fs.ErrPermission)
}
