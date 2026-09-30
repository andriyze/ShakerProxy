//go:build linux

package daemon

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"

	"shakerproxy.dev/shakerproxy/internal/networkplan"
)

const (
	maxSSHInspectionBytes = 1 << 20
	maxActiveSSHSessions  = 1024
)

func activeSSHSessions(ctx context.Context, interfaceAddresses map[string][]string) ([]networkplan.ActiveSSHSession, error) {
	ports, err := effectiveSSHPorts(ctx)
	if err != nil || len(ports) == 0 {
		if err != nil {
			return nil, fmt.Errorf("inspect effective OpenSSH configuration: %w", err)
		}
		return nil, nil
	}
	output, err := runSSHInspection(ctx, "/usr/bin/ss", "-Htn", "state", "established")
	if err != nil {
		return nil, fmt.Errorf("inspect established TCP sockets: %w", err)
	}
	return parseSSHSockets(output, interfaceAddresses, ports)
}

func effectiveSSHPorts(ctx context.Context) (map[uint16]bool, error) {
	if info, err := os.Stat("/usr/sbin/sshd"); errors.Is(err, os.ErrNotExist) {
		return map[uint16]bool{}, nil
	} else if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return nil, errors.New("installed OpenSSH server executable is invalid")
	}
	output, err := runSSHInspection(ctx, "/usr/sbin/sshd", "-T")
	if err != nil {
		return nil, err
	}
	ports := make(map[uint16]bool)
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[0] != "port" {
			continue
		}
		port, err := strconv.ParseUint(fields[1], 10, 16)
		if err != nil || port == 0 {
			return nil, errors.New("OpenSSH effective configuration contains an invalid port")
		}
		ports[uint16(port)] = true
	}
	if len(ports) == 0 {
		return nil, errors.New("OpenSSH effective configuration did not report a port")
	}
	return ports, nil
}

func runSSHInspection(ctx context.Context, path string, arguments ...string) (string, error) {
	approved := (path == "/usr/bin/ss" && strings.Join(arguments, "\x00") == "-Htn\x00state\x00established") ||
		(path == "/usr/sbin/sshd" && strings.Join(arguments, "\x00") == "-T")
	if !approved {
		return "", errors.New("active SSH inspection command is not allowlisted")
	}
	command := exec.CommandContext(ctx, path, arguments...)
	command.Env = []string{"HOME=/nonexistent", "LANG=C", "LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	var stdout sshInspectionBuffer
	var stderr sshInspectionBuffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		detail := strings.TrimSpace(stderr.String())
		if len(detail) > 512 {
			detail = detail[:512]
		}
		if detail != "" {
			return "", fmt.Errorf("fixed command failed: %w: %s", err, detail)
		}
		return "", fmt.Errorf("fixed command failed: %w", err)
	}
	if stdout.exceeded || stderr.exceeded {
		return "", errors.New("active SSH socket inspection output exceeded limit")
	}
	return stdout.String(), nil
}

type sshInspectionBuffer struct {
	buffer   bytes.Buffer
	exceeded bool
}

func (b *sshInspectionBuffer) Write(data []byte) (int, error) {
	original := len(data)
	remaining := maxSSHInspectionBytes - b.buffer.Len()
	if remaining <= 0 {
		b.exceeded = true
		return original, nil
	}
	if len(data) > remaining {
		b.exceeded = true
		data = data[:remaining]
	}
	_, _ = b.buffer.Write(data)
	return original, nil
}

func (b *sshInspectionBuffer) String() string { return b.buffer.String() }

func parseSSHSockets(output string, interfaceAddresses map[string][]string, sshPorts map[uint16]bool) ([]networkplan.ActiveSSHSession, error) {
	addressInterfaces := make(map[netip.Addr]string)
	for name, addresses := range interfaceAddresses {
		for _, raw := range addresses {
			prefix, err := netip.ParsePrefix(raw)
			if err == nil {
				addressInterfaces[prefix.Addr().Unmap()] = name
			}
		}
	}
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) > maxActiveSSHSessions*16 {
		return nil, errors.New("established socket count exceeded inspection limit")
	}
	sessions := make([]networkplan.ActiveSSHSession, 0)
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			return nil, errors.New("active SSH socket inspection returned an invalid row")
		}
		local, err := netip.ParseAddrPort(fields[2])
		if err != nil {
			return nil, fmt.Errorf("parse active SSH destination: %w", err)
		}
		remote, err := netip.ParseAddrPort(fields[3])
		if err != nil {
			return nil, fmt.Errorf("parse active SSH source: %w", err)
		}
		if !sshPorts[local.Port()] {
			continue
		}
		destination := local.Addr().Unmap()
		source := remote.Addr().Unmap()
		sessions = append(sessions, networkplan.ActiveSSHSession{
			SourceAddress:        source.String(),
			SourcePort:           int(remote.Port()),
			DestinationAddress:   destination.String(),
			DestinationPort:      int(local.Port()),
			DestinationInterface: addressInterfaces[destination],
		})
		if len(sessions) > maxActiveSSHSessions {
			return nil, errors.New("active SSH session count exceeded limit")
		}
	}
	sort.Slice(sessions, func(i, j int) bool {
		left, right := sessions[i], sessions[j]
		if left.DestinationAddress != right.DestinationAddress {
			return left.DestinationAddress < right.DestinationAddress
		}
		if left.DestinationPort != right.DestinationPort {
			return left.DestinationPort < right.DestinationPort
		}
		if left.SourceAddress != right.SourceAddress {
			return left.SourceAddress < right.SourceAddress
		}
		return left.SourcePort < right.SourcePort
	})
	return sessions, nil
}
