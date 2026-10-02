package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var (
	mcpTokenPattern  = regexp.MustCompile(`^lgt_[A-Za-z0-9_-]{40,124}$`)
	sshTargetPattern = regexp.MustCompile(`^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+$|^[A-Za-z0-9.-]+$`)
)

func writeHelp(output io.Writer) error {
	_, err := fmt.Fprintln(output, `ShakerProxy MCP read-only agent bridge

Usage:
  shakerproxy-mcp                 Start MCP over stdio
  shakerproxy-mcp setup           Securely save a display-once API token
  shakerproxy-mcp doctor          Verify token, TLS, API, and evidence readiness
  shakerproxy-mcp config local    Print local MCP client JSON
  shakerproxy-mcp config ssh TARGET
                              Print MCP client JSON using restricted SSH
  shakerproxy-mcp --version       Print version

Read-only tools: list_devices, find_device, device_report, device_activity,
compare_runs, protocols, search_traffic, traffic_summary, dns_lookups,
tls_issues, http_requests, test_sessions, system_status, dns_visibility,
visibility_coverage, vpn_devices. Devices can be named by friendly name, IP
address, MAC address, or device ID.

Try asking your AI: "What does my TV talk to?", "Is the camera secure?",
"What changed between firmware 1.2 and 1.3?"

The MCP bridge is read-only and metadata-only. It never exposes captured HTTP
bodies, sensitive headers, PCAP bytes, CA private keys, or shell/network tools.`)
	return err
}

func runSetup(input io.Reader, output, diagnostic io.Writer) error {
	path, err := defaultMCPTokenPath()
	if err != nil {
		return err
	}
	if configured := strings.TrimSpace(os.Getenv("SHAKERPROXY_API_TOKEN_FILE")); configured != "" {
		if !filepath.IsAbs(configured) {
			return errors.New("SHAKERPROXY_API_TOKEN_FILE must be absolute")
		}
		path = configured
	}
	if input == os.Stdin {
		_, _ = fmt.Fprintln(diagnostic, "Paste the display-once ShakerProxy API token. Input is hidden when a terminal is available.")
	}
	restoreEcho := disableTerminalEcho(input)
	if restoreEcho != nil {
		defer restoreEcho()
	}
	reader := bufio.NewReader(io.LimitReader(input, 256))
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return errors.New("read MCP API token")
	}
	if restoreEcho != nil {
		_, _ = fmt.Fprintln(diagnostic)
	}
	token := []byte(strings.TrimSpace(line))
	defer wipe(token)
	if !mcpTokenPattern.Match(token) {
		return errors.New("input is not a valid ShakerProxy API token")
	}
	if err := storeMCPToken(path, token); err != nil {
		return err
	}
	verified, err := loadMCPToken(path)
	if err != nil {
		return errors.New("saved MCP token did not pass private-file validation")
	}
	wipe(verified)
	_, err = fmt.Fprintf(output, "Saved private MCP token: %s\nNext: shakerproxy-mcp doctor\n", path)
	return err
}

func disableTerminalEcho(input io.Reader) func() {
	file, ok := input.(*os.File)
	if !ok {
		return nil
	}
	info, err := file.Stat()
	if err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return nil
	}
	command := exec.Command("stty", "-echo")
	command.Stdin = file
	if command.Run() != nil {
		return nil
	}
	return func() {
		command := exec.Command("stty", "echo")
		command.Stdin = file
		_ = command.Run()
	}
}

func storeMCPToken(path string, token []byte) error {
	if !filepath.IsAbs(path) || !mcpTokenPattern.Match(token) {
		return errors.New("MCP token destination or value is invalid")
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return errors.New("create MCP configuration directory")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("MCP configuration directory is unsafe")
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return errors.New("secure MCP configuration directory")
	}
	info, err = os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("MCP configuration directory permissions are unsafe")
	}
	temporary, err := os.CreateTemp(directory, ".mcp-token-*")
	if err != nil {
		return errors.New("create temporary MCP token file")
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return errors.New("secure temporary MCP token file")
	}
	value := append(append([]byte(nil), token...), '\n')
	defer wipe(value)
	if _, err := temporary.Write(value); err != nil {
		return errors.New("write MCP token file")
	}
	if err := temporary.Sync(); err != nil {
		return errors.New("sync MCP token file")
	}
	if err := temporary.Close(); err != nil {
		return errors.New("close MCP token file")
	}
	if existing, err := os.Lstat(path); err == nil && existing.Mode()&os.ModeSymlink != 0 {
		return errors.New("refusing to replace symlink MCP token path")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("inspect existing MCP token path")
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return errors.New("install MCP token file")
	}
	committed = true
	if directoryHandle, err := os.Open(directory); err == nil {
		_ = directoryHandle.Sync()
		_ = directoryHandle.Close()
	}
	return nil
}

func runDoctor(ctx context.Context, output io.Writer) error {
	backend, token, err := agentBackendFromEnvironment()
	if err != nil {
		return fmt.Errorf("connection setup: %w", err)
	}
	defer wipe(token)
	probeContext, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	overview, err := backend.SystemOverview(probeContext)
	if err != nil {
		return fmt.Errorf("ShakerProxy API authentication/evidence probe failed: %w", err)
	}
	status := "CONNECTED"
	if !overview.EvidenceReady {
		status = "CONNECTED · EVIDENCE DEGRADED"
	}
	if _, err := fmt.Fprintf(output, "ShakerProxy MCP: %s\nAPI: authenticated over %s\nGateway: %s\nEvidence: %s\nTools: 13 read-only tools (list_devices, find_device, device_report, compare_runs, visibility_coverage, …)\n", status, envOr("SHAKERPROXY_API_URL", "https://127.0.0.1:8443"), overview.Gateway.OperatingMode, overview.Overall); err != nil {
		return err
	}
	for _, limitation := range overview.Limitations {
		if _, err := fmt.Fprintf(output, "Limitation: %s\n", limitation); err != nil {
			return err
		}
	}
	return nil
}

type mcpClientConfig struct {
	MCPServers map[string]mcpServerConfig `json:"mcpServers"`
}

type mcpServerConfig struct {
	Command string            `json:"command"`
	Args    []string          `json:"args,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
}

func runConfig(args []string, output io.Writer) error {
	if len(args) < 1 || len(args) > 2 {
		return errors.New("usage: shakerproxy-mcp config local | shakerproxy-mcp config ssh TARGET")
	}
	var server mcpServerConfig
	switch args[0] {
	case "local":
		if len(args) != 1 {
			return errors.New("usage: shakerproxy-mcp config local")
		}
		path, err := defaultMCPTokenPath()
		if err != nil {
			return err
		}
		server = mcpServerConfig{Command: "/usr/bin/shakerproxy-mcp", Env: map[string]string{"SHAKERPROXY_API_TOKEN_FILE": path}}
	case "ssh":
		if len(args) != 2 || !sshTargetPattern.MatchString(args[1]) || strings.Contains(args[1], "..") {
			return errors.New("usage: shakerproxy-mcp config ssh USER@HOST")
		}
		server = mcpServerConfig{Command: "ssh", Args: []string{"-T", "-o", "BatchMode=yes", args[1], "/usr/bin/shakerproxy-mcp"}}
	default:
		return errors.New("config mode must be local or ssh")
	}
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	return encoder.Encode(mcpClientConfig{MCPServers: map[string]mcpServerConfig{"shakerproxy": server}})
}
