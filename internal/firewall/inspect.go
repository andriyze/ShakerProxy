package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const maxCommandOutput = 64 << 10

type Issue struct {
	Code     string `json:"code"`
	Message  string `json:"message"`
	Blocking bool   `json:"blocking"`
}

type Inspection struct {
	SelectedBackend        string  `json:"selected_backend"`
	DockerFirewallBackend  string  `json:"docker_firewall_backend"`
	DockerVersion          string  `json:"docker_version,omitempty"`
	IptablesVersion        string  `json:"iptables_version,omitempty"`
	IptablesPath           string  `json:"iptables_path,omitempty"`
	IptablesAlternative    string  `json:"iptables_alternative,omitempty"`
	DockerUserChain        bool    `json:"docker_user_chain"`
	ShakerProxyFilterChain bool    `json:"shakerproxy_filter_chain"`
	ShakerProxyNATChain    bool    `json:"shakerproxy_nat_chain"`
	IPv6Available          bool    `json:"ipv6_available"`
	Ip6tablesPath          string  `json:"ip6tables_path,omitempty"`
	IPv6DockerUserChain    bool    `json:"ipv6_docker_user_chain"`
	ShakerProxyIPv6Chains  bool    `json:"shakerproxy_ipv6_chains"`
	IPv6FirewallReady      bool    `json:"ipv6_firewall_ready"`
	UFWActive              bool    `json:"ufw_active"`
	FirewalldActive        bool    `json:"firewalld_active"`
	PreviewSupported       bool    `json:"preview_supported"`
	ApplyReady             bool    `json:"apply_ready"`
	Issues                 []Issue `json:"issues"`
}

type Runner interface {
	Run(context.Context, string, ...string) (string, error)
}

type Inspector struct {
	ReadFile     func(string) ([]byte, error)
	EvalSymlinks func(string) (string, error)
	Runner       Runner
}

func DefaultInspector() Inspector {
	return Inspector{ReadFile: os.ReadFile, EvalSymlinks: filepath.EvalSymlinks, Runner: OSRunner{}}
}

func (i Inspector) Inspect(ctx context.Context) Inspection {
	result := Inspection{DockerFirewallBackend: "iptables", Issues: []Issue{}}
	add := func(code, message string, blocking bool) {
		result.Issues = append(result.Issues, Issue{Code: code, Message: message, Blocking: blocking})
	}

	if raw, err := i.ReadFile("/etc/docker/daemon.json"); err == nil {
		if len(raw) > 1<<20 {
			add("DOCKER_CONFIG_TOO_LARGE", "Docker daemon configuration exceeds the inspection limit", true)
		} else {
			var config struct {
				FirewallBackend string `json:"firewall-backend"`
			}
			if err := json.Unmarshal(raw, &config); err != nil {
				add("DOCKER_CONFIG_INVALID", "Docker daemon configuration is not valid JSON", true)
			} else if config.FirewallBackend != "" {
				result.DockerFirewallBackend = config.FirewallBackend
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		add("DOCKER_CONFIG_UNREADABLE", "Docker daemon configuration could not be read", true)
	}

	result.IptablesAlternative, _ = i.EvalSymlinks("/etc/alternatives/iptables")
	commandCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	iptablesPath := "/usr/sbin/iptables"
	version, versionErr := i.Runner.Run(commandCtx, iptablesPath, "--version")
	if versionErr != nil {
		iptablesPath = "/usr/bin/iptables"
		version, versionErr = i.Runner.Run(commandCtx, iptablesPath, "--version")
	}
	if versionErr != nil {
		add("IPTABLES_UNAVAILABLE", "iptables could not be executed at an approved system path", true)
	} else {
		result.IptablesPath = iptablesPath
		result.IptablesVersion = strings.TrimSpace(version)
		switch {
		case strings.Contains(version, "nf_tables") || strings.Contains(result.IptablesAlternative, "xtables-nft"):
			result.SelectedBackend = "iptables-nft"
		case strings.Contains(strings.ToLower(version), "legacy") || strings.Contains(result.IptablesAlternative, "xtables-legacy"):
			result.SelectedBackend = "iptables-legacy"
		default:
			add("IPTABLES_MODE_UNKNOWN", "iptables is present but its nft/legacy mode could not be identified", true)
		}
	}

	dockerVersion, dockerErr := i.Runner.Run(commandCtx, "/usr/bin/docker", "version", "--format", "{{.Server.Version}}")
	if dockerErr == nil {
		result.DockerVersion = strings.TrimSpace(dockerVersion)
	} else {
		add("DOCKER_UNAVAILABLE", "Docker Engine is unavailable or its daemon is not running", true)
	}
	if result.DockerFirewallBackend != "iptables" {
		if result.DockerFirewallBackend == "nftables" {
			add("DOCKER_NFTABLES_UNSUPPORTED", "Docker native nftables backend is not accepted by the v1 coexistence suite", true)
		} else {
			add("DOCKER_FIREWALL_BACKEND_UNKNOWN", fmt.Sprintf("Docker firewall backend %q is unknown", result.DockerFirewallBackend), true)
		}
	}
	if versionErr == nil {
		filterRules, filterErr := i.Runner.Run(commandCtx, iptablesPath, "-w", "2", "-S")
		natRules, natErr := i.Runner.Run(commandCtx, iptablesPath, "-w", "2", "-t", "nat", "-S")
		if filterErr != nil || natErr != nil {
			add("IPTABLES_RULESET_UNREADABLE", "the complete filter and NAT rulesets could not be inspected", true)
		} else {
			result.DockerUserChain = ruleDeclaresChain(filterRules, "DOCKER-USER")
			result.ShakerProxyFilterChain = ruleDeclaresChain(filterRules, "SHAKERPROXY-FORWARD")
			result.ShakerProxyNATChain = ruleDeclaresChain(natRules, "SHAKERPROXY-POSTROUTING")
			if result.ShakerProxyFilterChain || result.ShakerProxyNATChain {
				add("SHAKERPROXY_CHAIN_CONFLICT", "reserved ShakerProxy firewall chains already exist", true)
			}
		}
		if !result.DockerUserChain && result.DockerVersion != "" {
			add("DOCKER_USER_CHAIN_MISSING", "Docker is running but the DOCKER-USER chain is unavailable", true)
		}
		i.inspectIPv6(commandCtx, iptablesPath, &result, add)
	}

	if raw, err := i.ReadFile("/etc/ufw/ufw.conf"); err == nil {
		result.UFWActive = configEnabled(raw)
		if result.UFWActive {
			add("UFW_ACTIVE", "UFW is active; its rules must be preserved and tested during apply", false)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		add("UFW_CONFIG_UNREADABLE", "UFW configuration could not be read", true)
	}
	state, firewalldErr := i.Runner.Run(commandCtx, "/usr/bin/systemctl", "is-active", "firewalld")
	switch strings.TrimSpace(state) {
	case "active", "activating", "reloading":
		result.FirewalldActive = true
		add("FIREWALLD_ACTIVE", "firewalld is active; apply is blocked until coexistence is tested", true)
	case "inactive", "failed", "deactivating":
		// systemctl normally exits non-zero for an inactive unit; the state text is authoritative.
	default:
		if firewalldErr != nil {
			add("FIREWALLD_STATE_UNKNOWN", "firewalld state could not be determined", true)
		}
	}

	result.PreviewSupported = result.SelectedBackend == "iptables-nft" || result.SelectedBackend == "iptables-legacy"
	result.ApplyReady = result.PreviewSupported && result.DockerFirewallBackend == "iptables" && result.DockerVersion != "" && result.DockerUserChain && !result.FirewalldActive
	for _, issue := range result.Issues {
		if issue.Blocking {
			result.ApplyReady = false
			break
		}
	}
	return result
}

func ruleDeclaresChain(rules, chain string) bool {
	declaration := "-N " + chain
	for _, line := range strings.Split(rules, "\n") {
		if strings.TrimSpace(line) == declaration {
			return true
		}
	}
	return false
}

func configEnabled(raw []byte) bool {
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.SplitN(strings.TrimSpace(line), "=", 2)
		if len(fields) == 2 && strings.EqualFold(strings.TrimSpace(fields[0]), "ENABLED") && strings.EqualFold(strings.Trim(strings.TrimSpace(fields[1]), "\"'"), "yes") {
			return true
		}
	}
	return false
}

type OSRunner struct{}

func (OSRunner) Run(ctx context.Context, path string, args ...string) (string, error) {
	if !allowedCommand(path, args) {
		return "", errors.New("command is not allowlisted")
	}
	command := exec.CommandContext(ctx, path, args...)
	var stdout cappedBuffer
	var stderr cappedBuffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	if stdout.exceeded || stderr.exceeded {
		return "", errors.New("command output exceeded limit")
	}
	if err != nil {
		return stdout.String(), fmt.Errorf("fixed command failed: %w", err)
	}
	return stdout.String(), nil
}

func allowedCommand(path string, args []string) bool {
	joined := strings.Join(args, "\x00")
	switch path {
	case "/usr/sbin/iptables", "/usr/bin/iptables":
		return joined == "--version" || joined == "-w\x002\x00-S" || joined == "-w\x002\x00-t\x00nat\x00-S"
	case "/usr/sbin/ip6tables", "/usr/bin/ip6tables":
		return allowedIPv6InspectionCommand(args)
	case "/usr/bin/docker":
		return joined == "version\x00--format\x00{{.Server.Version}}"
	case "/usr/bin/systemctl":
		return joined == "is-active\x00firewalld"
	default:
		return false
	}
}

type cappedBuffer struct {
	bytes.Buffer
	exceeded bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	original := len(p)
	remaining := maxCommandOutput - b.Len()
	if remaining <= 0 {
		b.exceeded = true
		return original, nil
	}
	if len(p) > remaining {
		p = p[:remaining]
		b.exceeded = true
	}
	_, _ = b.Buffer.Write(p)
	return original, nil
}
