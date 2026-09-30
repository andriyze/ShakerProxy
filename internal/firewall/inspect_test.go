package firewall

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

type fakeRunner struct {
	outputs map[string]string
	errors  map[string]error
}

func commandKey(path string, args ...string) string { return path + " " + strings.Join(args, " ") }
func (f fakeRunner) Run(_ context.Context, path string, args ...string) (string, error) {
	key := commandKey(path, args...)
	if err := f.errors[key]; err != nil {
		return f.outputs[key], err
	}
	value, ok := f.outputs[key]
	if !ok {
		return "", errors.New("not found")
	}
	return value, nil
}

func inspectorFor(config string, ufw string, runner fakeRunner) Inspector {
	return Inspector{
		ReadFile: func(path string) ([]byte, error) {
			switch path {
			case "/etc/docker/daemon.json":
				if config == "" {
					return nil, os.ErrNotExist
				}
				return []byte(config), nil
			case "/etc/ufw/ufw.conf":
				if ufw == "" {
					return nil, os.ErrNotExist
				}
				return []byte(ufw), nil
			default:
				return nil, os.ErrNotExist
			}
		},
		EvalSymlinks: func(string) (string, error) { return "/usr/sbin/xtables-nft-multi", nil },
		Runner:       runner,
	}
}

func readyRunner() fakeRunner {
	return fakeRunner{outputs: map[string]string{
		commandKey("/usr/sbin/iptables", "--version"):                               "iptables v1.8.11 (nf_tables)\n",
		commandKey("/usr/sbin/iptables", "-w", "2", "-S"):                           "-P FORWARD ACCEPT\n-N DOCKER-USER\n",
		commandKey("/usr/sbin/iptables", "-w", "2", "-t", "nat", "-S"):              "-P POSTROUTING ACCEPT\n",
		commandKey("/usr/bin/docker", "version", "--format", "{{.Server.Version}}"): "29.0.0\n",
		commandKey("/usr/bin/systemctl", "is-active", "firewalld"):                  "inactive\n",
	}, errors: map[string]error{commandKey("/usr/bin/systemctl", "is-active", "firewalld"): errors.New("inactive")}}
}

func TestInspectAcceptsSupportedDockerIptablesNFTCoexistence(t *testing.T) {
	inspection := inspectorFor(`{"firewall-backend":"iptables"}`, "ENABLED=yes\n", readyRunner()).Inspect(context.Background())
	if !inspection.ApplyReady || !inspection.PreviewSupported || inspection.SelectedBackend != "iptables-nft" || !inspection.DockerUserChain {
		t.Fatalf("unexpected inspection: %+v", inspection)
	}
	if !inspection.UFWActive || !hasFirewallIssue(inspection, "UFW_ACTIVE", false) {
		t.Fatalf("UFW evidence missing: %+v", inspection)
	}
}

func TestInspectBlocksDockerNativeNFTables(t *testing.T) {
	inspection := inspectorFor(`{"firewall-backend":"nftables"}`, "", readyRunner()).Inspect(context.Background())
	if inspection.ApplyReady || !hasFirewallIssue(inspection, "DOCKER_NFTABLES_UNSUPPORTED", true) {
		t.Fatalf("native nftables backend was not blocked: %+v", inspection)
	}
}

func TestInspectBlocksMissingDockerUserChain(t *testing.T) {
	runner := readyRunner()
	runner.outputs[commandKey("/usr/sbin/iptables", "-w", "2", "-S")] = "-P FORWARD ACCEPT\n"
	inspection := inspectorFor("", "", runner).Inspect(context.Background())
	if inspection.ApplyReady || !hasFirewallIssue(inspection, "DOCKER_USER_CHAIN_MISSING", true) {
		t.Fatalf("missing Docker chain was not blocked: %+v", inspection)
	}
}

func TestInspectBlocksReservedShakerProxyChains(t *testing.T) {
	runner := readyRunner()
	runner.outputs[commandKey("/usr/sbin/iptables", "-w", "2", "-S")] += "-N SHAKERPROXY-FORWARD\n"
	runner.outputs[commandKey("/usr/sbin/iptables", "-w", "2", "-t", "nat", "-S")] += "-N SHAKERPROXY-POSTROUTING\n"
	inspection := inspectorFor("", "", runner).Inspect(context.Background())
	if inspection.ApplyReady || !inspection.ShakerProxyFilterChain || !inspection.ShakerProxyNATChain || !hasFirewallIssue(inspection, "SHAKERPROXY_CHAIN_CONFLICT", true) {
		t.Fatalf("reserved chains were not blocked: %+v", inspection)
	}
}

func TestInspectBlocksUnreadableRuleset(t *testing.T) {
	runner := readyRunner()
	runner.errors[commandKey("/usr/sbin/iptables", "-w", "2", "-S")] = errors.New("permission denied")
	inspection := inspectorFor("", "", runner).Inspect(context.Background())
	if inspection.ApplyReady || !hasFirewallIssue(inspection, "IPTABLES_RULESET_UNREADABLE", true) {
		t.Fatalf("unreadable ruleset was not blocked: %+v", inspection)
	}
}

func TestInvalidDockerConfigurationIsBlocking(t *testing.T) {
	inspection := inspectorFor(`{`, "", readyRunner()).Inspect(context.Background())
	if inspection.ApplyReady || !hasFirewallIssue(inspection, "DOCKER_CONFIG_INVALID", true) {
		t.Fatalf("invalid config was not blocked: %+v", inspection)
	}
}

func TestIndeterminateFirewalldStateIsBlocking(t *testing.T) {
	runner := readyRunner()
	delete(runner.outputs, commandKey("/usr/bin/systemctl", "is-active", "firewalld"))
	inspection := inspectorFor("", "", runner).Inspect(context.Background())
	if inspection.ApplyReady || !hasFirewallIssue(inspection, "FIREWALLD_STATE_UNKNOWN", true) {
		t.Fatalf("unknown firewalld state was not blocked: %+v", inspection)
	}
}

func TestUnreadableUFWConfigurationIsBlocking(t *testing.T) {
	inspector := inspectorFor("", "", readyRunner())
	inspector.ReadFile = func(path string) ([]byte, error) {
		if path == "/etc/ufw/ufw.conf" {
			return nil, os.ErrPermission
		}
		return nil, os.ErrNotExist
	}
	inspection := inspector.Inspect(context.Background())
	if inspection.ApplyReady || !hasFirewallIssue(inspection, "UFW_CONFIG_UNREADABLE", true) {
		t.Fatalf("unreadable UFW config was not blocked: %+v", inspection)
	}
}

func TestCappedBufferSignalsTruncation(t *testing.T) {
	var buffer cappedBuffer
	payload := make([]byte, maxCommandOutput+1)
	if written, err := buffer.Write(payload); err != nil || written != len(payload) {
		t.Fatalf("unexpected write result: written=%d err=%v", written, err)
	}
	if !buffer.exceeded || buffer.Len() != maxCommandOutput {
		t.Fatalf("output cap was not enforced: exceeded=%v length=%d", buffer.exceeded, buffer.Len())
	}
}

func TestOSRunnerCommandAllowlistRejectsUserControlledArguments(t *testing.T) {
	if allowedCommand("/usr/sbin/iptables", []string{"-F"}) {
		t.Fatal("flush command was allowlisted")
	}
	if allowedCommand("/bin/sh", []string{"-c", "iptables -F"}) {
		t.Fatal("shell command was allowlisted")
	}
	if !allowedCommand("/usr/sbin/iptables", []string{"--version"}) {
		t.Fatal("fixed version probe was rejected")
	}
	if allowedCommand("/usr/sbin/iptables", []string{"-S", "USER-CONTROLLED"}) {
		t.Fatal("user-controlled chain query was allowlisted")
	}
}

func hasFirewallIssue(inspection Inspection, code string, blocking bool) bool {
	for _, issue := range inspection.Issues {
		if issue.Code == code && issue.Blocking == blocking {
			return true
		}
	}
	return false
}
