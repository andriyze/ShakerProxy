package trafficpolicy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
)

// CommandLocalPolicyCleaner removes only the fixed jumps owned by the local
// gateway policy. Fleet policy uses a separate nftables table and never
// accepts caller-provided command text or rule fragments.
type CommandLocalPolicyCleaner struct {
	Binary string
}

func (cleaner CommandLocalPolicyCleaner) Relinquish(ctx context.Context) error {
	binary := cleaner.Binary
	if binary == "" {
		binary = "/usr/sbin/iptables"
	}
	for _, jump := range []struct {
		table  string
		parent string
		child  string
	}{
		{table: "filter", parent: "DOCKER-USER", child: "SHAKERPROXY-SEC-FORWARD"},
		{table: "nat", parent: "PREROUTING", child: "SHAKERPROXY-SEC-PREROUTING"},
	} {
		if err := detachFixedJump(ctx, binary, jump.table, jump.parent, jump.child); err != nil {
			return err
		}
	}
	return nil
}

func detachFixedJump(ctx context.Context, binary, table, parent, child string) error {
	base := []string{"-w", "5"}
	if table != "filter" {
		base = append(base, "-t", table)
	}
	check := append(append([]string{}, base...), "-C", parent, "-j", child)
	remove := append(append([]string{}, base...), "-D", parent, "-j", child)
	for removed := 0; removed < 64; removed++ {
		output, err := runFixedIPTables(ctx, binary, check)
		if err != nil {
			var exitError *exec.ExitError
			if errors.As(err, &exitError) && exitError.ExitCode() == 1 {
				return nil
			}
			return fmt.Errorf("inspect local traffic policy jump: %w: %s", err, boundedOutput(output))
		}
		output, err = runFixedIPTables(ctx, binary, remove)
		if err != nil {
			return fmt.Errorf("remove local traffic policy jump: %w: %s", err, boundedOutput(output))
		}
	}
	return errors.New("local traffic policy contains too many duplicate jumps")
}

func runFixedIPTables(ctx context.Context, binary string, arguments []string) ([]byte, error) {
	if binary != "/usr/sbin/iptables" {
		return nil, errors.New("local traffic policy cleaner executable is not allowlisted")
	}
	command := exec.CommandContext(ctx, binary, arguments...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8"}
	output, err := command.CombinedOutput()
	return bytes.TrimSpace(output), err
}
