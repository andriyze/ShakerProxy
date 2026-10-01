package daemon

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
	"time"

	"shakerproxy.dev/shakerproxy/internal/networkplan"
)

const networkOwnershipTimeout = 5 * time.Second

// networkManagerEvidence reports whether NetworkManager runs and which
// interfaces systemd-networkd manages; it only asks networkctl when needed.
func networkManagerEvidence(ctx context.Context) networkplan.NetworkManagerEvidence {
	evidence := networkplan.NetworkManagerEvidence{Active: networkManagerActive(ctx)}
	if !evidence.Active {
		return evidence
	}
	commandContext, cancel := context.WithTimeout(ctx, networkOwnershipTimeout)
	defer cancel()
	command := exec.CommandContext(commandContext, "/usr/bin/networkctl", "list", "--no-legend", "--no-pager")
	command.Env = []string{"HOME=/nonexistent", "LANG=C", "LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "SYSTEMD_COLORS=0"}
	var stdout bytes.Buffer
	command.Stdout = &stdout
	if err := command.Run(); err != nil {
		return evidence
	}
	evidence.NetworkdConfigured = parseNetworkctlList(stdout.String())
	return evidence
}

// parseNetworkctlList reads "IDX LINK TYPE OPERATIONAL SETUP" rows.
func parseNetworkctlList(output string) map[string]bool {
	configured := map[string]bool{}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 5 && fields[4] == "configured" {
			configured[fields[1]] = true
		}
	}
	return configured
}
