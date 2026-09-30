//go:build !linux

package daemon

import (
	"context"

	"shakerproxy.dev/shakerproxy/internal/networkplan"
)

func activeSSHSessions(context.Context, map[string][]string) ([]networkplan.ActiveSSHSession, error) {
	return []networkplan.ActiveSSHSession{}, nil
}
