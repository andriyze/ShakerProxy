//go:build !linux

package daemon

import (
	"context"

	"shakerproxy.dev/shakerproxy/internal/trafficpolicy"
)

func labNeighbors(context.Context, string) ([]trafficpolicy.Neighbor, error) {
	return nil, nil
}
