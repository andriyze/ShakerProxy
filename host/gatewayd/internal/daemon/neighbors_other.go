//go:build !linux

package daemon

import (
	"context"
	"errors"
)

func dumpNeighbors(context.Context, uint8) ([]rawNeighbor, error) {
	return nil, errors.New("neighbor inspection requires Linux")
}
