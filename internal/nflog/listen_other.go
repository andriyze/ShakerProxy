//go:build !linux

package nflog

import (
	"context"
	"errors"
)

// Listen is available on Linux only.
func Listen(context.Context, uint16, uint32, func(Packet)) error {
	return errors.New("NFLOG is available on Linux only")
}
