//go:build !linux

package conntrack

import (
	"context"
	"errors"
)

// Listener is unavailable off Linux.
type Listener struct{}

// Listen reports that conntrack events need Linux.
func Listen() (*Listener, error) {
	return nil, errors.New("conntrack events need Linux")
}

// Run is unreachable off Linux.
func (l *Listener) Run(context.Context, func(Event)) error {
	return errors.New("conntrack events need Linux")
}

// Dropped is always zero off Linux.
func (l *Listener) Dropped() uint64 { return 0 }
