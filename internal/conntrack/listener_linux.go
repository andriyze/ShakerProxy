//go:build linux

package conntrack

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

const receiveBufferBytes = 4 << 20

// Listener receives conntrack creation events from the kernel. Joining the
// multicast group needs CAP_NET_ADMIN, which gatewayd holds.
type Listener struct {
	descriptor int
	// Overruns counts times the kernel dropped events because the socket
	// buffer was full (ENOBUFS); the listener keeps reading.
	Overruns atomic.Uint64
}

// Listen subscribes to new-connection events.
func Listen() (*Listener, error) {
	descriptor, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_NETFILTER)
	if err != nil {
		return nil, fmt.Errorf("open conntrack netlink socket: %w", err)
	}
	// Prefer a large buffer so bursts are not lost; the forced variant needs
	// CAP_NET_ADMIN and is allowed to fail.
	if unix.SetsockoptInt(descriptor, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, receiveBufferBytes) != nil {
		_ = unix.SetsockoptInt(descriptor, unix.SOL_SOCKET, unix.SO_RCVBUF, receiveBufferBytes)
	}
	timeout := unix.NsecToTimeval(int64(time.Second))
	if err := unix.SetsockoptTimeval(descriptor, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout); err != nil {
		unix.Close(descriptor)
		return nil, fmt.Errorf("set conntrack socket timeout: %w", err)
	}
	if err := unix.Bind(descriptor, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: 1 << (GroupNew - 1)}); err != nil {
		unix.Close(descriptor)
		return nil, fmt.Errorf("subscribe to conntrack events: %w", err)
	}
	return &Listener{descriptor: descriptor}, nil
}

// Run delivers events to handle until ctx ends, then closes the socket.
func (l *Listener) Run(ctx context.Context, handle func(Event)) error {
	defer unix.Close(l.descriptor)
	buffer := make([]byte, 64<<10)
	for ctx.Err() == nil {
		count, _, err := unix.Recvfrom(l.descriptor, buffer, 0)
		switch {
		case errors.Is(err, unix.EAGAIN), errors.Is(err, unix.EWOULDBLOCK), errors.Is(err, unix.EINTR):
			continue
		case errors.Is(err, unix.ENOBUFS):
			l.Overruns.Add(1)
			continue
		case err != nil:
			return fmt.Errorf("read conntrack events: %w", err)
		}
		events, _ := ParseMessages(buffer[:count])
		for _, event := range events {
			handle(event)
		}
	}
	return nil
}

// Dropped reports and resets the overrun count.
func (l *Listener) Dropped() uint64 { return l.Overruns.Swap(0) }
