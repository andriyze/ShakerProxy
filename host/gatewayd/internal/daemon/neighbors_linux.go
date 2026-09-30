//go:build linux

package daemon

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

var neighborDumpSequence atomic.Uint32

// dumpNeighbors reads one family of the kernel neighbor table (NDP or ARP)
// over rtnetlink. It sends one fixed RTM_GETNEIGH dump request; nothing is
// written to the table.
func dumpNeighbors(ctx context.Context, family uint8) ([]rawNeighbor, error) {
	descriptor, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("open neighbor netlink socket: %w", err)
	}
	defer unix.Close(descriptor)
	timeout := unix.NsecToTimeval(int64(2 * time.Second))
	if err := unix.SetsockoptTimeval(descriptor, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout); err != nil {
		return nil, fmt.Errorf("bound neighbor netlink socket: %w", err)
	}
	if err := unix.Bind(descriptor, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, fmt.Errorf("bind neighbor netlink socket: %w", err)
	}
	sequence := neighborDumpSequence.Add(1)
	if err := unix.Sendto(descriptor, neighborDumpRequest(sequence, family), 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, fmt.Errorf("request neighbor table: %w", err)
	}
	buffer := make([]byte, 64<<10)
	var neighbors []rawNeighbor
	total := 0
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		count, from, err := unix.Recvfrom(descriptor, buffer, 0)
		if err != nil {
			return nil, fmt.Errorf("read neighbor table: %w", err)
		}
		if netlink, ok := from.(*unix.SockaddrNetlink); !ok || netlink.Pid != 0 {
			continue
		}
		total += count
		if total > maxNeighborDumpBytes {
			return nil, errors.New("neighbor table exceeds its size limit")
		}
		batch, done, err := parseNeighborMessages(buffer[:count], sequence)
		if err != nil {
			return nil, err
		}
		neighbors = append(neighbors, batch...)
		if done {
			return neighbors, nil
		}
	}
}
