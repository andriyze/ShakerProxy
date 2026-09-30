//go:build linux

package daemon

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"syscall"

	"shakerproxy.dev/shakerproxy/internal/trafficpolicy"
)

const (
	trafficNDADestination = 1
	trafficNDALinkAddress = 2
	nudIncomplete         = 0x01
	nudFailed             = 0x20
	nudNoARP              = 0x40
	maxNeighborEntries    = 16384
)

// labNeighbors dumps the kernel ARP and NDP tables for one interface over
// netlink. It is read-only and needs no capability beyond AF_NETLINK.
func labNeighbors(_ context.Context, interfaceName string) ([]trafficpolicy.Neighbor, error) {
	link, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, err
	}
	result := []trafficpolicy.Neighbor{}
	for _, family := range []int{syscall.AF_INET, syscall.AF_INET6} {
		data, err := syscall.NetlinkRIB(syscall.RTM_GETNEIGH, family)
		if err != nil {
			if family == syscall.AF_INET6 && errors.Is(err, syscall.EAFNOSUPPORT) {
				continue
			}
			return nil, err
		}
		messages, err := syscall.ParseNetlinkMessage(data)
		if err != nil {
			return nil, err
		}
		for _, message := range messages {
			if message.Header.Type != syscall.RTM_NEWNEIGH || len(message.Data) < 12 {
				continue
			}
			if int(int32(binary.NativeEndian.Uint32(message.Data[4:8]))) != link.Index {
				continue
			}
			state := binary.NativeEndian.Uint16(message.Data[8:10])
			if state&(nudIncomplete|nudFailed|nudNoARP) != 0 {
				continue
			}
			neighbor, ok := parseNeighborAttributes(message.Data[12:])
			if !ok {
				continue
			}
			result = append(result, neighbor)
			if len(result) >= maxNeighborEntries {
				return result, nil
			}
		}
	}
	return result, nil
}

func parseNeighborAttributes(data []byte) (trafficpolicy.Neighbor, bool) {
	var address netip.Addr
	var hardware net.HardwareAddr
	for len(data) >= 4 {
		length := int(binary.NativeEndian.Uint16(data[0:2]))
		kind := binary.NativeEndian.Uint16(data[2:4])
		if length < 4 || length > len(data) {
			break
		}
		value := data[4:length]
		switch kind {
		case trafficNDADestination:
			if parsed, ok := netip.AddrFromSlice(value); ok {
				address = parsed.Unmap()
			}
		case trafficNDALinkAddress:
			if len(value) == 6 {
				hardware = net.HardwareAddr(append([]byte(nil), value...))
			}
		}
		aligned := (length + 3) &^ 3
		if aligned > len(data) {
			break
		}
		data = data[aligned:]
	}
	if !address.IsValid() || hardware == nil {
		return trafficpolicy.Neighbor{}, false
	}
	return trafficpolicy.Neighbor{Address: address.String(), HardwareAddress: hardware.String()}, true
}
