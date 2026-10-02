//go:build linux

package wireguard

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

var sequence atomic.Uint32

// request sends one netlink request and collects the reply messages of the
// given type until the kernel acknowledges it (or ends the dump).
func request(protocol int, kind, flags uint16, body []byte, replyKind uint16) ([][]byte, error) {
	descriptor, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, protocol)
	if err != nil {
		return nil, fmt.Errorf("open netlink socket: %w", err)
	}
	defer unix.Close(descriptor)
	timeout := unix.NsecToTimeval(int64(5 * time.Second))
	if err := unix.SetsockoptTimeval(descriptor, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout); err != nil {
		return nil, err
	}
	if err := unix.Bind(descriptor, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	number := sequence.Add(1)
	if err := unix.Sendto(descriptor, message(kind, flags|flagRequest, number, body), 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	dump := flags&flagDump == flagDump
	buffer := make([]byte, 1<<16)
	var replies [][]byte
	for {
		count, from, err := unix.Recvfrom(descriptor, buffer, 0)
		if err != nil {
			return nil, err
		}
		if netlink, ok := from.(*unix.SockaddrNetlink); !ok || netlink.Pid != 0 {
			continue
		}
		messages, err := parseMessages(buffer[:count])
		if err != nil {
			return nil, err
		}
		for _, reply := range messages {
			if reply.sequence != number {
				continue
			}
			switch reply.kind {
			case nlmsgDone:
				return replies, nil
			case nlmsgError:
				if len(reply.body) < 4 {
					return nil, errors.New("short netlink error")
				}
				if code := int32(native.Uint32(reply.body[0:4])); code != 0 {
					return nil, syscall.Errno(-code)
				}
				if !dump {
					return replies, nil
				}
			case replyKind:
				replies = append(replies, append([]byte(nil), reply.body...))
				if !dump && flags&flagAck == 0 {
					return replies, nil
				}
			}
		}
	}
}

func familyID() (uint16, error) {
	var attrs attributes
	attrs.addString(ctrlAttrFamilyName, familyName)
	body := append([]byte{ctrlCmdGetFamily, 1, 0, 0}, attrs...)
	replies, err := request(unix.NETLINK_GENERIC, genlIDCtrl, 0, body, genlIDCtrl)
	if errors.Is(err, unix.ENOENT) {
		return 0, ErrUnsupported
	}
	if err != nil {
		return 0, fmt.Errorf("find the WireGuard netlink family: %w", err)
	}
	for _, reply := range replies {
		if len(reply) < genlHeaderLength {
			continue
		}
		parsed, err := parseAttributes(reply[genlHeaderLength:])
		if err != nil {
			return 0, err
		}
		for _, attr := range parsed {
			if attr.kind == ctrlAttrFamilyID && len(attr.value) >= 2 {
				return native.Uint16(attr.value), nil
			}
		}
	}
	return 0, ErrUnsupported
}

// GetDevice reads a WireGuard interface, peers and their statistics
// included.
func GetDevice(name string) (Device, error) {
	family, err := familyID()
	if err != nil {
		return Device{}, err
	}
	var attrs attributes
	attrs.addString(wgDeviceIfname, name)
	replies, err := request(unix.NETLINK_GENERIC, family, flagDump, genlBody(wgCmdGetDevice, attrs), family)
	if errors.Is(err, unix.ENODEV) {
		return Device{}, ErrNotFound
	}
	if err != nil {
		return Device{}, fmt.Errorf("read WireGuard interface %s: %w", name, err)
	}
	device := Device{Name: name}
	for _, reply := range replies {
		if err := parseDeviceMessage(reply, &device); err != nil {
			return Device{}, err
		}
	}
	return device, nil
}

// Configure applies config to a WireGuard interface.
func Configure(name string, config Config) error {
	family, err := familyID()
	if err != nil {
		return err
	}
	for _, body := range setDeviceMessages(name, config) {
		if _, err := request(unix.NETLINK_GENERIC, family, flagAck, body, family); err != nil {
			if errors.Is(err, unix.ENODEV) {
				return ErrNotFound
			}
			return fmt.Errorf("configure WireGuard interface %s: %w", name, err)
		}
	}
	return nil
}

// GetLink reads an interface by name.
func GetLink(name string) (Link, error) {
	var attrs attributes
	attrs.addString(iflaIfname, name)
	replies, err := request(unix.NETLINK_ROUTE, rtmGetLink, flagAck, append(ifinfo(0, 0, 0), attrs...), rtmNewLink)
	if errors.Is(err, unix.ENODEV) {
		return Link{}, ErrNotFound
	}
	if err != nil {
		return Link{}, fmt.Errorf("read interface %s: %w", name, err)
	}
	for _, reply := range replies {
		link, _, err := parseLink(reply)
		if err == nil {
			return link, nil
		}
	}
	return Link{}, ErrNotFound
}

// CreateLink adds a WireGuard interface. The kernel loads the module on
// demand.
func CreateLink(name string, mtu int) error {
	var info attributes
	info.addString(iflaInfoKind, "wireguard")
	var attrs attributes
	attrs.addString(iflaIfname, name)
	if mtu > 0 {
		attrs.addUint32(iflaMTU, uint32(mtu))
	}
	attrs.addNested(iflaLinkInfo, info)
	_, err := request(unix.NETLINK_ROUTE, rtmNewLink, flagAck|flagCreate|flagExclude, append(ifinfo(0, 0, 0), attrs...), rtmNewLink)
	if errors.Is(err, unix.EOPNOTSUPP) {
		return ErrUnsupported
	}
	if err != nil {
		return fmt.Errorf("create WireGuard interface %s: %w", name, err)
	}
	return nil
}

// DeleteLink removes an interface; a missing one is not an error.
func DeleteLink(name string) error {
	link, err := GetLink(name)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err := request(unix.NETLINK_ROUTE, rtmDelLink, flagAck, ifinfo(link.Index, 0, 0), rtmNewLink); err != nil && !errors.Is(err, unix.ENODEV) {
		return fmt.Errorf("delete interface %s: %w", name, err)
	}
	return nil
}

// SetLinkUp brings an interface up.
func SetLinkUp(name string) error {
	link, err := GetLink(name)
	if err != nil {
		return err
	}
	if _, err := request(unix.NETLINK_ROUTE, rtmNewLink, flagAck, ifinfo(link.Index, iffUp, iffUp), rtmNewLink); err != nil {
		return fmt.Errorf("bring interface %s up: %w", name, err)
	}
	return nil
}

// Addresses lists an interface's addresses.
func Addresses(name string) ([]netip.Prefix, error) {
	link, err := GetLink(name)
	if err != nil {
		return nil, err
	}
	replies, err := request(unix.NETLINK_ROUTE, rtmGetAddr, flagDump, make([]byte, 8), rtmNewAddr)
	if err != nil {
		return nil, fmt.Errorf("list addresses of %s: %w", name, err)
	}
	var result []netip.Prefix
	for _, reply := range replies {
		if index, prefix, ok := parseAddress(reply); ok && index == link.Index {
			result = append(result, prefix)
		}
	}
	return result, nil
}

// AddAddress assigns an address (with its prefix length) to an interface.
func AddAddress(name string, prefix netip.Prefix) error {
	link, err := GetLink(name)
	if err != nil {
		return err
	}
	if _, err := request(unix.NETLINK_ROUTE, rtmNewAddr, flagAck|flagCreate|flagReplace, ifaddr(link.Index, prefix), rtmNewAddr); err != nil {
		return fmt.Errorf("add address %s to %s: %w", prefix, name, err)
	}
	return nil
}

// DeleteAddress removes an address from an interface.
func DeleteAddress(name string, prefix netip.Prefix) error {
	link, err := GetLink(name)
	if err != nil {
		return err
	}
	if _, err := request(unix.NETLINK_ROUTE, rtmDelAddr, flagAck, ifaddr(link.Index, prefix), rtmNewAddr); err != nil && !errors.Is(err, unix.EADDRNOTAVAIL) {
		return fmt.Errorf("remove address %s from %s: %w", prefix, name, err)
	}
	return nil
}

// InterfaceExists reports whether any interface has the name.
func InterfaceExists(name string) bool {
	_, err := net.InterfaceByName(name)
	return err == nil
}
