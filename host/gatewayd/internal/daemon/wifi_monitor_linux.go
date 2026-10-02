//go:build linux

package daemon

import (
	"golang.org/x/sys/unix"
)

func linkFlags(name string) (int, *unix.Ifreq, uint16, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return -1, nil, 0, err
	}
	request, err := unix.NewIfreq(name)
	if err != nil {
		unix.Close(fd)
		return -1, nil, 0, err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, request); err != nil {
		unix.Close(fd)
		return -1, nil, 0, err
	}
	return fd, request, request.Uint16(), nil
}

func linkUp(name string) (bool, error) {
	fd, _, flags, err := linkFlags(name)
	if err != nil {
		return false, err
	}
	unix.Close(fd)
	return flags&unix.IFF_UP != 0, nil
}

// setLinkUp sets an interface administratively up or down (needs
// CAP_NET_ADMIN).
func setLinkUp(name string, up bool) error {
	fd, request, flags, err := linkFlags(name)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if up {
		flags |= unix.IFF_UP
	} else {
		flags &^= unix.IFF_UP
	}
	request.SetUint16(flags)
	return unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, request)
}
