//go:build linux

package nflog

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

// Config commands and copy mode (linux/netfilter/nfnetlink_log.h).
const (
	attrConfigCmd  = 1
	attrConfigMode = 2
	cmdBind        = 1
	cmdPFBind      = 3
	cmdPFUnbind    = 4
	copyPacket     = 2
)

// Listen binds NFLOG group and calls handle for every logged packet until
// ctx ends. It needs CAP_NET_ADMIN. copyBytes bounds how much of each packet
// the kernel copies (the rule's --nflog-size also bounds it).
func Listen(ctx context.Context, group uint16, copyBytes uint32, handle func(Packet)) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_NETFILTER)
	if err != nil {
		return fmt.Errorf("open netfilter netlink socket: %w", err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("bind netfilter netlink socket: %w", err)
	}
	timeout := unix.Timeval{Sec: 1}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout); err != nil {
		return err
	}
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 1<<20)
	sequence := uint32(time.Now().Unix())
	request := func(family uint8, resource uint16, attributeType uint16, value []byte) error {
		sequence++
		message := configMessage(sequence, family, resource, attributeType, value)
		if err := unix.Sendto(fd, message, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
			return err
		}
		return readAck(fd, sequence)
	}
	// Kernels before 3.17 need the per-family handler bound; newer ones
	// ignore these two commands.
	for _, family := range []uint8{unix.AF_INET, unix.AF_INET6} {
		_ = request(family, 0, attrConfigCmd, []byte{cmdPFUnbind})
		_ = request(family, 0, attrConfigCmd, []byte{cmdPFBind})
	}
	if err := request(unix.AF_UNSPEC, group, attrConfigCmd, []byte{cmdBind}); err != nil {
		return fmt.Errorf("bind NFLOG group %d: %w", group, err)
	}
	mode := make([]byte, 6)
	binary.BigEndian.PutUint32(mode[0:4], copyBytes)
	mode[4] = copyPacket
	if err := request(unix.AF_UNSPEC, group, attrConfigMode, mode); err != nil {
		return fmt.Errorf("set NFLOG copy mode: %w", err)
	}
	buffer := make([]byte, maxMessageBytes)
	for ctx.Err() == nil {
		n, _, err := unix.Recvfrom(fd, buffer, 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				continue
			}
			// ENOBUFS: the kernel dropped log messages; keep reading.
			if errors.Is(err, unix.ENOBUFS) {
				continue
			}
			return fmt.Errorf("read NFLOG: %w", err)
		}
		packets, _ := ParseMessages(buffer[:n], time.Now())
		for _, packet := range packets {
			handle(packet)
		}
	}
	return nil
}

func configMessage(sequence uint32, family uint8, resource uint16, attributeType uint16, value []byte) []byte {
	attributeLength := 4 + len(value)
	length := nlmsgHeaderLen + nfgenHeaderLen + align(attributeLength)
	message := make([]byte, length)
	binary.LittleEndian.PutUint32(message[0:4], uint32(length))
	binary.LittleEndian.PutUint16(message[4:6], subsysULOG<<8|msgConfig)
	binary.LittleEndian.PutUint16(message[6:8], unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	binary.LittleEndian.PutUint32(message[8:12], sequence)
	message[16] = family
	binary.BigEndian.PutUint16(message[18:20], resource)
	binary.LittleEndian.PutUint16(message[20:22], uint16(attributeLength))
	binary.LittleEndian.PutUint16(message[22:24], attributeType)
	copy(message[24:], value)
	return message
}

func readAck(fd int, sequence uint32) error {
	buffer := make([]byte, 4096)
	for attempt := 0; attempt < 8; attempt++ {
		n, _, err := unix.Recvfrom(fd, buffer, 0)
		if err != nil {
			return err
		}
		data := buffer[:n]
		for len(data) >= nlmsgHeaderLen {
			length := int(binary.LittleEndian.Uint32(data[0:4]))
			if length < nlmsgHeaderLen || length > len(data) {
				return errors.New("netlink acknowledgement is malformed")
			}
			kind := binary.LittleEndian.Uint16(data[4:6])
			seq := binary.LittleEndian.Uint32(data[8:12])
			if kind == nlmsgError && seq == sequence && length >= nlmsgHeaderLen+4 {
				code := int32(binary.LittleEndian.Uint32(data[16:20]))
				if code == 0 {
					return nil
				}
				return unix.Errno(-code)
			}
			next := align(length)
			if next >= len(data) {
				break
			}
			data = data[next:]
		}
	}
	return errors.New("no netlink acknowledgement")
}
