// Package conntrack reads the kernel's netfilter connection-tracking events:
// every connection a lab device opens through the gateway, the moment it
// opens, long before a packet capture of it has been analyzed.
package conntrack

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

// Event is one new tracked connection, in its original direction.
type Event struct {
	Protocol    string // "tcp", "udp", "icmp" or "sctp"
	Source      netip.AddrPort
	Destination netip.AddrPort
}

// Netlink and ctnetlink constants (linux/netlink.h, linux/netfilter/
// nfnetlink.h, linux/netfilter/nfnetlink_conntrack.h).
const (
	netlinkHeaderLength = 16
	nfgenmsgLength      = 4

	netlinkMessageNoop  = 1
	netlinkMessageError = 2
	netlinkMessageDone  = 3
	netlinkFlagCreate   = 0x400

	subsystemCTNetlink = 1
	messageCTNew       = 0
	// GroupNew is the multicast group of conntrack creations
	// (NFNLGRP_CONNTRACK_NEW).
	GroupNew = 1

	attributeTypeMask = 0x3fff

	ctaTupleOrig    = 1
	ctaTupleIP      = 1
	ctaTupleProto   = 2
	ctaIPv4Source   = 1
	ctaIPv4Dest     = 2
	ctaIPv6Source   = 3
	ctaIPv6Dest     = 4
	ctaProtoNumber  = 1
	ctaProtoSrcPort = 2
	ctaProtoDstPort = 3
)

var errTruncated = errors.New("conntrack netlink message is truncated")

// ParseMessages decodes the connection-creation events in one netlink
// datagram. Messages of other types (updates, errors, done) are skipped.
func ParseMessages(datagram []byte) ([]Event, error) {
	var events []Event
	for len(datagram) >= netlinkHeaderLength {
		length := int(binary.NativeEndian.Uint32(datagram[0:4]))
		if length < netlinkHeaderLength || length > len(datagram) {
			return events, errTruncated
		}
		messageType := binary.NativeEndian.Uint16(datagram[4:6])
		flags := binary.NativeEndian.Uint16(datagram[6:8])
		message := datagram[netlinkHeaderLength:length]
		datagram = datagram[min(align(length), len(datagram)):]
		switch messageType {
		case netlinkMessageNoop, netlinkMessageDone:
			continue
		case netlinkMessageError:
			continue
		}
		if messageType != subsystemCTNetlink<<8|messageCTNew || flags&netlinkFlagCreate == 0 {
			continue
		}
		if len(message) < nfgenmsgLength {
			return events, errTruncated
		}
		event, ok, err := parseConnection(message[nfgenmsgLength:])
		if err != nil {
			return events, err
		}
		if ok {
			events = append(events, event)
		}
	}
	return events, nil
}

func parseConnection(attributes []byte) (Event, bool, error) {
	var event Event
	found := false
	err := walk(attributes, func(kind uint16, value []byte) error {
		if kind != ctaTupleOrig {
			return nil
		}
		found = true
		return walk(value, func(kind uint16, value []byte) error {
			switch kind {
			case ctaTupleIP:
				return walk(value, func(kind uint16, value []byte) error {
					switch kind {
					case ctaIPv4Source, ctaIPv6Source:
						if address, ok := netip.AddrFromSlice(value); ok && (len(value) == 4 || len(value) == 16) {
							event.Source = netip.AddrPortFrom(address.Unmap(), event.Source.Port())
						}
					case ctaIPv4Dest, ctaIPv6Dest:
						if address, ok := netip.AddrFromSlice(value); ok && (len(value) == 4 || len(value) == 16) {
							event.Destination = netip.AddrPortFrom(address.Unmap(), event.Destination.Port())
						}
					}
					return nil
				})
			case ctaTupleProto:
				return walk(value, func(kind uint16, value []byte) error {
					switch kind {
					case ctaProtoNumber:
						if len(value) >= 1 {
							event.Protocol = protocolName(value[0])
						}
					case ctaProtoSrcPort:
						if len(value) >= 2 {
							event.Source = netip.AddrPortFrom(event.Source.Addr(), binary.BigEndian.Uint16(value))
						}
					case ctaProtoDstPort:
						if len(value) >= 2 {
							event.Destination = netip.AddrPortFrom(event.Destination.Addr(), binary.BigEndian.Uint16(value))
						}
					}
					return nil
				})
			}
			return nil
		})
	})
	if err != nil {
		return Event{}, false, err
	}
	if !found || event.Protocol == "" || !event.Source.Addr().IsValid() || !event.Destination.Addr().IsValid() {
		return Event{}, false, nil
	}
	return event, true, nil
}

// walk calls visit for each netlink attribute in data.
func walk(data []byte, visit func(kind uint16, value []byte) error) error {
	for len(data) >= 4 {
		length := int(binary.NativeEndian.Uint16(data[0:2]))
		kind := binary.NativeEndian.Uint16(data[2:4]) & attributeTypeMask
		if length < 4 || length > len(data) {
			return errTruncated
		}
		if err := visit(kind, data[4:length]); err != nil {
			return err
		}
		if align(length) >= len(data) {
			return nil
		}
		data = data[align(length):]
	}
	return nil
}

func align(length int) int { return (length + 3) &^ 3 }

func protocolName(number byte) string {
	switch number {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1, 58:
		return "icmp"
	case 132:
		return "sctp"
	}
	return ""
}
