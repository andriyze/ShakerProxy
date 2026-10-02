package pcapng

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"
)

// Packet is one captured packet: its link type (for example 127, 802.11
// with radiotap), when it was captured (zero for a simple packet block),
// and its captured bytes. Data is only valid during the callback.
type Packet struct {
	LinkType uint16
	At       time.Time
	Data     []byte
}

// ErrStopScan ends ScanPackets early without an error.
var ErrStopScan = errors.New("stop packet scan")

// ScanPackets reads one PCAPNG file and calls visit for every packet in
// order. A partial last block, as in a file still being written, ends the
// scan with io.ErrUnexpectedEOF after the complete packets were visited.
func ScanPackets(ctx context.Context, reader io.Reader, visit func(Packet) error) error {
	if ctx == nil || reader == nil || visit == nil {
		return errors.New("PCAPNG packet scan is incomplete")
	}
	var section *rewriteSection
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		block, blockType, order, err := readBlock(reader, rewriteReadSection(section))
		if errors.Is(err, io.EOF) {
			if section == nil {
				return fmt.Errorf("%w: section header is absent", ErrInvalidPCAPNG)
			}
			return nil
		}
		if err != nil {
			if section != nil && errors.Is(err, ErrInvalidPCAPNG) && truncated(err) {
				return io.ErrUnexpectedEOF
			}
			return err
		}
		if blockType == 0x0a0d0d0a {
			if order.Uint16(block[12:14]) != 1 || order.Uint16(block[14:16]) != 0 {
				return fmt.Errorf("%w: section version is unsupported", ErrInvalidPCAPNG)
			}
			section = &rewriteSection{order: order}
			continue
		}
		if section == nil {
			return fmt.Errorf("%w: data precedes the section header", ErrInvalidPCAPNG)
		}
		if blockType == 1 {
			configuration, err := parseRewriteInterface(block, section.order)
			if err != nil || len(section.interfaces) >= maxInterfaces {
				return fmt.Errorf("%w: interface block is invalid", ErrInvalidPCAPNG)
			}
			section.interfaces = append(section.interfaces, configuration)
			continue
		}
		data, configuration, timestamp, packetBlock, err := rewritePacket(block, blockType, section)
		if err != nil {
			return err
		}
		if !packetBlock {
			continue
		}
		packet := Packet{LinkType: configuration.linkType, Data: data}
		if timestamp != nil {
			at, err := configuration.observedAt(*timestamp)
			if err != nil {
				return err
			}
			packet.At = at
		}
		if err := visit(packet); err != nil {
			if errors.Is(err, ErrStopScan) {
				return nil
			}
			return err
		}
	}
}

// truncated reports a block cut short by the end of the file, which is how
// a segment dumpcap is still writing ends.
func truncated(err error) bool {
	message := err.Error()
	for _, suffix := range []string{"truncated block type", "truncated block header", "block body is truncated"} {
		if len(message) >= len(suffix) && message[len(message)-len(suffix):] == suffix {
			return true
		}
	}
	return false
}
