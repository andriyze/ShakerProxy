package wifi

import (
	"context"
	"io"
	"time"

	"shakerproxy.dev/shakerproxy/internal/pcapng"
)

// Decode parses one radiotap-framed capture into a management frame. It
// returns false for anything else: control and data frames, damaged frames,
// and input that does not parse.
func Decode(at time.Time, data []byte) (Frame, bool) {
	radio, err := ParseRadiotap(data)
	if err != nil || radio.BadFCS {
		return Frame{}, false
	}
	frame, err := ParseManagement(data[radio.Length:], radio.FCS)
	if err != nil {
		return Frame{}, false
	}
	return Frame{At: at, Radio: radio, Frame: frame}, true
}

// FileProgress is how far a capture file was read.
type FileProgress struct {
	// Packets is the number of packets read, including skipped ones.
	Packets int
	// Complete is false when the file ended in a partial block, as one
	// dumpcap is still writing does.
	Complete bool
	// Frames counts the management frames given to the observer.
	Frames int
}

// ObserveFile feeds the radiotap frames of one PCAPNG file to the observer,
// skipping the first skip packets (already read on an earlier pass).
func ObserveFile(ctx context.Context, reader io.Reader, observer *Observer, skip int) (FileProgress, error) {
	progress := FileProgress{}
	err := pcapng.ScanPackets(ctx, reader, func(packet pcapng.Packet) error {
		progress.Packets++
		if progress.Packets <= skip || packet.LinkType != LinkTypeRadiotap {
			return nil
		}
		if frame, ok := Decode(packet.At, packet.Data); ok {
			observer.Observe(frame)
			progress.Frames++
		}
		return nil
	})
	if err == io.ErrUnexpectedEOF {
		return progress, nil
	}
	if err != nil {
		return progress, err
	}
	progress.Complete = true
	return progress, nil
}
