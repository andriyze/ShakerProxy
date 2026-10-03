// Package syslogcollector receives network devices' own logs over syslog and
// turns them into ShakerProxy events and device identity. It is UniFi-first:
// a generic syslog frame/header parser feeds a UniFi-aware message layer, with
// a clean seam to add other vendors later.
//
// Everything read here is untrusted input from the network. The receiver
// accepts only allowlisted sources, bounds message size and rate, and treats
// every byte as data, never as an instruction.
package syslogcollector

import (
	"bufio"
	"errors"
	"io"
)

// MaxMessageBytes bounds one syslog message. RFC5424 requires receivers to
// support at least 2048 bytes; 8 KiB leaves room for UniFi's longer kernel
// firewall lines without letting a sender exhaust memory.
const MaxMessageBytes = 8 << 10

// maxOctetCountDigits bounds the length prefix of an octet-counted frame, so a
// sender cannot force a huge allocation by sending many leading digits.
const maxOctetCountDigits = 7

var errFrameTooLarge = errors.New("syslog frame exceeds the message limit")

// ReadFrame reads one syslog message from a stream. It supports both TCP
// framings from RFC6587: octet counting ("<len> <message>") when the next
// byte is a digit, and newline/null termination otherwise. The returned
// message excludes the length prefix and the trailing terminator. io.EOF with
// no bytes means the stream ended cleanly between frames.
func ReadFrame(reader *bufio.Reader) ([]byte, error) {
	first, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}
	if first >= '0' && first <= '9' {
		return readOctetCounted(reader, first)
	}
	if err := reader.UnreadByte(); err != nil {
		return nil, err
	}
	return readDelimited(reader)
}

func readOctetCounted(reader *bufio.Reader, first byte) ([]byte, error) {
	length := int(first - '0')
	digits := 1
	for {
		next, err := reader.ReadByte()
		if err != nil {
			return nil, err
		}
		if next == ' ' {
			break
		}
		if next < '0' || next > '9' || digits >= maxOctetCountDigits {
			return nil, errors.New("syslog octet count is invalid")
		}
		length = length*10 + int(next-'0')
		digits++
	}
	if length <= 0 || length > MaxMessageBytes {
		return nil, errFrameTooLarge
	}
	message := make([]byte, length)
	if _, err := io.ReadFull(reader, message); err != nil {
		return nil, err
	}
	return message, nil
}

func readDelimited(reader *bufio.Reader) ([]byte, error) {
	message := make([]byte, 0, 256)
	for {
		next, err := reader.ReadByte()
		if err != nil {
			if err == io.EOF && len(message) > 0 {
				return message, nil
			}
			return nil, err
		}
		if next == '\n' || next == 0 {
			return message, nil
		}
		if len(message) >= MaxMessageBytes {
			// Drain the rest of the oversized frame so the stream stays
			// aligned, then report it.
			if drainErr := drainToDelimiter(reader); drainErr != nil {
				return nil, drainErr
			}
			return nil, errFrameTooLarge
		}
		message = append(message, next)
	}
}

func drainToDelimiter(reader *bufio.Reader) error {
	for {
		next, err := reader.ReadByte()
		if err != nil {
			return err
		}
		if next == '\n' || next == 0 {
			return nil
		}
	}
}
