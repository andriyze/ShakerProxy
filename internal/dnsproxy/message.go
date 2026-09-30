package dnsproxy

import (
	"encoding/binary"
	"errors"
	"strings"
)

const (
	minimumDNSMessage = 12
	maximumDNSMessage = 65535
)

func QuestionName(message []byte) (string, error) {
	if len(message) < minimumDNSMessage || binary.BigEndian.Uint16(message[4:6]) == 0 {
		return "", errors.New("DNS message has no question")
	}
	name, _, err := decodeName(message, minimumDNSMessage, map[int]bool{}, 0)
	return name, err
}

func questionEnd(message []byte) (int, error) {
	if len(message) < minimumDNSMessage {
		return 0, errors.New("DNS message is too short")
	}
	count := int(binary.BigEndian.Uint16(message[4:6]))
	if count < 1 || count > 16 {
		return 0, errors.New("DNS question count is invalid")
	}
	offset := minimumDNSMessage
	for index := 0; index < count; index++ {
		_, next, err := decodeName(message, offset, map[int]bool{}, 0)
		if err != nil {
			return 0, err
		}
		offset = next
		if offset+4 > len(message) {
			return 0, errors.New("DNS question is truncated")
		}
		offset += 4
	}
	return offset, nil
}

func decodeName(message []byte, offset int, visited map[int]bool, depth int) (string, int, error) {
	if depth > 16 || offset < 0 || offset >= len(message) {
		return "", 0, errors.New("DNS name is invalid")
	}
	labels := []string{}
	cursor := offset
	next := -1
	for {
		if cursor >= len(message) {
			return "", 0, errors.New("DNS name is truncated")
		}
		length := int(message[cursor])
		cursor++
		if length == 0 {
			if next < 0 {
				next = cursor
			}
			break
		}
		if length&0xc0 == 0xc0 {
			if cursor >= len(message) {
				return "", 0, errors.New("DNS compression pointer is truncated")
			}
			pointer := ((length & 0x3f) << 8) | int(message[cursor])
			cursor++
			if next < 0 {
				next = cursor
			}
			if pointer >= len(message) || visited[pointer] {
				return "", 0, errors.New("DNS compression pointer is invalid")
			}
			visited[pointer] = true
			suffix, _, err := decodeName(message, pointer, visited, depth+1)
			if err != nil {
				return "", 0, err
			}
			if suffix != "" {
				labels = append(labels, suffix)
			}
			break
		}
		if length&0xc0 != 0 || length > 63 || cursor+length > len(message) {
			return "", 0, errors.New("DNS label is invalid")
		}
		label := strings.ToLower(string(message[cursor : cursor+length]))
		if !printableDNSLabel(label) {
			return "", 0, errors.New("DNS label contains unsupported bytes")
		}
		labels = append(labels, label)
		cursor += length
		if cursor-offset > 255 {
			return "", 0, errors.New("DNS name exceeds maximum wire length")
		}
	}
	return strings.Join(labels, "."), next, nil
}

func printableDNSLabel(value string) bool {
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-' || character == '_' {
			continue
		}
		return false
	}
	return true
}

func validateQuery(message []byte) error {
	if len(message) < minimumDNSMessage || len(message) > maximumDNSMessage {
		return errors.New("DNS query length is invalid")
	}
	flags := binary.BigEndian.Uint16(message[2:4])
	if flags&0x8000 != 0 {
		return errors.New("DNS client message is already a response")
	}
	_, err := questionEnd(message)
	return err
}

func validResponse(query, response []byte) bool {
	return len(response) >= minimumDNSMessage && len(response) <= maximumDNSMessage &&
		query[0] == response[0] && query[1] == response[1] &&
		binary.BigEndian.Uint16(response[2:4])&0x8000 != 0
}

func servfail(query []byte) []byte {
	return errorResponse(query, 2)
}

// nxdomain answers "name does not exist" with the question echoed and no
// records, which is what a device sees for a domain that is really gone.
func nxdomain(query []byte) []byte {
	return errorResponse(query, 3)
}

func errorResponse(query []byte, rcode uint16) []byte {
	end, err := questionEnd(query)
	if err != nil {
		return nil
	}
	response := append([]byte(nil), query[:end]...)
	flags := binary.BigEndian.Uint16(query[2:4])
	// Preserve opcode, recursion desired, authenticated-data and checking-disabled.
	flags = (flags & 0x7910) | 0x8080 | (rcode & 0x000f)
	binary.BigEndian.PutUint16(response[2:4], flags)
	binary.BigEndian.PutUint16(response[6:8], 0)
	binary.BigEndian.PutUint16(response[8:10], 0)
	binary.BigEndian.PutUint16(response[10:12], 0)
	return response
}
