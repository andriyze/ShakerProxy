package dnsproxy

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"strconv"
	"time"
)

// maxRecordedAnswers bounds the answers kept per lookup; AnswerCount still
// counts all of them.
const maxRecordedAnswers = 32

// Lookup is one lab DNS query the forwarder answered, recorded so the Traffic
// view shows which names each device looked up even when no capture runs.
type Lookup struct {
	At          time.Time
	Client      netip.AddrPort
	Transport   string
	Name        string
	Type        string
	Rcode       string
	AnswerCount int
	Answers     []Answer
	// Blocked is set when ShakerProxy answered NXDOMAIN for a domain blocked
	// for the client's device.
	Blocked       bool
	BlockedDomain string
}

// Answer is one answer record. Data is the address of an A or AAAA record or
// the target of a CNAME; other record types carry no data.
type Answer struct {
	Name string
	Type string
	TTL  uint32
	Data string
}

// LookupObserver receives every answered lab query. ObserveLookup runs after
// the answer was sent and must not block.
type LookupObserver interface {
	ObserveLookup(Lookup)
}

// answerNote carries what the forwarder decided about a query, beyond the
// response bytes, to the lookup record.
type answerNote struct {
	blocked bool
	domain  string
}

// NewLookup describes a query and the response sent for it. It fails only
// when the query has no readable question.
func NewLookup(at time.Time, transport string, client netip.AddrPort, query, response []byte) (Lookup, error) {
	name, end, err := firstQuestion(query)
	if err != nil {
		return Lookup{}, err
	}
	lookup := Lookup{At: at.UTC(), Client: netip.AddrPortFrom(client.Addr().Unmap(), client.Port()), Transport: transport, Name: name, Type: recordTypeName(binary.BigEndian.Uint16(query[end-4 : end-2]))}
	if len(response) < minimumDNSMessage {
		return lookup, nil
	}
	lookup.Rcode = rcodeName(binary.BigEndian.Uint16(response[2:4]) & 0x000f)
	lookup.AnswerCount, lookup.Answers = parseAnswers(response)
	return lookup, nil
}

// firstQuestion returns the first question's name and the offset just past
// that question's type and class.
func firstQuestion(message []byte) (string, int, error) {
	if len(message) < minimumDNSMessage || binary.BigEndian.Uint16(message[4:6]) == 0 {
		return "", 0, errors.New("DNS message has no question")
	}
	name, next, err := decodeName(message, minimumDNSMessage, map[int]bool{}, 0)
	if err != nil {
		return "", 0, err
	}
	if next+4 > len(message) {
		return "", 0, errors.New("DNS question is truncated")
	}
	return name, next + 4, nil
}

// parseAnswers reads the answer section. A malformed record ends parsing;
// what was read before it is kept.
func parseAnswers(message []byte) (int, []Answer) {
	count := int(binary.BigEndian.Uint16(message[6:8]))
	offset, err := questionEnd(message)
	if err != nil || count == 0 {
		return count, nil
	}
	answers := []Answer{}
	for index := 0; index < count && len(answers) < maxRecordedAnswers; index++ {
		name, next, err := decodeName(message, offset, map[int]bool{}, 0)
		if err != nil || next+10 > len(message) {
			break
		}
		recordType := binary.BigEndian.Uint16(message[next : next+2])
		ttl := binary.BigEndian.Uint32(message[next+4 : next+8])
		length := int(binary.BigEndian.Uint16(message[next+8 : next+10]))
		data := next + 10
		if data+length > len(message) {
			break
		}
		answer := Answer{Name: name, Type: recordTypeName(recordType), TTL: ttl}
		switch {
		case recordType == 1 && length == 4:
			answer.Data = netip.AddrFrom4([4]byte(message[data : data+4])).String()
		case recordType == 28 && length == 16:
			answer.Data = netip.AddrFrom16([16]byte(message[data : data+16])).String()
		case recordType == 5:
			if target, _, err := decodeName(message, data, map[int]bool{}, 0); err == nil {
				answer.Data = target
			}
		}
		answers = append(answers, answer)
		offset = data + length
	}
	return count, answers
}

var recordTypeNames = map[uint16]string{
	1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA",
	33: "SRV", 35: "NAPTR", 43: "DS", 46: "RRSIG", 48: "DNSKEY", 64: "SVCB", 65: "HTTPS", 255: "ANY",
}

func recordTypeName(value uint16) string {
	if name, ok := recordTypeNames[value]; ok {
		return name
	}
	return "TYPE" + strconv.Itoa(int(value))
}

var rcodeNames = []string{"NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED"}

func rcodeName(value uint16) string {
	if int(value) < len(rcodeNames) {
		return rcodeNames[value]
	}
	return "RCODE" + strconv.Itoa(int(value))
}
