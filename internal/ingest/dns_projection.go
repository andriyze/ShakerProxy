package ingest

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"regexp"
	"strings"
)

var (
	dnsNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.*-]{1,253}$`)
	dnsCodePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)
)

// MaxDNSAnswers bounds the answers stored with a DNS event: enough to show
// what a name resolved to on one line, never the whole response.
const MaxDNSAnswers = 8

type DNSProjection struct {
	Query        string
	RecordType   string
	ResponseCode string
	AnswerCount  *int
	// Answers are the addresses and names a lookup resolved to, in answer
	// order: IP addresses in canonical form and lower-case DNS names.
	Answers []string
}

// ProjectDNSFields extracts a bounded observation from known Zeek/Suricata DNS
// schemas, ShakerProxy's DNS forwarder lookups and its DNS-over-HTTPS
// detections. It never infers DNS from port 53 alone and never modifies policy.
func ProjectDNSFields(envelope Envelope) DNSProjection {
	doh := envelope.Source == SourceMitmproxy && envelope.Kind == "encrypted_dns_detected"
	forwarded := isHostDNS(envelope)
	if !doh && !forwarded && ((envelope.Source != SourceZeek && envelope.Source != SourceSuricata) || !strings.Contains(strings.ToLower(envelope.Kind), "dns")) {
		return DNSProjection{}
	}
	decoder := json.NewDecoder(bytes.NewReader(envelope.Payload))
	decoder.UseNumber()
	var raw map[string]any
	if decoder.Decode(&raw) != nil {
		return DNSProjection{}
	}
	result := DNSProjection{}
	if forwarded {
		result.Query = dnsName(raw["query"])
		result.RecordType = dnsCode(raw["query_type"])
		result.ResponseCode = dnsCode(raw["response_code"])
		if number, ok := raw["answer_count"].(json.Number); ok {
			if count, err := number.Int64(); err == nil && count >= 0 && count <= 10000 {
				answers := int(count)
				result.AnswerCount = &answers
			}
		}
		if answers, ok := raw["answers"].([]any); ok {
			result.Answers = dnsAnswers(answers, "data")
		}
		return result
	}
	if doh {
		// The addon decodes the DNS question from the DoH request. An empty
		// name means it could not be decoded, which is not the DNS root.
		if name, ok := raw["query_name"].(string); ok && strings.TrimSpace(name) != "" {
			result.Query = dnsName(name)
			result.RecordType = dnsCode(raw["query_type"])
		}
		return result
	}
	if envelope.Source == SourceZeek {
		result.Query = dnsName(raw["query"])
		result.RecordType = dnsCode(raw["qtype_name"])
		result.ResponseCode = dnsCode(raw["rcode_name"])
		if answers, ok := raw["answers"].([]any); ok && len(answers) <= 10000 {
			count := len(answers)
			result.AnswerCount = &count
			result.Answers = dnsAnswers(answers, "")
		}
		return result
	}
	dns, ok := raw["dns"].(map[string]any)
	if !ok {
		return result
	}
	result.Query = dnsName(dns["rrname"])
	result.RecordType = dnsCode(dns["rrtype"])
	// EVE v2/v3 request records also carry the request header's rcode
	// (normally NOERROR); only an answer/response states the outcome.
	if messageType, _ := dns["type"].(string); messageType != "query" && messageType != "request" {
		result.ResponseCode = dnsCode(dns["rcode"])
	}
	if answers, ok := dns["answers"].([]any); ok && len(answers) <= 10000 {
		count := len(answers)
		result.AnswerCount = &count
		result.Answers = dnsAnswers(answers, "rdata")
	}
	if len(result.Answers) == 0 {
		// EVE "grouped" answers: {"A": [...], "CNAME": [...]}.
		if grouped, ok := dns["grouped"].(map[string]any); ok {
			for _, recordType := range []string{"CNAME", "A", "AAAA"} {
				if values, ok := grouped[recordType].([]any); ok {
					result.Answers = append(result.Answers, dnsAnswers(values, "")...)
				}
			}
			result.Answers = boundDNSAnswers(result.Answers)
		}
	}
	if result.Query == "" {
		if queries, ok := dns["queries"].([]any); ok && len(queries) > 0 {
			if first, ok := queries[0].(map[string]any); ok {
				result.Query = dnsName(first["rrname"])
				result.RecordType = dnsCode(first["rrtype"])
			}
		}
	}
	return result
}

func dnsName(value any) string {
	text, ok := value.(string)
	if !ok {
		return ""
	}
	text = strings.TrimSuffix(strings.TrimSpace(text), ".")
	if text == "" {
		return "."
	}
	if !dnsNamePattern.MatchString(text) {
		return ""
	}
	return strings.ToLower(text)
}

func dnsCode(value any) string {
	text, ok := value.(string)
	if !ok {
		return ""
	}
	text = strings.ToUpper(strings.TrimSpace(text))
	if !dnsCodePattern.MatchString(text) {
		return ""
	}
	return text
}

// dnsAnswers reads answer values: plain strings, or objects whose field
// holds the value (dnsd "data", Suricata "rdata").
func dnsAnswers(values []any, field string) []string {
	answers := make([]string, 0, min(len(values), MaxDNSAnswers))
	for _, value := range values {
		if object, ok := value.(map[string]any); ok && field != "" {
			value = object[field]
		}
		if answer := DNSAnswer(value); answer != "" {
			answers = append(answers, answer)
		}
	}
	return boundDNSAnswers(answers)
}

// DNSAnswer normalizes one answer: an IP address in canonical form or a
// lower-case DNS name. Anything else (TXT data, malformed values) is dropped.
func DNSAnswer(value any) string {
	text, ok := value.(string)
	if !ok {
		return ""
	}
	text = strings.TrimSpace(text)
	if address, err := netip.ParseAddr(text); err == nil && address.Zone() == "" {
		return address.Unmap().String()
	}
	text = strings.TrimSuffix(text, ".")
	if text == "" || !dnsNamePattern.MatchString(text) {
		return ""
	}
	return strings.ToLower(text)
}

func boundDNSAnswers(answers []string) []string {
	seen := make(map[string]bool, len(answers))
	bounded := make([]string, 0, min(len(answers), MaxDNSAnswers))
	for _, answer := range answers {
		if answer == "" || seen[answer] {
			continue
		}
		seen[answer] = true
		bounded = append(bounded, answer)
		if len(bounded) == MaxDNSAnswers {
			break
		}
	}
	if len(bounded) == 0 {
		return nil
	}
	return bounded
}

// validEventDNSAnswers checks answers read back from the event store.
func validEventDNSAnswers(answers []string) bool {
	if len(answers) > MaxDNSAnswers {
		return false
	}
	for _, answer := range answers {
		if answer == "" || len(answer) > 255 || DNSAnswer(answer) != answer {
			return false
		}
	}
	return true
}
