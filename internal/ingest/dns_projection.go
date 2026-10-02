package ingest

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
)

var (
	dnsNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.*-]{1,253}$`)
	dnsCodePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)
)

type DNSProjection struct {
	Query        string
	RecordType   string
	ResponseCode string
	AnswerCount  *int
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
