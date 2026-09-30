package trafficpolicy

import (
	"bytes"
	"strings"
)

// InstrumentDetectionLogs adds a rate-limited kernel log rule in front of
// each encrypted-DNS blocking rule. The messages contain packet metadata only
// and are consumed by the unprivileged encrypted-DNS event forwarder. It
// never logs packet payloads, DNS questions, HTTP headers, or TLS secrets.
//
// The log rule is separate from the blocking rule on purpose: an nftables
// `limit` is a match, so putting it in the blocking rule would stop blocking
// packets once the log rate is exceeded. Instrumenting twice is a no-op.
func InstrumentDetectionLogs(script []byte) []byte {
	lines := bytes.Split(script, []byte{'\n'})
	result := make([][]byte, 0, len(lines)+8)
	for _, raw := range lines {
		line := string(raw)
		prefix := detectionLogPrefix(line)
		if prefix != "" {
			match, ok := blockingMatch(line)
			logLine := match + ` limit rate 10/second burst 20 packets log prefix "` + prefix + `" flags all`
			if ok && (len(result) == 0 || string(result[len(result)-1]) != logLine) {
				result = append(result, []byte(logLine))
			}
		}
		result = append(result, raw)
	}
	return bytes.Join(result, []byte{'\n'})
}

func detectionLogPrefix(line string) string {
	if strings.Contains(line, "log prefix") {
		return ""
	}
	if _, ok := blockingMatch(line); !ok {
		return ""
	}
	switch {
	case strings.Contains(line, "tcp dport 853"):
		return "SHAKERPROXY_EDNS_DOT "
	case strings.Contains(line, "udp dport 853"):
		return "SHAKERPROXY_EDNS_DOQ "
	case strings.Contains(line, "@resolver_doh") && strings.Contains(line, "tcp dport 443"):
		return "SHAKERPROXY_EDNS_DOH_TCP "
	case strings.Contains(line, "@resolver_doh") && strings.Contains(line, "udp dport 443"):
		return "SHAKERPROXY_EDNS_DOH_UDP "
	case strings.Contains(line, "udp dport 443") && strings.Contains(strings.ToLower(line), "strict"):
		return "SHAKERPROXY_EDNS_QUIC "
	}
	return ""
}

// blockingMatch returns the match part of a rule whose verdict is reject or
// drop (everything before the verdict).
func blockingMatch(line string) (string, bool) {
	lower := strings.ToLower(line)
	if strings.Contains(lower, " redirect ") {
		return "", false
	}
	for _, verdict := range []string{" reject", " drop"} {
		if index := strings.Index(lower, verdict); index > 0 {
			rest := lower[index+len(verdict):]
			if rest == "" || rest[0] == ' ' {
				return line[:index], true
			}
		}
	}
	return "", false
}
