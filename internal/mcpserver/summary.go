package mcpserver

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"unicode/utf8"

	"shakerproxy.dev/shakerproxy/internal/agentapi"
	"shakerproxy.dev/shakerproxy/internal/devicereport"
	"shakerproxy.dev/shakerproxy/internal/ingest"
	"shakerproxy.dev/shakerproxy/internal/protocolclass"
)

const maxSummaryBytes = 160

// recentEventSummary prefers the control API's plain-language summary and
// otherwise builds a short local one from existing event columns.
func recentEventSummary(event agentapi.Event) string {
	if summary := strings.TrimSpace(event.Summary); summary != "" {
		return boundSummary(summary)
	}
	return boundSummary(localEventSummary(event.RecentEvent))
}

func localEventSummary(event ingest.RecentEvent) string {
	switch {
	case event.Kind == "encrypted_dns_detected" || event.Service == "doh":
		return "Encrypted DNS (DNS over HTTPS) to " + endpoint(event)
	case event.DNSQuery != "":
		summary := "DNS lookup " + event.DNSQuery
		if event.DNSRecordType != "" {
			summary += " (" + event.DNSRecordType + ")"
		}
		switch {
		case event.DNSResponseCode != "" && event.DNSResponseCode != "NOERROR":
			summary += " → " + event.DNSResponseCode
		case event.DNSAnswerCount != nil:
			summary += " → " + countNoun(*event.DNSAnswerCount, "answer", "answers")
		}
		return summary
	case event.TLSInterceptionState != "":
		host := event.TLSServerName
		if host == "" {
			host = endpoint(event)
		}
		switch event.TLSInterceptionState {
		case "INTERCEPTED":
			return "HTTPS " + host + " — decrypted"
		case "BYPASSED":
			return "HTTPS " + host + " — not decrypted (passed through)"
		default:
			reason := "decryption failed"
			if pinningLikely(event) {
				reason = "not decrypted (pinning likely)"
			} else if event.TLSFailureReason != "" {
				reason = "decryption failed: " + strings.ReplaceAll(event.TLSFailureReason, "_", " ")
			}
			return "HTTPS " + host + " — " + reason
		}
	case event.DetectionSummary != "":
		severity := event.DetectionSeverity
		if severity == "" {
			severity = "WARNING"
		}
		return fmt.Sprintf("Alert (%s): %s", severity, event.DetectionSummary)
	case event.Kind == "suricata.alert":
		return "IDS alert involving " + endpoint(event)
	case event.Kind == "http_request" || event.Kind == "http_response":
		return "HTTP exchange with " + endpoint(event)
	}
	classification := protocolclass.Classify(protocolclass.Observation{Transport: event.Protocol, Service: event.Service, ServerPort: event.DestinationPort, ClientPort: event.SourcePort})
	summary := classification.Label + " to " + endpoint(event)
	if event.NetworkBytes > 0 {
		summary += " · " + devicereport.FormatBytes(event.NetworkBytes)
	}
	if event.Kind != "" && event.Protocol == "" && event.Service == "" && event.DestinationIP == "" {
		summary = event.Kind + " event"
	}
	return summary
}

func endpoint(event ingest.RecentEvent) string {
	if event.DestinationIP == "" {
		return "an unknown destination"
	}
	if event.DestinationPort == 0 {
		return event.DestinationIP
	}
	return net.JoinHostPort(event.DestinationIP, strconv.Itoa(event.DestinationPort))
}

func httpSummary(event ingest.HTTPActivityEvent) string {
	target := event.Host + event.Path
	if target == "" {
		target = "an unknown host"
	}
	summary := strings.TrimSpace(event.Method + " " + target)
	if event.Status > 0 {
		summary += " → " + strconv.Itoa(event.Status)
	}
	if event.Decrypted != nil && *event.Decrypted {
		summary += " (decrypted HTTPS)"
	} else if strings.EqualFold(event.Scheme, "http") {
		summary += " (unencrypted HTTP)"
	}
	return boundSummary(summary)
}

func boundSummary(value string) string {
	if len(value) <= maxSummaryBytes {
		return value
	}
	cut := value[:maxSummaryBytes-len("…")]
	for !utf8.ValidString(cut) && len(cut) > 0 {
		cut = cut[:len(cut)-1]
	}
	return cut + "…"
}
