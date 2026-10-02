package ingest

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"unicode/utf8"

	"shakerproxy.dev/shakerproxy/internal/protocolclass"
)

// MaxEventSummaryRunes bounds EventSummary output.
const MaxEventSummaryRunes = 160

// EventSummary renders one plain-language line for an event, for example
// "DNS lookup api.example.com (A) → 3 answers" or
// "HTTPS api.example.com — decrypted". It uses only projected columns, so it
// never contains headers, bodies, cookies, credentials, or query strings.
func EventSummary(event RecentEvent) string {
	return boundSummary(strings.Join(strings.Fields(eventSummary(event)), " "))
}

func eventSummary(event RecentEvent) string {
	switch {
	case isHostWiFi(event.Source, event.Kind):
		return wifiSummary(event)
	case event.DetectionSummary != "":
		return "ShakerProxy detection (" + event.DetectionSeverity + "): " + event.DetectionSummary
	case event.AlertSignature != "":
		if severity := alertSeverityLabel(event.AlertSeverity); severity != "" {
			return "Alert (" + severity + "): " + event.AlertSignature
		}
		return "Alert: " + event.AlertSignature
	case event.Source == SourceHost && event.Kind == HostBlockedKind:
		return "Blocked " + blockReasonLabel(event.BlockedReason) + " to " + firstNonEmpty(endpoint(event.DestinationIP, event.DestinationPort), "an unknown resolver") + " — falls back to plain DNS"
	case event.Blocked && event.DNSQuery != "":
		return "DNS lookup " + event.DNSQuery + recordTypeSuffix(event.DNSRecordType) + " — blocked (" + blockReasonLabel(event.BlockedReason) + ")"
	case event.Source == SourceMitmproxy && event.Kind == "encrypted_dns_detected":
		if event.DNSQuery != "" {
			return "Encrypted DNS (DoH) lookup " + event.DNSQuery + recordTypeSuffix(event.DNSRecordType)
		}
		return "Encrypted DNS (DoH) to " + firstNonEmpty(event.HTTPHost, event.TLSServerName, event.DestinationIP, "an unknown resolver")
	case event.DNSQuery != "":
		return "DNS lookup " + event.DNSQuery + recordTypeSuffix(event.DNSRecordType) + dnsOutcome(event)
	case event.Source == SourceHost && event.Kind == HostConnKind:
		target := net.JoinHostPort(event.DestinationIP, strconv.Itoa(event.DestinationPort))
		if event.DNSName != "" {
			return "Connection to " + event.DNSName + " (" + target + "/" + event.Protocol + ")"
		}
		return "Connection to " + target + "/" + event.Protocol
	case event.TLSInterceptionState != "":
		host := firstNonEmpty(event.TLSServerName, event.DestinationIP, "unknown host")
		switch event.TLSInterceptionState {
		case "INTERCEPTED":
			return "HTTPS " + host + " — decrypted"
		case "BYPASSED":
			return "HTTPS " + host + " — not decrypted (bypassed)"
		default:
			if event.TLSPinningSuspected {
				return "HTTPS " + host + " — not decrypted (pinned?)"
			}
			if event.TLSFailureReason != "" {
				return "HTTPS " + host + " — decryption failed: " + strings.ReplaceAll(event.TLSFailureReason, "_", " ")
			}
			return "HTTPS " + host + " — decryption failed"
		}
	case event.HTTPMethod != "" || event.HTTPHost != "":
		target := firstNonEmpty(event.HTTPHost, event.DestinationIP) + event.HTTPPath
		line := strings.TrimSpace(event.HTTPMethod + " " + target)
		if event.HTTPStatus != 0 {
			line += " → " + strconv.Itoa(event.HTTPStatus)
		}
		return line
	case event.TLSServerName != "":
		label := "TLS"
		if event.AppProtocol == "quic" {
			label = "QUIC"
		}
		return label + " to " + event.TLSServerName + byteSuffix(event.NetworkBytes)
	case event.AppProtocol != "":
		label := event.AppProtocol
		if protocol, ok := protocolclass.Lookup(event.AppProtocol); ok {
			label = protocol.Label
		}
		if destination := endpoint(event.DestinationIP, event.DestinationPort); destination != "" {
			return label + " to " + destination + byteSuffix(event.NetworkBytes)
		}
		return label + " traffic" + byteSuffix(event.NetworkBytes)
	}
	line := sourceLabel(event.Source) + " " + kindLabel(event)
	if event.SourceIP != "" && event.DestinationIP != "" {
		line += ": " + event.SourceIP + " → " + endpoint(event.DestinationIP, event.DestinationPort)
	}
	return line
}

// blockReasonLabel names what ShakerProxy blocked in plain language.
func blockReasonLabel(reason string) string {
	switch reason {
	case "dot":
		return "DNS over TLS"
	case "doq":
		return "DNS over QUIC"
	case "doh-ip":
		return "DNS over HTTPS"
	case "doh3-ip":
		return "DNS over HTTP/3"
	case "doh-name":
		return "encrypted DNS resolver name"
	case "canary":
		return "encrypted DNS check"
	case "device-domain":
		return "domain blocked for this device"
	default:
		return "encrypted DNS"
	}
}

func dnsOutcome(event RecentEvent) string {
	if event.DNSResponseCode != "" && event.DNSResponseCode != "NOERROR" {
		return " → " + event.DNSResponseCode
	}
	if event.DNSAnswerCount != nil {
		switch *event.DNSAnswerCount {
		case 0:
			return " → no answers"
		case 1:
			return " → 1 answer"
		default:
			return " → " + strconv.Itoa(*event.DNSAnswerCount) + " answers"
		}
	}
	return ""
}

func recordTypeSuffix(recordType string) string {
	if recordType == "" {
		return ""
	}
	return " (" + recordType + ")"
}

func alertSeverityLabel(severity int) string {
	switch severity {
	case 1:
		return "HIGH"
	case 2:
		return "MEDIUM"
	case 3:
		return "LOW"
	case 4:
		return "INFO"
	}
	return ""
}

func sourceLabel(source Source) string {
	switch source {
	case SourceZeek:
		return "Zeek"
	case SourceSuricata:
		return "Suricata"
	case SourceMitmproxy:
		return "Interception"
	case SourceHost:
		return "ShakerProxy"
	}
	return string(source)
}

func kindLabel(event RecentEvent) string {
	kind := event.Kind
	for _, prefix := range []string{"zeek.", "suricata.", "shakerproxy."} {
		kind = strings.TrimPrefix(kind, prefix)
	}
	kind = strings.NewReplacer("_", " ", ".", " ").Replace(kind)
	if kind == "" {
		return "event"
	}
	return kind + " event"
}

func endpoint(address string, port int) string {
	if address == "" {
		return ""
	}
	if port == 0 {
		return address
	}
	return net.JoinHostPort(address, strconv.Itoa(port))
}

func byteSuffix(bytes int64) string {
	if bytes <= 0 {
		return ""
	}
	return " · " + formatBytes(bytes)
}

func formatBytes(bytes int64) string {
	value := float64(bytes)
	for _, unit := range []string{"B", "KB", "MB", "GB", "TB"} {
		if value < 1024 || unit == "TB" {
			if unit == "B" {
				return strconv.FormatInt(bytes, 10) + " B"
			}
			if value < 10 {
				return strings.TrimSuffix(fmt.Sprintf("%.1f", value), ".0") + " " + unit
			}
			return fmt.Sprintf("%.0f %s", value, unit)
		}
		value /= 1024
	}
	return strconv.FormatInt(bytes, 10) + " B"
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func boundSummary(summary string) string {
	if utf8.RuneCountInString(summary) <= MaxEventSummaryRunes {
		return summary
	}
	runes := []rune(summary)
	return strings.TrimSpace(string(runes[:MaxEventSummaryRunes-1])) + "…"
}

func validEventSummary(summary string) bool {
	if summary == "" {
		return true
	}
	if !utf8.ValidString(summary) || utf8.RuneCountInString(summary) > MaxEventSummaryRunes || summary != strings.TrimSpace(summary) {
		return false
	}
	for _, character := range summary {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}
