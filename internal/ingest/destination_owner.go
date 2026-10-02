package ingest

import (
	"strings"

	"shakerproxy.dev/shakerproxy/internal/domainclass"
)

// destinationName is the name an event gives its destination: the TLS or
// QUIC server name, the web host, the name a lookup asked for, or the name a
// gateway-reported connection was resolved from.
func destinationName(event RecentEvent) string {
	for _, name := range []string{event.TLSServerName, event.HTTPHost, event.DNSQuery, event.DNSName} {
		if strings.TrimSpace(name) != "" {
			return name
		}
	}
	return ""
}

// destinationOwner says who operates the destination, from the curated
// domain table. Unknown destinations have neither value.
func destinationOwner(event RecentEvent) (organization, category string) {
	name := destinationName(event)
	if name == "" {
		return "", ""
	}
	classification := domainclass.Classify(name)
	if classification.Organization == "" || classification.Category == domainclass.CategoryUnknown {
		return "", ""
	}
	return classification.Organization, string(classification.Category)
}

// maxEventByteCount bounds the per-side byte counts a row may carry (1 PiB).
const maxEventByteCount = int64(1) << 50

func validEventDestinationOwner(event RecentEvent) bool {
	if event.DestinationOrganization == "" {
		return event.DestinationCategory == ""
	}
	if len(event.DestinationOrganization) > 128 || strings.ContainsAny(event.DestinationOrganization, "\r\n\x00") {
		return false
	}
	for _, category := range domainclass.Categories() {
		if string(category) == event.DestinationCategory && category != domainclass.CategoryUnknown {
			return true
		}
	}
	return false
}

func validEventByteCounts(event RecentEvent) bool {
	for _, count := range []*int64{event.BytesSent, event.BytesReceived} {
		if count != nil && (*count < 0 || *count > maxEventByteCount) {
			return false
		}
	}
	return true
}
