package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"shakerproxy.dev/shakerproxy/internal/agentapi"
	"shakerproxy.dev/shakerproxy/internal/ingest"
)

const (
	defaultSummaryBuckets = 12
	maxSummaryBuckets     = 60
)

type TrafficSummaryArgs struct {
	Device  string `json:"device,omitempty" jsonschema:"optional friendly name, IP address, MAC address, or device ID"`
	Query   string `json:"query,omitempty" jsonschema:"optional extra filter in the search_traffic query language, e.g. NOT service:dns or dst.port:1883"`
	Window  string `json:"window,omitempty" jsonschema:"one of 5m, 15m, 1h, 6h, 24h, 7d, 30d; default 24h"`
	Buckets int    `json:"buckets,omitempty" jsonschema:"timeline buckets, 1-60, default 12"`
}

type summaryFacet struct {
	Values []ingest.TrafficSummaryFacetValue `json:"values"`
	Other  int64                             `json:"other,omitempty"`
	// SampledEvents is set when the counts cover only the newest events.
	SampledEvents int64 `json:"sampled_events,omitempty"`
}

type summaryPoint struct {
	Start  time.Time        `json:"start"`
	Events int64            `json:"events"`
	Types  map[string]int64 `json:"types,omitempty"`
}

type trafficSummaryResult struct {
	Summary        string                  `json:"summary"`
	CanonicalQuery string                  `json:"canonical_query,omitempty"`
	From           time.Time               `json:"from"`
	To             time.Time               `json:"to"`
	Totals         summaryTotals           `json:"totals"`
	Facets         map[string]summaryFacet `json:"facets"`
	BucketSeconds  float64                 `json:"bucket_seconds"`
	Timeline       []summaryPoint          `json:"timeline"`
	ExcludedNote   string                  `json:"excluded"`
}

type summaryTotals struct {
	Events        int64            `json:"events"`
	BytesSent     int64            `json:"bytes_sent"`
	BytesReceived int64            `json:"bytes_received"`
	Types         map[string]int64 `json:"types"`
}

func (s *Service) trafficSummary(ctx context.Context, _ *mcp.CallToolRequest, args TrafficSummaryArgs) (*mcp.CallToolResult, any, error) {
	buckets := args.Buckets
	if buckets == 0 {
		buckets = defaultSummaryBuckets
	}
	if buckets < 1 || buckets > maxSummaryBuckets {
		return nil, nil, fmt.Errorf("buckets must be between 1 and %d", maxSummaryBuckets)
	}
	window, relative, err := searchWindow(args.Window)
	if err != nil {
		return nil, nil, err
	}
	parts := []string{"time:" + relative}
	scope := "in the last " + windowNames[window]
	if strings.TrimSpace(args.Device) != "" {
		device, err := s.resolveDevice(ctx, args.Device)
		if err != nil {
			return nil, nil, err
		}
		parts = append(parts, "device.id:"+device.DeviceID)
		scope += " for " + firstNonEmpty(device.FriendlyName, device.DeviceID)
	}
	if extra := strings.TrimSpace(args.Query); extra != "" {
		if len(extra) > 1536 {
			return nil, nil, errors.New("query is limited to 1536 characters")
		}
		parts = append(parts, "("+extra+")")
		scope += " matching " + extra
	}
	summary, err := s.backend.TrafficSummary(ctx, agentapi.TrafficSummaryRequest{Query: strings.Join(parts, " AND "), Buckets: buckets})
	if err != nil {
		return nil, nil, fmt.Errorf("summarize traffic: %w (see the query syntax in search_traffic's description)", err)
	}
	result := trafficSummaryResult{
		CanonicalQuery: summary.CanonicalQuery, From: summary.From, To: summary.To, BucketSeconds: summary.BucketSeconds,
		Totals:       summaryTotals{Events: summary.Totals.Events, BytesSent: summary.Totals.BytesSent, BytesReceived: summary.Totals.BytesReceived, Types: typeCounts(summary.Totals.Types)},
		Facets:       map[string]summaryFacet{},
		Timeline:     make([]summaryPoint, 0, len(summary.Buckets)),
		ExcludedNote: "Analyzer duplicates (Suricata flow and app-layer records, Zeek TLS/QUIC handshake and bookkeeping logs, connection records of DNS lookups) are not counted; see docs/traffic-stream-types.md.",
	}
	for _, facet := range summary.Facets {
		if facet.Field == ingest.SummaryFacetType {
			continue
		}
		result.Facets[facet.Field] = summaryFacet{Values: facet.Values, Other: facet.OtherCount, SampledEvents: facet.SampledEvents}
	}
	for _, bucket := range summary.Buckets {
		result.Timeline = append(result.Timeline, summaryPoint{Start: bucket.Start, Events: bucket.Counts.Total(), Types: typeCounts(bucket.Counts)})
	}
	result.Summary = trafficSummaryLine(summary, scope)
	return textResult(result)
}

func typeCounts(counts ingest.StreamTypeCounts) map[string]int64 {
	result := map[string]int64{}
	for _, streamType := range ingest.StreamTypes {
		if count := counts.Get(streamType); count > 0 {
			result[streamType] = count
		}
	}
	return result
}

// trafficSummaryLine reads like "1,240 events in the last hour for Pixel:
// 700 DNS, 400 TLS, 140 QUIC; sent 2.1 MB, received 48 MB. Top devices:
// Pixel 1,240. Top destinations: Google 610, Meta 90."
func trafficSummaryLine(summary ingest.TrafficSummary, scope string) string {
	var line strings.Builder
	line.WriteString(formatCount(summary.Totals.Events) + " " + plural(summary.Totals.Events, "event", "events") + " " + scope)
	if summary.Totals.Events == 0 {
		line.WriteString(".")
		return line.String()
	}
	typeParts := []string{}
	for _, facet := range summary.Facets {
		if facet.Field != ingest.SummaryFacetType {
			continue
		}
		for _, value := range facet.Values {
			typeParts = append(typeParts, formatCount(value.Count)+" "+streamTypeLabel(value.Value))
		}
	}
	line.WriteString(": " + strings.Join(typeParts, ", "))
	if summary.Totals.BytesSent > 0 || summary.Totals.BytesReceived > 0 {
		line.WriteString("; sent " + formatBytes(summary.Totals.BytesSent) + ", received " + formatBytes(summary.Totals.BytesReceived))
	}
	line.WriteString(".")
	for _, facet := range summary.Facets {
		var title string
		switch facet.Field {
		case ingest.SummaryFacetDevice:
			title = "Top devices"
		case ingest.SummaryFacetOrganization:
			title = "Top destinations"
		default:
			continue
		}
		if len(facet.Values) == 0 {
			continue
		}
		top := []string{}
		for _, value := range facet.Values[:min(5, len(facet.Values))] {
			top = append(top, firstNonEmpty(value.Label, value.Value)+" "+formatCount(value.Count))
		}
		line.WriteString(" " + title + ": " + strings.Join(top, ", "))
		if facet.SampledEvents > 0 {
			line.WriteString(" (of the newest " + formatCount(facet.SampledEvents) + " events)")
		}
		line.WriteString(".")
	}
	return line.String()
}

func streamTypeLabel(streamType string) string {
	switch streamType {
	case ingest.StreamDNS, ingest.StreamTLS, ingest.StreamQUIC, ingest.StreamHTTP:
		return strings.ToUpper(streamType)
	}
	return streamType
}

func plural(count int64, singular, pluralForm string) string {
	if count == 1 {
		return singular
	}
	return pluralForm
}

func formatCount(value int64) string {
	digits := strconv.FormatInt(value, 10)
	if len(digits) <= 3 {
		return digits
	}
	var grouped strings.Builder
	lead := len(digits) % 3
	if lead > 0 {
		grouped.WriteString(digits[:lead])
	}
	for index := lead; index < len(digits); index += 3 {
		if grouped.Len() > 0 {
			grouped.WriteByte(',')
		}
		grouped.WriteString(digits[index : index+3])
	}
	return grouped.String()
}

func formatBytes(value int64) string {
	const unit = 1000
	if value < unit {
		return strconv.FormatInt(value, 10) + " B"
	}
	scaled, suffix := float64(value), ""
	for _, next := range []string{"kB", "MB", "GB", "TB", "PB"} {
		scaled /= unit
		suffix = next
		if scaled < unit {
			break
		}
	}
	if scaled < 10 {
		return strconv.FormatFloat(scaled, 'f', 1, 64) + " " + suffix
	}
	return strconv.FormatFloat(scaled, 'f', 0, 64) + " " + suffix
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
