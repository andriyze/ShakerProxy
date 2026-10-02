package agentapi

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/ingest"
)

func agentTrafficSummary(buckets int) ingest.TrafficSummary {
	from := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	width := time.Hour / time.Duration(buckets)
	summary := ingest.TrafficSummary{Schema: 1, GeneratedAt: from.Add(time.Hour), From: from, To: from.Add(time.Hour), BucketSeconds: width.Seconds(), Buckets: make([]ingest.TrafficSummaryBucket, buckets)}
	for index := range summary.Buckets {
		summary.Buckets[index].Start = from.Add(time.Duration(index) * width)
	}
	summary.Buckets[0].Counts.TLS = 4
	summary.Totals = ingest.TrafficSummaryTotals{Events: 4, BytesSent: 10, BytesReceived: 900, Types: ingest.StreamTypeCounts{TLS: 4}}
	for _, field := range ingest.TrafficSummaryFacetFields {
		facet := ingest.TrafficSummaryFacet{Field: field, Values: []ingest.TrafficSummaryFacetValue{}, Exact: true}
		if field == ingest.SummaryFacetDevice {
			facet.Values = []ingest.TrafficSummaryFacetValue{{Value: intelDeviceID, Label: "Bench camera", Count: 4}}
		}
		summary.Facets = append(summary.Facets, facet)
	}
	return summary
}

func TestTrafficSummaryRequestsTheBoundedSummary(t *testing.T) {
	var query string
	reply := agentTrafficSummary(12)
	client := intelServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/events/summary" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		query = r.URL.RawQuery
		writeJSONResponse(w, http.StatusOK, reply)
	})
	summary, err := client.TrafficSummary(context.Background(), TrafficSummaryRequest{Query: "time:last_1h AND protocol:tcp", Buckets: 12})
	if err != nil || summary.Totals.Events != 4 || summary.Facets[0].Values[0].Label != "Bench camera" || query != "buckets=12&q=time%3Alast_1h+AND+protocol%3Atcp" {
		t.Fatalf("summary: %+v query=%q err=%v", summary.Totals, query, err)
	}
	if _, err := client.TrafficSummary(context.Background(), TrafficSummaryRequest{}); err == nil || !strings.Contains(err.Error(), "invalid summary") {
		t.Fatalf("a summary with the wrong bucket count was accepted: %v", err)
	}
	for _, request := range []TrafficSummaryRequest{{Buckets: -1}, {Buckets: ingest.MaxTrafficSummaryBuckets + 1}, {Query: strings.Repeat("a", 2049)}} {
		if _, err := client.TrafficSummary(context.Background(), request); err == nil {
			t.Errorf("invalid request accepted: %+v", request)
		}
	}
	reply.Totals.Events = 5
	if _, err := client.TrafficSummary(context.Background(), TrafficSummaryRequest{Buckets: 12}); err == nil {
		t.Fatal("inconsistent totals were accepted")
	}
}
