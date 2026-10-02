package mcpserver

import (
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/coverage"
)

func TestCoverageSummarySaysWhatIsSeenAndHowToBypass(t *testing.T) {
	never := coverageSummary(coverage.Overview{Routing: []coverage.Finding{{Title: "IPv6", Status: coverage.FindingOK}}})
	if !strings.Contains(never, "has not run yet") || !strings.Contains(never, "no way around ShakerProxy was found") {
		t.Fatalf("summary = %q", never)
	}
	run := &coverage.Report{State: coverage.StateCompleted, StartedAt: time.Date(2026, 10, 2, 4, 0, 0, 0, time.UTC), PassCount: 12, FailCount: 2,
		Results: []coverage.Result{{Name: "SSH", Status: coverage.StatusFail}, {Name: "DNS over HTTPS (DoH)", Status: coverage.StatusFail}, {Name: "HTTP", Status: coverage.StatusPass}}}
	summary := coverageSummary(coverage.Overview{LastRun: run, Routing: []coverage.Finding{
		{Title: "Device-to-device traffic", Status: coverage.FindingGap}, {Title: "Encrypted DNS", Status: coverage.FindingGap}, {Title: "IPv6", Status: coverage.FindingOK},
	}})
	for _, fragment := range []string{"saw 12 of 14 traffic types", "not seen or not identified: SSH, DNS over HTTPS (DoH)", "2 ways devices can bypass ShakerProxy: Device-to-device traffic; Encrypted DNS"} {
		if !strings.Contains(summary, fragment) {
			t.Fatalf("summary %q lacks %q", summary, fragment)
		}
	}
}
