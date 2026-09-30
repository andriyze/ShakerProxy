package devicereport

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

const maxChangeItems = 200

// Side labels one report in a comparison.
type Side struct {
	SessionID string
	Name      string
}

// Compare describes what changed from base to compare (for example firmware
// 1.2 to 1.3): domains and protocols that appeared or disappeared, findings
// that are new or resolved, and TLS hosts whose interception outcome changed.
func Compare(generatedAt time.Time, base, compare Report, baseSide, compareSide Side) Comparison {
	result := Comparison{
		Schema:      Schema,
		GeneratedAt: generatedAt.UTC(),
		DeviceID:    compare.Device.DeviceID,
		Base:        CompareSide{Start: base.WindowStart, End: base.WindowEnd, SessionID: baseSide.SessionID, Name: baseSide.Name, Totals: base.Totals},
		Compare:     CompareSide{Start: compare.WindowStart, End: compare.WindowEnd, SessionID: compareSide.SessionID, Name: compareSide.Name, Totals: compare.Totals},
		Findings:    FindingChange{New: []Finding{}, Resolved: []Finding{}},
	}
	baseDomains, compareDomains := []string{}, []string{}
	for _, item := range base.Domains {
		baseDomains = append(baseDomains, item.Domain)
	}
	for _, item := range compare.Domains {
		compareDomains = append(compareDomains, item.Domain)
	}
	result.Domains = diff(baseDomains, compareDomains)
	baseProtocols, compareProtocols := []string{}, []string{}
	for _, item := range base.Protocols {
		baseProtocols = append(baseProtocols, item.Protocol)
	}
	for _, item := range compare.Protocols {
		compareProtocols = append(compareProtocols, item.Protocol)
	}
	result.Protocols = diff(baseProtocols, compareProtocols)
	baseFindings := map[string]bool{}
	for _, finding := range base.Findings {
		baseFindings[finding.ID] = true
	}
	compareFindings := map[string]bool{}
	for _, finding := range compare.Findings {
		compareFindings[finding.ID] = true
		if !baseFindings[finding.ID] {
			result.Findings.New = append(result.Findings.New, finding)
		}
	}
	for _, finding := range base.Findings {
		if !compareFindings[finding.ID] {
			result.Findings.Resolved = append(result.Findings.Resolved, finding)
		}
	}
	result.TLS = TLSChange{
		NewlyFailedHosts:      diff(base.TLS.FailedHosts, compare.TLS.FailedHosts).Added,
		NewlyInterceptedHosts: diff(base.TLS.InterceptedHosts, compare.TLS.InterceptedHosts).Added,
	}
	result.Truncated = reportListsTruncated(base) || reportListsTruncated(compare)
	result.Summary = comparisonSummary(result)
	return result
}

func reportListsTruncated(report Report) bool {
	return report.Truncated || len(report.Domains) >= MaxDomains || len(report.TLS.FailedHosts) >= MaxHostList || len(report.TLS.InterceptedHosts) >= MaxHostList
}

// diff returns items present only in next (added) and only in previous
// (removed), sorted and bounded.
func diff(previous, next []string) Change {
	before := map[string]bool{}
	for _, item := range previous {
		before[item] = true
	}
	after := map[string]bool{}
	for _, item := range next {
		after[item] = true
	}
	change := Change{Added: []string{}, Removed: []string{}}
	for item := range after {
		if !before[item] {
			change.Added = append(change.Added, item)
		}
	}
	for item := range before {
		if !after[item] {
			change.Removed = append(change.Removed, item)
		}
	}
	sort.Strings(change.Added)
	sort.Strings(change.Removed)
	if len(change.Added) > maxChangeItems {
		change.Added = change.Added[:maxChangeItems]
	}
	if len(change.Removed) > maxChangeItems {
		change.Removed = change.Removed[:maxChangeItems]
	}
	return change
}

func comparisonSummary(result Comparison) string {
	baseName, compareName := result.Base.Name, result.Compare.Name
	if baseName == "" {
		baseName = "the base run"
	}
	if compareName == "" {
		compareName = "the compared run"
	}
	parts := []string{}
	if len(result.Domains.Added) > 0 || len(result.Domains.Removed) > 0 {
		parts = append(parts, fmt.Sprintf("%s added, %s removed", plural(int64(len(result.Domains.Added)), "domain", "domains"), plural(int64(len(result.Domains.Removed)), "domain", "domains")))
	}
	if len(result.Protocols.Added) > 0 {
		parts = append(parts, "new protocols: "+strings.Join(result.Protocols.Added, ", "))
	}
	if len(result.Protocols.Removed) > 0 {
		parts = append(parts, "protocols no longer used: "+strings.Join(result.Protocols.Removed, ", "))
	}
	for _, finding := range result.Findings.New {
		parts = append(parts, fmt.Sprintf("new finding (%s): %s", finding.Severity, finding.Title))
	}
	for _, finding := range result.Findings.Resolved {
		parts = append(parts, fmt.Sprintf("resolved: %s", finding.Title))
	}
	if len(result.TLS.NewlyFailedHosts) > 0 {
		parts = append(parts, plural(int64(len(result.TLS.NewlyFailedHosts)), "host now fails decryption", "hosts now fail decryption"))
	}
	if len(result.TLS.NewlyInterceptedHosts) > 0 {
		parts = append(parts, plural(int64(len(result.TLS.NewlyInterceptedHosts)), "host is newly decrypted", "hosts are newly decrypted"))
	}
	note := ""
	if result.Truncated {
		note = " Some lists reached their size limit, so a few added or removed items may only reflect ranking; compare shorter runs for an exact diff."
	}
	if len(parts) == 0 {
		return fmt.Sprintf("No differences between %s and %s in domains, protocols, findings, or TLS outcomes.%s", baseName, compareName, note)
	}
	return fmt.Sprintf("Compared with %s, %s: %s.%s", baseName, compareName, strings.Join(parts, "; "), note)
}
