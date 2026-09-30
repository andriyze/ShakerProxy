package main

import (
	_ "embed"
	"html/template"
	"io"
	"strings"
	"time"
)

//go:embed report.html.tmpl
var reportTemplateSource string

var reportTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	"bytes":    humanBytes,
	"count":    humanCount,
	"when":     reportTime,
	"catrust":  caTrustText,
	"join":     func(values []string) string { return joinLimited(values, 0) },
	"lower":    strings.ToLower,
	"upper":    strings.ToUpper,
	"clean":    sanitize,
	"severity": severityClass,
}).Parse(reportTemplateSource))

// severityClass maps a severity to one of the stylesheet's classes.
func severityClass(value string) string {
	switch severity := strings.ToLower(strings.TrimSpace(value)); severity {
	case "critical", "high", "medium", "low":
		return severity
	default:
		return "info"
	}
}

type reportPage struct {
	Report      deviceReport
	Title       string
	DeviceName  string
	Findings    []finding
	Severities  []severityCount
	GeneratedAt string
	CLIVersion  string
}

type severityCount struct {
	Severity string
	Count    int
}

func reportTime(value string) string {
	parsed, ok := parseTime(value)
	if !ok {
		return orDash(value)
	}
	return parsed.UTC().Format("2006-01-02 15:04 UTC")
}

// renderReportHTML writes a self-contained, printable HTML page. All values
// go through html/template escaping; the page loads nothing external.
func renderReportHTML(w io.Writer, report deviceReport, now time.Time) error {
	name := sanitize(orText(report.Device.FriendlyName, report.Device.DeviceID))
	findings := sortedFindings(report.Findings)
	counts := map[string]int{}
	for _, item := range findings {
		counts[strings.ToUpper(item.Severity)]++
	}
	var severities []severityCount
	for _, severity := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} {
		if counts[severity] > 0 {
			severities = append(severities, severityCount{Severity: severity, Count: counts[severity]})
		}
	}
	page := reportPage{
		Report:      report,
		Title:       "ShakerProxy report: " + name,
		DeviceName:  name,
		Findings:    findings,
		Severities:  severities,
		GeneratedAt: now.UTC().Format("2006-01-02 15:04 UTC"),
		CLIVersion:  version,
	}
	return reportTemplate.Execute(w, page)
}
