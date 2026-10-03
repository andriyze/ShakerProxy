package notify

import "strings"

// flaggedDomains is a small, offline, conservative list of domain suffixes a
// tester usually wants flagged: advertising and tracking endpoints, and a few
// well-known telemetry hosts. It is intentionally short — a notification is
// meant to be notable, not constant — and bundled, never fetched. Matching is
// by registrable-suffix, case-insensitive.
var flaggedDomains = map[string]string{
	"doubleclick.net":       "advertising",
	"googlesyndication.com": "advertising",
	"googleadservices.com":  "advertising",
	"adnxs.com":             "advertising",
	"scorecardresearch.com": "tracking",
	"criteo.com":            "advertising",
	"taboola.com":           "advertising",
	"outbrain.com":          "advertising",
	"branch.io":             "tracking",
	"adjust.com":            "tracking",
	"appsflyer.com":         "tracking",
	"flurry.com":            "tracking",
	"crashlytics.com":       "telemetry",
	"amplitude.com":         "tracking",
	"mixpanel.com":          "tracking",
	"segment.io":            "tracking",
	"sentry.io":             "telemetry",
	"bugsnag.com":           "telemetry",
}

// FlaggedCategory returns the category a domain is flagged under, or "" when it
// is not flagged. A subdomain of a flagged domain matches.
func FlaggedCategory(domain string) string {
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if host == "" {
		return ""
	}
	for {
		if category, ok := flaggedDomains[host]; ok {
			return category
		}
		dot := strings.IndexByte(host, '.')
		if dot < 0 {
			return ""
		}
		host = host[dot+1:]
	}
}
