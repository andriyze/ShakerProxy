// Package domainclass labels host names with the organization that operates
// them and a coarse category describing what a device is doing when it talks
// to them (analytics, advertising, telemetry, push, ...). Device security
// reports use it to explain where a TV, phone, camera or IoT device sends
// traffic.
//
// The suffix table in table.go is first-party: it is curated by hand for
// ShakerProxy from publicly known facts about which company operates which
// domain. It is not derived from, and must not be extended by copying from,
// any third-party blocklist, tracker list or filter list.
//
// For hosting and CDN suffixes (for example appspot.com or cloudfront.net)
// the organization is the platform operator, not the tenant whose content is
// served. Subsidiaries of the large platform companies are attributed to the
// parent (Nest and Crashlytics to Google, Ring and Twitch to Amazon).
//
// Classification is a longest-suffix match on label boundaries with a hard
// bound on work: a valid host has at most 253 bytes and 127 labels, and the
// lookup walks those labels doing map lookups only. It uses no regular
// expressions and never scans the table.
package domainclass

import (
	"cmp"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Category groups destinations by what a device uses them for.
type Category string

const (
	CategoryAnalytics      Category = "analytics"
	CategoryAdvertising    Category = "advertising"
	CategoryCrashReporting Category = "crash-reporting"
	CategoryTelemetry      Category = "telemetry"
	CategoryCloudPlatform  Category = "cloud-platform"
	CategoryCDN            Category = "cdn"
	CategoryPush           Category = "push"
	CategoryOSServices     Category = "os-services"
	CategoryStreaming      Category = "streaming"
	CategoryIoTCloud       Category = "iot-cloud"
	CategoryUnknown        Category = "unknown"
)

var categoryOrder = [...]Category{
	CategoryAnalytics, CategoryAdvertising, CategoryCrashReporting, CategoryTelemetry,
	CategoryCloudPlatform, CategoryCDN, CategoryPush, CategoryOSServices,
	CategoryStreaming, CategoryIoTCloud, CategoryUnknown,
}

// Categories returns every category in display order, ending with
// CategoryUnknown. The caller owns the returned slice.
func Categories() []Category {
	return slices.Clone(categoryOrder[:])
}

func knownCategory(c Category) bool {
	return slices.Contains(categoryOrder[:], c)
}

// Classification describes one host name.
type Classification struct {
	// Domain is the normalized host: lowercase, no trailing dot, no port.
	// It is empty when the input was not a valid host.
	Domain string `json:"domain"`
	// RegistrableDomain is the eTLD+1 of Domain, the address itself for IP
	// literals, and Domain itself when no eTLD+1 exists (e.g. "localhost").
	RegistrableDomain string `json:"registrable_domain"`
	// Organization operates the matched suffix; "" when unknown.
	Organization string `json:"organization"`
	// Category is CategoryUnknown when no table suffix matched.
	Category Category `json:"category"`
	// MatchedSuffix is the table suffix that produced the match, if any.
	MatchedSuffix string `json:"matched_suffix,omitempty"`
}

// Entry is one row of the curated suffix table.
type Entry struct {
	Suffix       string   `json:"suffix"`
	Organization string   `json:"organization"`
	Category     Category `json:"category"`
}

const (
	maxHostLen  = 253
	maxLabelLen = 63
	// maxLabels is the most labels a valid host can have: 127 one-byte
	// labels and 126 dots fill exactly maxHostLen bytes.
	maxLabels = (maxHostLen + 1) / 2
	// maxRawHostLen bounds the input before the port and trailing dot are
	// removed: a maximal host, one trailing dot and ":65535". Bracketed IPv6
	// literals are far shorter.
	maxRawHostLen = maxHostLen + len(".") + len(":65535")
)

// NormalizeHost lowercases host, trims surrounding white space and one
// trailing dot, strips a ":port" suffix and the brackets around an IPv6
// literal, and validates the result. A valid result is either an IP literal
// in canonical form (IPv6 zones are rejected) or a name of at most 253 bytes
// whose labels are 1 to 63 bytes of [a-z0-9_-]. A name whose final label is
// all digits is rejected, because no top-level domain is numeric and such
// strings are almost always malformed IPv4 literals. ok is false on invalid
// input.
func NormalizeHost(host string) (string, bool) {
	normalized, _, ok := normalize(host)
	return normalized, ok
}

// RegistrableDomain returns the eTLD+1 of host according to the public suffix
// list, the canonical address for IP literals, and the normalized host itself
// when no eTLD+1 exists (for example "localhost" or a bare public suffix such
// as "co.uk"). It returns "" for invalid input.
func RegistrableDomain(host string) string {
	normalized, isIP, ok := normalize(host)
	if !ok {
		return ""
	}
	return registrable(normalized, isIP)
}

// Classify normalizes host and labels it with the longest table suffix that
// matches on a label boundary: "api.samsungacr.com" matches "samsungacr.com"
// but "notsamsungacr.com" does not. IP literals and invalid input are
// CategoryUnknown with no organization; invalid input also has an empty
// Domain.
func Classify(host string) Classification {
	normalized, isIP, ok := normalize(host)
	if !ok {
		return Classification{Category: CategoryUnknown}
	}
	result := Classification{
		Domain:            normalized,
		RegistrableDomain: registrable(normalized, isIP),
		Category:          CategoryUnknown,
	}
	if isIP {
		return result
	}
	if entry, found := lookup(normalized); found {
		result.Organization = entry.Organization
		result.Category = entry.Category
		result.MatchedSuffix = entry.Suffix
	}
	return result
}

// Entries returns a copy of the suffix table sorted by suffix.
func Entries() []Entry {
	return slices.Clone(sortedEntries)
}

var index, sortedEntries, maxEntryLabels = mustBuildIndex(table)

// lookup finds the longest table suffix of the normalized, non-IP host. It
// walks at most the host's labels (never more than maxLabels) and performs
// at most maxEntryLabels map lookups, one per candidate suffix, starting with
// the longest candidate that could be in the table.
func lookup(host string) (Entry, bool) {
	labels := strings.Count(host, ".") + 1
	suffix := host
	for i := 0; i < labels && i < maxLabels; i++ {
		if labels-i <= maxEntryLabels {
			if entry, found := index[suffix]; found {
				return entry, true
			}
		}
		dot := strings.IndexByte(suffix, '.')
		if dot < 0 {
			break
		}
		suffix = suffix[dot+1:]
	}
	return Entry{}, false
}

func registrable(host string, isIP bool) string {
	if isIP {
		return host
	}
	if domain, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		return domain
	}
	return host
}

// normalize implements NormalizeHost and also reports whether the result is
// an IP literal.
func normalize(raw string) (host string, isIP bool, ok bool) {
	s := strings.TrimSpace(raw)
	if s == "" || len(s) > maxRawHostLen {
		return "", false, false
	}
	if s[0] == '[' {
		end := strings.IndexByte(s, ']')
		if end < 0 {
			return "", false, false
		}
		if rest := s[end+1:]; rest != "" && (rest[0] != ':' || !validPort(rest[1:])) {
			return "", false, false
		}
		addr, err := netip.ParseAddr(s[1:end])
		if err != nil || !addr.Is6() || addr.Zone() != "" {
			return "", false, false
		}
		return addr.String(), true, true
	}
	// Exactly one colon separates a host from its port. More than one colon
	// can only be a bare IPv6 literal, which cannot carry a port.
	if colon := strings.IndexByte(s, ':'); colon >= 0 && strings.IndexByte(s[colon+1:], ':') < 0 {
		if !validPort(s[colon+1:]) {
			return "", false, false
		}
		s = s[:colon]
	}
	s = strings.TrimSuffix(s, ".")
	if addr, err := netip.ParseAddr(s); err == nil {
		if addr.Zone() != "" {
			return "", false, false
		}
		return addr.String(), true, true
	}
	name, ok := normalizeName(s)
	return name, false, ok
}

// normalizeName validates a DNS name and lowercases ASCII letters. Non-ASCII
// input is rejected before any case folding, so Unicode characters that fold
// to ASCII (such as the Kelvin sign) cannot slip through.
func normalizeName(s string) (string, bool) {
	if s == "" || len(s) > maxHostLen {
		return "", false
	}
	var lowered []byte
	labelLen, digitsOnly := 0, true
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '.':
			if labelLen == 0 {
				return "", false
			}
			labelLen, digitsOnly = 0, true
			continue
		case '0' <= c && c <= '9':
		case 'a' <= c && c <= 'z', c == '-', c == '_':
			digitsOnly = false
		case 'A' <= c && c <= 'Z':
			digitsOnly = false
			if lowered == nil {
				lowered = []byte(s)
			}
			lowered[i] = c + ('a' - 'A')
		default:
			return "", false
		}
		labelLen++
		if labelLen > maxLabelLen {
			return "", false
		}
	}
	if labelLen == 0 || digitsOnly {
		return "", false
	}
	if lowered != nil {
		return string(lowered), true
	}
	return s, true
}

func validPort(port string) bool {
	if port == "" || len(port) > len("65535") {
		return false
	}
	value := 0
	for i := 0; i < len(port); i++ {
		c := port[i]
		if c < '0' || c > '9' {
			return false
		}
		value = value*10 + int(c-'0')
	}
	return value <= 65535
}

// validateEntries checks the table invariants that lookup relies on: every
// suffix is a normalized, non-IP name with at least two labels that is not
// itself an ICANN public suffix, suffixes are unique, and every entry names
// an organization and a known category other than CategoryUnknown.
func validateEntries(entries []Entry) error {
	seen := make(map[string]struct{}, len(entries))
	var errs []error
	for _, entry := range entries {
		normalized, isIP, ok := normalize(entry.Suffix)
		switch {
		case !ok || isIP || normalized != entry.Suffix:
			errs = append(errs, fmt.Errorf("suffix %q is not a normalized host name", entry.Suffix))
		case !strings.Contains(entry.Suffix, "."):
			errs = append(errs, fmt.Errorf("suffix %q has a single label", entry.Suffix))
		default:
			if ps, icann := publicsuffix.PublicSuffix(entry.Suffix); icann && ps == entry.Suffix {
				errs = append(errs, fmt.Errorf("suffix %q is an ICANN public suffix", entry.Suffix))
			}
		}
		if _, dup := seen[entry.Suffix]; dup {
			errs = append(errs, fmt.Errorf("suffix %q is listed twice", entry.Suffix))
		}
		seen[entry.Suffix] = struct{}{}
		if entry.Organization == "" || strings.TrimSpace(entry.Organization) != entry.Organization {
			errs = append(errs, fmt.Errorf("suffix %q has a missing or untrimmed organization %q", entry.Suffix, entry.Organization))
		}
		if !knownCategory(entry.Category) || entry.Category == CategoryUnknown {
			errs = append(errs, fmt.Errorf("suffix %q has invalid category %q", entry.Suffix, entry.Category))
		}
	}
	return errors.Join(errs...)
}

// mustBuildIndex validates the static table and builds the lookup index. The
// table is compiled in, so a violation is a programming error caught by the
// package tests; panicking keeps a broken table from ever classifying hosts.
func mustBuildIndex(entries []Entry) (map[string]Entry, []Entry, int) {
	if err := validateEntries(entries); err != nil {
		panic("domainclass: invalid suffix table: " + err.Error())
	}
	byName := make(map[string]Entry, len(entries))
	deepest := 0
	for _, entry := range entries {
		byName[entry.Suffix] = entry
		deepest = max(deepest, strings.Count(entry.Suffix, ".")+1)
	}
	sorted := slices.Clone(entries)
	slices.SortFunc(sorted, func(a, b Entry) int { return cmp.Compare(a.Suffix, b.Suffix) })
	return byName, sorted, deepest
}
