package ingest

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Devices check for internet access the moment they join a network, and each
// operating system asks its own vendor's server. Those lookups and server
// names say what a device is even when it has no hostname and a private MAC.

const (
	DevicePlatformHintsSchema = 1
	// DevicePlatformWindow is how far back the connectivity checks are read.
	DevicePlatformWindow = 7 * 24 * time.Hour
	// MaxDevicePlatformHints bounds the response; inventory holds at most
	// 50,000 devices, and lab appliances see far fewer.
	MaxDevicePlatformHints        = 10000
	maxDevicePlatformObservations = 4 * MaxDevicePlatformHints
)

type platformCheck struct {
	platform string
	// rank orders hints by how specific they are: a GrapheneOS phone also
	// makes Google's checks, so GrapheneOS outranks Android.
	rank int
}

// platformChecks lists host names that only an operating system's own
// connectivity, captive-portal or system service uses, never a website a
// person browses to on another device.
var platformChecks = map[string]platformCheck{
	"connectivitycheck.grapheneos.network":   {"GrapheneOS phone", 3},
	"connectivitycheck.grapheneos.org":       {"GrapheneOS phone", 3},
	"supl.grapheneos.org":                    {"GrapheneOS phone", 3},
	"time.grapheneos.org":                    {"GrapheneOS phone", 3},
	"ctest.cdn.nintendo.net":                 {"Nintendo Switch", 3},
	"spectrum.s3.amazonaws.com":              {"Amazon Kindle", 3},
	"connect.rom.miui.com":                   {"Xiaomi phone", 2},
	"connectivitycheck.platform.hicloud.com": {"Huawei device", 2},
	"captive.apple.com":                      {"Apple device", 2},
	"www.msftconnecttest.com":                {"Windows PC", 2},
	"ipv6.msftconnecttest.com":               {"Windows PC", 2},
	"www.msftncsi.com":                       {"Windows PC", 2},
	"dns.msftncsi.com":                       {"Windows PC", 2},
	"connectivity-check.ubuntu.com":          {"Linux computer", 2},
	"nmcheck.gnome.org":                      {"Linux computer", 2},
	"network-test.debian.org":                {"Linux computer", 2},
	"conncheck.opensuse.org":                 {"Linux computer", 2},
	"connectivitycheck.gstatic.com":          {"Android device", 1},
	"connectivitycheck.android.com":          {"Android device", 1},
	"clients3.google.com":                    {"Android device", 1},
	"play.googleapis.com":                    {"Android device", 1},
}

// DHCPPlatform says what a device is from its DHCP request when only one
// platform's DHCP client asks that way: the vendor class it sends (option
// 60) or, for Apple devices, which send none, the order of the options they
// ask for (option 55). Evidence is the value that matched, for the UI's
// "Identified from its DHCP request: ...". Rank orders the hint against the
// connectivity checks, which win a tie: they are more specific.
func DHCPPlatform(vendorClass, parameterList string) (platform, evidence string, rank int, ok bool) {
	lower := strings.ToLower(vendorClass)
	switch {
	case strings.HasPrefix(lower, "android-dhcp-"):
		return "Android device", vendorClass, 1, true
	case strings.HasPrefix(vendorClass, "MSFT "):
		return "Windows PC", vendorClass, 2, true
	case strings.HasPrefix(lower, "dhcpcd-"):
		// dhcpcd is Linux's (Raspberry Pi OS, Arch) and older Android's.
		return "Linux or Android device", vendorClass, 0, true
	case strings.HasPrefix(lower, "udhcp "):
		// BusyBox's client: routers, cameras, plugs and other embedded Linux.
		return "Embedded Linux device", vendorClass, 0, true
	case vendorClass == "" && appleParameterList(parameterList):
		return "Apple device", "options " + parameterList, 1, true
	}
	return "", "", 0, false
}

// appleParameterList matches the option order of Apple's DHCP client on
// iOS, iPadOS and macOS: subnet mask, then classless routes (121) before
// the router, and auto-configuration (116 or 252, with 119) among the rest.
func appleParameterList(list string) bool {
	if !strings.HasPrefix(list, "1,121,3,6,15,") {
		return false
	}
	options := map[string]bool{}
	for _, option := range strings.Split(list, ",") {
		options[option] = true
	}
	return options["119"] && options["252"]
}

// DevicePlatformHint says what a device most likely is and which check
// showed it.
type DevicePlatformHint struct {
	DeviceID string    `json:"device_id"`
	Platform string    `json:"platform"`
	Domain   string    `json:"domain"`
	LastSeen time.Time `json:"last_seen"`
}

type DevicePlatformHints struct {
	Schema      int                  `json:"schema"`
	GeneratedAt time.Time            `json:"generated_at"`
	Hints       []DevicePlatformHint `json:"hints"`
}

type DevicePlatformHintReader interface {
	QueryDevicePlatformHints(context.Context) (DevicePlatformHints, error)
}

// platformCheckDomains returns the catalog's host names in a stable order.
func platformCheckDomains() []string {
	domains := make([]string, 0, len(platformChecks))
	for domain := range platformChecks {
		domains = append(domains, domain)
	}
	sort.Strings(domains)
	return domains
}

// DevicePlatformRank is how specific a connectivity-check hint is, on the
// scale DHCPPlatform's rank uses.
func DevicePlatformRank(hint DevicePlatformHint) int {
	return platformChecks[hint.Domain].rank
}

// PreferDevicePlatformHint reports whether candidate is a better hint than
// current: more specific first, then more recent.
func PreferDevicePlatformHint(candidate, current DevicePlatformHint) bool {
	candidateRank, currentRank := platformChecks[candidate.Domain].rank, platformChecks[current.Domain].rank
	if candidateRank != currentRank {
		return candidateRank > currentRank
	}
	if !candidate.LastSeen.Equal(current.LastSeen) {
		return candidate.LastSeen.After(current.LastSeen)
	}
	return candidate.Domain < current.Domain
}

type devicePlatformObservation struct {
	deviceID, domain string
	lastSeen         time.Time
}

// resolveDevicePlatformHints keeps the best hint per device.
func resolveDevicePlatformHints(observations []devicePlatformObservation) []DevicePlatformHint {
	best := map[string]DevicePlatformHint{}
	for _, observation := range observations {
		check, ok := platformChecks[observation.domain]
		if !ok || !deviceIDPattern.MatchString(observation.deviceID) {
			continue
		}
		hint := DevicePlatformHint{DeviceID: observation.deviceID, Platform: check.platform, Domain: observation.domain, LastSeen: observation.lastSeen.UTC()}
		if current, seen := best[hint.DeviceID]; !seen || PreferDevicePlatformHint(hint, current) {
			best[hint.DeviceID] = hint
		}
	}
	hints := make([]DevicePlatformHint, 0, len(best))
	for _, hint := range best {
		hints = append(hints, hint)
	}
	sort.Slice(hints, func(i, j int) bool { return hints[i].DeviceID < hints[j].DeviceID })
	if len(hints) > MaxDevicePlatformHints {
		hints = hints[:MaxDevicePlatformHints]
	}
	return hints
}

func (h DevicePlatformHints) Validate() error {
	if h.Schema != DevicePlatformHintsSchema || h.GeneratedAt.IsZero() || len(h.Hints) > MaxDevicePlatformHints {
		return errors.New("device platform hints are invalid")
	}
	seen := map[string]bool{}
	for _, hint := range h.Hints {
		check, ok := platformChecks[hint.Domain]
		if !ok || check.platform != hint.Platform || !deviceIDPattern.MatchString(hint.DeviceID) || seen[hint.DeviceID] || hint.LastSeen.IsZero() {
			return errors.New("device platform hint is invalid")
		}
		seen[hint.DeviceID] = true
	}
	return nil
}

// The dns_query and tls_server_name indexes serve both halves; zeek.conn rows
// carry the HTTP Host or TLS/QUIC server name in tls_server_name.
const devicePlatformStatement = `SELECT device_id, name, max(occurred_at) FROM (
  SELECT device_id, dns_query AS name, occurred_at FROM normalized_events
  WHERE dns_query = ANY($1::text[]) AND occurred_at >= $2 AND device_id IS NOT NULL
  UNION ALL
  SELECT device_id, tls_server_name AS name, occurred_at FROM normalized_events
  WHERE tls_server_name = ANY($1::text[]) AND occurred_at >= $2 AND device_id IS NOT NULL
) matches
GROUP BY device_id, name
LIMIT $3`

// QueryDevicePlatformHints reads the connectivity checks of the last week
// and keeps the most specific platform per device.
func (s PostgresSink) QueryDevicePlatformHints(ctx context.Context) (DevicePlatformHints, error) {
	if s.DB == nil {
		return DevicePlatformHints{}, errors.New("PostgreSQL connection is required")
	}
	var generatedAt time.Time
	if err := s.DB.QueryRowContext(ctx, "SELECT clock_timestamp()").Scan(&generatedAt); err != nil {
		return DevicePlatformHints{}, fmt.Errorf("read device platform boundary: %w", err)
	}
	generatedAt = generatedAt.UTC()
	rows, err := s.DB.QueryContext(ctx, devicePlatformStatement, platformCheckDomains(), generatedAt.Add(-DevicePlatformWindow), maxDevicePlatformObservations)
	if err != nil {
		return DevicePlatformHints{}, fmt.Errorf("query device platform hints: %w", err)
	}
	defer rows.Close()
	var observations []devicePlatformObservation
	for rows.Next() {
		var observation devicePlatformObservation
		var lastSeen sql.NullTime
		if err := rows.Scan(&observation.deviceID, &observation.domain, &lastSeen); err != nil {
			return DevicePlatformHints{}, fmt.Errorf("decode device platform hint: %w", err)
		}
		observation.lastSeen = lastSeen.Time
		observations = append(observations, observation)
	}
	if err := rows.Err(); err != nil {
		return DevicePlatformHints{}, fmt.Errorf("read device platform hints: %w", err)
	}
	hints := DevicePlatformHints{Schema: DevicePlatformHintsSchema, GeneratedAt: generatedAt, Hints: resolveDevicePlatformHints(observations)}
	if err := hints.Validate(); err != nil {
		return DevicePlatformHints{}, err
	}
	return hints, nil
}
