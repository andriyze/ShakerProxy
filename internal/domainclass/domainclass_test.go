package domainclass

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func TestCategoriesOrderAndWireValues(t *testing.T) {
	want := []struct {
		category Category
		wire     string
	}{
		{CategoryAnalytics, "analytics"},
		{CategoryAdvertising, "advertising"},
		{CategoryCrashReporting, "crash-reporting"},
		{CategoryTelemetry, "telemetry"},
		{CategoryCloudPlatform, "cloud-platform"},
		{CategoryCDN, "cdn"},
		{CategoryPush, "push"},
		{CategoryOSServices, "os-services"},
		{CategoryStreaming, "streaming"},
		{CategoryIoTCloud, "iot-cloud"},
		{CategoryUnknown, "unknown"},
	}
	got := Categories()
	if len(got) != len(want) {
		t.Fatalf("Categories() has %d entries, want %d: %v", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i] != w.category || string(got[i]) != w.wire {
			t.Errorf("Categories()[%d] = %q, want %q", i, got[i], w.wire)
		}
	}
	got[0] = "mutated"
	if Categories()[0] != CategoryAnalytics {
		t.Fatal("Categories() returned shared storage")
	}
}

func TestClassify(t *testing.T) {
	type want struct {
		domain, registrable, org, suffix string
		category                         Category
	}
	unknownHost := func(domain, registrable string) want {
		return want{domain: domain, registrable: registrable, category: CategoryUnknown}
	}
	cases := []struct {
		name string
		host string
		want want
	}{
		// Exact suffix and subdomains.
		{"exact suffix", "samsungacr.com", want{"samsungacr.com", "samsungacr.com", orgSamsung, "samsungacr.com", CategoryTelemetry}},
		{"subdomain", "log-config.samsungacr.com", want{"log-config.samsungacr.com", "samsungacr.com", orgSamsung, "samsungacr.com", CategoryTelemetry}},
		{"deep subdomain", "a.b.c.samsungacr.com", want{"a.b.c.samsungacr.com", "samsungacr.com", orgSamsung, "samsungacr.com", CategoryTelemetry}},
		{"tuya region", "a1.tuyaus.com", want{"a1.tuyaus.com", "tuyaus.com", "Tuya", "tuyaus.com", CategoryIoTCloud}},
		{"crashlytics", "firebase-settings.crashlytics.com", want{"firebase-settings.crashlytics.com", "crashlytics.com", orgGoogle, "crashlytics.com", CategoryCrashReporting}},
		{"acr on lg", "tkacrstats.alphonso.tv", want{"tkacrstats.alphonso.tv", "alphonso.tv", orgLG, "alphonso.tv", CategoryTelemetry}},

		// Label-boundary negatives.
		{"prefix glued to suffix", "evilsamsungacr.com", unknownHost("evilsamsungacr.com", "evilsamsungacr.com")},
		{"not prefix glued", "notsamsungacr.com", unknownHost("notsamsungacr.com", "notsamsungacr.com")},
		{"suffix as a middle label", "samsungacr.com.evil.example", unknownHost("samsungacr.com.evil.example", "evil.example")},
		{"shorter than suffix", "acr.com", unknownHost("acr.com", "acr.com")},
		{"unlisted domain", "www.example.com", unknownHost("www.example.com", "example.com")},

		// Longest suffix wins.
		{"samsung ads beats samsung", "ads.samsung.com", want{"ads.samsung.com", "samsung.com", orgSamsung, "ads.samsung.com", CategoryAdvertising}},
		{"samsung ads subdomain", "config.ads.samsung.com", want{"config.ads.samsung.com", "samsung.com", orgSamsung, "ads.samsung.com", CategoryAdvertising}},
		{"samsung www", "www.samsung.com", want{"www.samsung.com", "samsung.com", orgSamsung, "samsung.com", CategoryOSServices}},
		{"roku logs", "scribe.logs.roku.com", want{"scribe.logs.roku.com", "roku.com", "Roku", "logs.roku.com", CategoryTelemetry}},
		{"roku ads", "ads.roku.com", want{"ads.roku.com", "roku.com", "Roku", "ads.roku.com", CategoryAdvertising}},
		{"roku other", "api.roku.com", want{"api.roku.com", "roku.com", "Roku", "roku.com", CategoryOSServices}},
		{"google ads", "adservice.google.com", want{"adservice.google.com", "google.com", orgGoogle, "adservice.google.com", CategoryAdvertising}},
		{"google push", "mtalk.google.com", want{"mtalk.google.com", "google.com", orgGoogle, "mtalk.google.com", CategoryPush}},
		{"google analytics", "analytics.google.com", want{"analytics.google.com", "google.com", orgGoogle, "analytics.google.com", CategoryAnalytics}},
		{"google other", "www.google.com", want{"www.google.com", "google.com", orgGoogle, "google.com", CategoryOSServices}},
		{"connectivity check beats cdn", "connectivitycheck.gstatic.com", want{"connectivitycheck.gstatic.com", "gstatic.com", orgGoogle, "connectivitycheck.gstatic.com", CategoryOSServices}},
		{"gstatic cdn", "fonts.gstatic.com", want{"fonts.gstatic.com", "gstatic.com", orgGoogle, "gstatic.com", CategoryCDN}},
		{"doubleclick specific", "googleads.g.doubleclick.net", want{"googleads.g.doubleclick.net", "doubleclick.net", orgGoogle, "googleads.g.doubleclick.net", CategoryAdvertising}},
		{"windows crash beats telemetry", "watson.telemetry.microsoft.com", want{"watson.telemetry.microsoft.com", "microsoft.com", orgMicrosoft, "watson.telemetry.microsoft.com", CategoryCrashReporting}},
		{"windows telemetry", "v10.events.data.microsoft.com", want{"v10.events.data.microsoft.com", "microsoft.com", orgMicrosoft, "events.data.microsoft.com", CategoryTelemetry}},
		{"microsoft other", "www.microsoft.com", want{"www.microsoft.com", "microsoft.com", orgMicrosoft, "microsoft.com", CategoryOSServices}},
		{"fire tv metrics", "device-metrics-us-2.amazon.com", want{"device-metrics-us-2.amazon.com", "amazon.com", orgAmazon, "device-metrics-us-2.amazon.com", CategoryTelemetry}},
		{"aws console", "console.aws.amazon.com", want{"console.aws.amazon.com", "amazon.com", orgAWS, "aws.amazon.com", CategoryCloudPlatform}},
		{"amazon other", "www.amazon.com", want{"www.amazon.com", "amazon.com", orgAmazon, "amazon.com", CategoryOSServices}},
		{"apns", "1-courier.push.apple.com", want{"1-courier.push.apple.com", "apple.com", orgApple, "push.apple.com", CategoryPush}},
		{"apple other", "www.apple.com", want{"www.apple.com", "apple.com", orgApple, "apple.com", CategoryOSServices}},
		{"meta graph", "graph.facebook.com", want{"graph.facebook.com", "facebook.com", orgMeta, "graph.facebook.com", CategoryAdvertising}},
		{"unity ads beats unity", "config.unityads.unity3d.com", want{"config.unityads.unity3d.com", "unity3d.com", "Unity Technologies", "unityads.unity3d.com", CategoryAdvertising}},

		// Normalization.
		{"uppercase and trailing dot", "API.SamsungACR.com.", want{"api.samsungacr.com", "samsungacr.com", orgSamsung, "samsungacr.com", CategoryTelemetry}},
		{"port", "api.samsungacr.com:443", want{"api.samsungacr.com", "samsungacr.com", orgSamsung, "samsungacr.com", CategoryTelemetry}},
		{"trailing dot and port", "api.samsungacr.com.:8443", want{"api.samsungacr.com", "samsungacr.com", orgSamsung, "samsungacr.com", CategoryTelemetry}},
		{"surrounding space", " \tapi.samsungacr.com \n", want{"api.samsungacr.com", "samsungacr.com", orgSamsung, "samsungacr.com", CategoryTelemetry}},
		{"single label", "localhost", unknownHost("localhost", "localhost")},
		{"public suffix only", "co.uk", unknownHost("co.uk", "co.uk")},

		// IP literals are never classified.
		{"ipv4", "192.0.2.10", unknownHost("192.0.2.10", "192.0.2.10")},
		{"ipv4 with port", "192.0.2.10:8080", unknownHost("192.0.2.10", "192.0.2.10")},
		{"ipv6", "2001:DB8::1", unknownHost("2001:db8::1", "2001:db8::1")},
		{"bracketed ipv6", "[2001:db8::1]", unknownHost("2001:db8::1", "2001:db8::1")},
		{"bracketed ipv6 with port", "[2001:DB8:0::1]:443", unknownHost("2001:db8::1", "2001:db8::1")},
		{"ipv4-mapped ipv6", "[::ffff:192.0.2.1]", unknownHost("::ffff:192.0.2.1", "::ffff:192.0.2.1")},

		// Invalid input.
		{"empty", "", unknownHost("", "")},
		{"only spaces", "   ", unknownHost("", "")},
		{"inner space", "samsung acr.com", unknownHost("", "")},
		{"bad character", "samsungacr$.com", unknownHost("", "")},
		{"empty label", "api..samsungacr.com", unknownHost("", "")},
		{"too long", strings.Repeat("a.", 126) + "samsungacr.com", unknownHost("", "")},
		{"label too long", strings.Repeat("a", 64) + ".samsungacr.com", unknownHost("", "")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Classify(tc.host)
			wantResult := Classification{
				Domain:            tc.want.domain,
				RegistrableDomain: tc.want.registrable,
				Organization:      tc.want.org,
				Category:          tc.want.category,
				MatchedSuffix:     tc.want.suffix,
			}
			if got != wantResult {
				t.Fatalf("Classify(%q) = %+v, want %+v", tc.host, got, wantResult)
			}
			if rd := RegistrableDomain(tc.host); rd != got.RegistrableDomain {
				t.Fatalf("RegistrableDomain(%q) = %q, Classify reported %q", tc.host, rd, got.RegistrableDomain)
			}
		})
	}
}

// TestClassifyUnderPrivateSuffixes covers hosts whose registrable domain
// depends on the private section of the public suffix list, so it checks the
// classification and consistency with RegistrableDomain rather than a fixed
// eTLD+1.
func TestClassifyUnderPrivateSuffixes(t *testing.T) {
	cases := []struct {
		host     string
		org      string
		suffix   string
		category Category
	}{
		{"fcm.googleapis.com", orgGoogle, "fcm.googleapis.com", CategoryPush},
		{"android.fcm.googleapis.com", orgGoogle, "fcm.googleapis.com", CategoryPush},
		{"firebaselogging-pa.googleapis.com", orgGoogle, "firebaselogging-pa.googleapis.com", CategoryTelemetry},
		{"crashlyticsreports-pa.googleapis.com", orgGoogle, "crashlyticsreports-pa.googleapis.com", CategoryCrashReporting},
		{"imasdk.googleapis.com", orgGoogle, "imasdk.googleapis.com", CategoryAdvertising},
		{"x.googleapis.com", orgGoogle, "googleapis.com", CategoryCloudPlatform},
		{"storage.googleapis.com", orgGoogle, "googleapis.com", CategoryCloudPlatform},
		{"my-app.appspot.com", orgGoogle, "appspot.com", CategoryCloudPlatform},
		{"d111111abcdef8.cloudfront.net", orgAWS, "cloudfront.net", CategoryCDN},
		{"a1b2c3d4e5f6g7-ats.iot.us-east-1.amazonaws.com", orgAWS, "iot.us-east-1.amazonaws.com", CategoryIoTCloud},
		{"a1b2c3d4e5f6g7.credentials.iot.eu-west-1.amazonaws.com", orgAWS, "iot.eu-west-1.amazonaws.com", CategoryIoTCloud},
		{"a1b2c3d4e5f6g7.ats.iot.cn-north-1.amazonaws.com.cn", orgAWS, "iot.cn-north-1.amazonaws.com.cn", CategoryIoTCloud},
		{"iot.sa-east-1.amazonaws.com", orgAWS, "amazonaws.com", CategoryCloudPlatform},
		{"s3.amazonaws.com", orgAWS, "amazonaws.com", CategoryCloudPlatform},
		{"hub.azure-devices.net", orgMicrosoft, "azure-devices.net", CategoryIoTCloud},
		{"account.blob.core.windows.net", orgMicrosoft, "windows.net", CategoryCloudPlatform},
	}
	for _, tc := range cases {
		got := Classify(tc.host)
		if got.Domain != tc.host || got.Organization != tc.org || got.MatchedSuffix != tc.suffix || got.Category != tc.category {
			t.Errorf("Classify(%q) = %+v, want org %q suffix %q category %q", tc.host, got, tc.org, tc.suffix, tc.category)
		}
		if rd := RegistrableDomain(tc.host); rd == "" || rd != got.RegistrableDomain || !isSuffixOf(rd, tc.host) {
			t.Errorf("RegistrableDomain(%q) = %q, Classify reported %q", tc.host, rd, got.RegistrableDomain)
		}
	}
}

func TestNormalizeHost(t *testing.T) {
	maxName := strings.Join([]string{
		strings.Repeat("a", 63), strings.Repeat("b", 63), strings.Repeat("c", 63), strings.Repeat("d", 61),
	}, ".")
	if len(maxName) != maxHostLen {
		t.Fatalf("test setup: maxName has %d bytes", len(maxName))
	}
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"example.com", "example.com", true},
		{"Example.COM", "example.com", true},
		{"example.com.", "example.com", true},
		{" example.com\t", "example.com", true},
		{"example.com:443", "example.com", true},
		{"example.com.:443", "example.com", true},
		{"example.com:0", "example.com", true},
		{"example.com:65535", "example.com", true},
		{"_dmarc.example-1.com", "_dmarc.example-1.com", true},
		{"xn--bcher-kva.example", "xn--bcher-kva.example", true},
		{"localhost", "localhost", true},
		{"LOCALHOST.", "localhost", true},
		{"192.0.2.1", "192.0.2.1", true},
		{"192.0.2.1.", "192.0.2.1", true},
		{"192.0.2.1:53", "192.0.2.1", true},
		{"::1", "::1", true},
		{"2001:0DB8:0000::0001", "2001:db8::1", true},
		{"[2001:db8::1]", "2001:db8::1", true},
		{"[2001:db8::1]:8443", "2001:db8::1", true},
		{maxName, maxName, true},
		{maxName + ".", maxName, true},
		{strings.ToUpper(maxName) + ".:443", maxName, true},
		{strings.Repeat("a", 63) + ".com", strings.Repeat("a", 63) + ".com", true},

		{"", "", false},
		{"   ", "", false},
		{".", "", false},
		{"..", "", false},
		{"example.com..", "", false},
		{".example.com", "", false},
		{"a..example.com", "", false},
		{"exa mple.com", "", false},
		{"exa$mple.com", "", false},
		{"example.com/path", "", false},
		{"user@example.com", "", false},
		{"bücher.example", "", false},
		{"Kelvin.example", "", false}, // Kelvin sign folds to ASCII "k" under Unicode lowercasing.
		{maxName + "e", "", false},
		{"e." + maxName, "", false},
		{strings.Repeat("a", 64) + ".com", "", false},
		{"example.com:", "", false},
		{"example.com:http", "", false},
		{"example.com:65536", "", false},
		{"example.com:123456", "", false},
		{"example.com:-1", "", false},
		{":443", "", false},
		{"1.2.3", "", false},
		{"192.0.2.999", "", false},
		{"123", "", false},
		{"[example.com]", "", false},
		{"[example.com]:443", "", false},
		{"[192.0.2.1]", "", false},
		{"[2001:db8::1", "", false},
		{"[2001:db8::1]443", "", false},
		{"[2001:db8::1]:", "", false},
		{"[2001:db8::1]:99999", "", false},
		{"fe80::1%eth0", "", false},
		{"[fe80::1%25eth0]:443", "", false},
		{"2001:db8::zz", "", false},
		{strings.Repeat(" ", 10000) + "example.com", "example.com", true},
		{strings.Repeat("a", 10000), "", false},
	}
	for _, tc := range cases {
		got, ok := NormalizeHost(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Errorf("NormalizeHost(%q) = (%q, %v), want (%q, %v)", abbreviate(tc.in), abbreviate(got), ok, abbreviate(tc.want), tc.ok)
		}
	}
}

func TestRegistrableDomain(t *testing.T) {
	cases := map[string]string{
		"api.example.co.uk":      "example.co.uk",
		"example.co.uk":          "example.co.uk",
		"a.b.example.com":        "example.com",
		"Example.COM.":           "example.com",
		"www.example.com:8443":   "example.com",
		"localhost":              "localhost",
		"co.uk":                  "co.uk",
		"com":                    "com",
		"device.lan":             "device.lan",
		"192.0.2.1":              "192.0.2.1",
		"[2001:db8::1]:443":      "2001:db8::1",
		"2001:db8::1":            "2001:db8::1",
		"":                       "",
		"not a host":             "",
		"bad$host.example.com":   "",
		"api.samsungacr.com.:80": "samsungacr.com",
	}
	for in, want := range cases {
		if got := RegistrableDomain(in); got != want {
			t.Errorf("RegistrableDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTableInvariants(t *testing.T) {
	if n := len(table); n < 150 || n > 250 {
		t.Fatalf("table has %d entries, want between 150 and 250", n)
	}
	if err := validateEntries(table); err != nil {
		t.Fatal(err)
	}
	used := map[Category]int{}
	for _, entry := range table {
		used[entry.Category]++
	}
	for _, category := range Categories() {
		if category == CategoryUnknown {
			if used[category] != 0 {
				t.Errorf("%d entries use %q", used[category], category)
			}
			continue
		}
		if used[category] == 0 {
			t.Errorf("no table entry uses category %q", category)
		}
	}
	if maxEntryLabels < 2 || maxEntryLabels > maxLabels {
		t.Fatalf("maxEntryLabels = %d, want within [2, %d]", maxEntryLabels, maxLabels)
	}
}

func TestValidateEntriesRejectsBadRows(t *testing.T) {
	bad := [][]Entry{
		{{"Example.com", "Org", CategoryCDN}},
		{{"example.com.", "Org", CategoryCDN}},
		{{"exa mple.com", "Org", CategoryCDN}},
		{{"192.0.2.1", "Org", CategoryCDN}},
		{{"example", "Org", CategoryCDN}},
		{{"co.uk", "Org", CategoryCDN}},
		{{"example.com", "", CategoryCDN}},
		{{"example.com", " Org", CategoryCDN}},
		{{"example.com", "Org", CategoryUnknown}},
		{{"example.com", "Org", Category("social")}},
		{{"example.com", "Org", CategoryCDN}, {"example.com", "Org", CategoryPush}},
	}
	for _, entries := range bad {
		if err := validateEntries(entries); err == nil {
			t.Errorf("validateEntries(%+v) = nil, want an error", entries)
		}
	}
	if err := validateEntries([]Entry{{"example.com", "Org", CategoryCDN}, {"cdn.example.com", "Org", CategoryCDN}}); err != nil {
		t.Errorf("validateEntries(valid rows) = %v", err)
	}
}

func TestEveryEntryClassifiesToItself(t *testing.T) {
	for _, entry := range Entries() {
		for _, host := range []string{entry.Suffix, "zz-probe." + entry.Suffix, strings.ToUpper(entry.Suffix) + ".:443"} {
			got := Classify(host)
			if got.MatchedSuffix != entry.Suffix || got.Organization != entry.Organization || got.Category != entry.Category {
				t.Errorf("Classify(%q) = %+v, want entry %+v", host, got, entry)
			}
		}
		if got := Classify("zz-probe" + entry.Suffix); got.MatchedSuffix == entry.Suffix {
			t.Errorf("Classify(%q) matched %q across a label boundary", "zz-probe"+entry.Suffix, entry.Suffix)
		}
	}
}

func TestEntriesReturnsSortedCopy(t *testing.T) {
	entries := Entries()
	if len(entries) != len(table) {
		t.Fatalf("Entries() has %d rows, table has %d", len(entries), len(table))
	}
	if !slices.IsSortedFunc(entries, func(a, b Entry) int { return strings.Compare(a.Suffix, b.Suffix) }) {
		t.Fatal("Entries() is not sorted by suffix")
	}
	first := entries[0]
	entries[0] = Entry{Suffix: "mutated.example", Organization: "x", Category: CategoryCDN}
	if again := Entries(); again[0] != first {
		t.Fatal("Entries() returned shared storage")
	}
	if got := Classify(first.Suffix); got.MatchedSuffix != first.Suffix {
		t.Fatalf("mutating Entries() changed classification: %+v", got)
	}
}

func TestClassifyBoundedOnMaximalHosts(t *testing.T) {
	// 127 one-byte labels: the most labels a valid host can have.
	widest := strings.TrimSuffix(strings.Repeat("a.", maxLabels), ".")
	if len(widest) != maxHostLen || strings.Count(widest, ".")+1 != maxLabels {
		t.Fatalf("test setup: widest has %d bytes", len(widest))
	}
	if got := Classify(widest); got.Domain != widest || got.Category != CategoryUnknown {
		t.Fatalf("Classify(127 labels) = %+v", got)
	}
	// 119 prefix labels in front of a table suffix still match.
	deep := strings.Repeat("a.", 119) + "samsungacr.com"
	if got := Classify(deep); got.MatchedSuffix != "samsungacr.com" {
		t.Fatalf("Classify(deep) = %+v", got)
	}
	// One byte over the limit is rejected before any lookup.
	if got := Classify("a" + widest); got.Domain != "" || got.Category != CategoryUnknown {
		t.Fatalf("Classify(254 bytes) = %+v", got)
	}
	allocs := testing.AllocsPerRun(100, func() { lookup(widest) })
	if allocs != 0 {
		t.Fatalf("lookup allocated %.0f times per call", allocs)
	}
}

func TestClassificationJSON(t *testing.T) {
	matched, err := json.Marshal(Classify("logs.roku.com"))
	if err != nil {
		t.Fatal(err)
	}
	const wantMatched = `{"domain":"logs.roku.com","registrable_domain":"roku.com","organization":"Roku","category":"telemetry","matched_suffix":"logs.roku.com"}`
	if string(matched) != wantMatched {
		t.Fatalf("json = %s, want %s", matched, wantMatched)
	}
	unknown, err := json.Marshal(Classify("192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	const wantUnknown = `{"domain":"192.0.2.1","registrable_domain":"192.0.2.1","organization":"","category":"unknown"}`
	if string(unknown) != wantUnknown {
		t.Fatalf("json = %s, want %s", unknown, wantUnknown)
	}
}

func FuzzClassify(f *testing.F) {
	for _, seed := range []string{
		"", "samsungacr.com", "API.SamsungACR.com.:443", "evilsamsungacr.com", "[2001:db8::1]:443",
		"192.0.2.1", "fe80::1%eth0", "a..b", "localhost", "Kelvin.example", "x.iot.cn-north-1.amazonaws.com.cn",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		got := Classify(input)
		normalized, ok := NormalizeHost(input)
		if got.Domain != normalized || ok != (normalized != "") {
			t.Fatalf("Classify(%q).Domain = %q, NormalizeHost = (%q, %v)", input, got.Domain, normalized, ok)
		}
		if got.RegistrableDomain != RegistrableDomain(input) {
			t.Fatalf("Classify(%q).RegistrableDomain = %q, RegistrableDomain = %q", input, got.RegistrableDomain, RegistrableDomain(input))
		}
		if !knownCategory(got.Category) {
			t.Fatalf("Classify(%q) category %q is not known", input, got.Category)
		}
		if got.Category == CategoryUnknown && (got.Organization != "" || got.MatchedSuffix != "") {
			t.Fatalf("Classify(%q) = %+v: unknown category with a match", input, got)
		}
		if got.MatchedSuffix != "" && !isSuffixOf(got.MatchedSuffix, got.Domain) {
			t.Fatalf("Classify(%q) matched %q, not a label suffix of %q", input, got.MatchedSuffix, got.Domain)
		}
		if !ok {
			return
		}
		if len(normalized) > maxHostLen {
			t.Fatalf("NormalizeHost(%q) returned %d bytes", input, len(normalized))
		}
		again, ok := NormalizeHost(normalized)
		if !ok || again != normalized {
			t.Fatalf("NormalizeHost is not idempotent: %q -> %q -> (%q, %v)", input, normalized, again, ok)
		}
		if got.RegistrableDomain == "" || !isSuffixOf(got.RegistrableDomain, normalized) {
			t.Fatalf("RegistrableDomain(%q) = %q is not a label suffix of %q", input, got.RegistrableDomain, normalized)
		}
	})
}

// isSuffixOf reports whether suffix equals host or is a suffix of host on a
// label boundary.
func isSuffixOf(suffix, host string) bool {
	return host == suffix || strings.HasSuffix(host, "."+suffix)
}

func abbreviate(s string) string {
	if len(s) <= 80 {
		return s
	}
	return s[:40] + "..." + s[len(s)-20:]
}
