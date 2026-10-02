package ingest

import (
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/querylang"
)

func TestDestinationOwnerComesFromTheBestName(t *testing.T) {
	for _, test := range []struct {
		event         RecentEvent
		owner, catego string
	}{
		{RecentEvent{TLSServerName: "googleads.g.doubleclick.net"}, "Google", "advertising"},
		{RecentEvent{HTTPHost: "maps.googleapis.com:80"}, "Google", "cloud-platform"},
		{RecentEvent{DNSQuery: "www.google.com"}, "Google", "os-services"},
		{RecentEvent{DNSName: "maps.googleapis.com"}, "Google", "cloud-platform"},
		// The server name wins over the looked-up name.
		{RecentEvent{TLSServerName: "maps.googleapis.com", DNSName: "googleads.g.doubleclick.net"}, "Google", "cloud-platform"},
		{RecentEvent{TLSServerName: "unknown-vendor.example"}, "", ""},
		{RecentEvent{DestinationIP: "142.250.1.1"}, "", ""},
	} {
		owner, category := destinationOwner(test.event)
		if owner != test.owner || category != test.catego {
			t.Fatalf("%+v → %q/%q, want %q/%q", test.event, owner, category, test.owner, test.catego)
		}
	}
}

func TestByteCountsAndOwnerAreValidated(t *testing.T) {
	negative, huge, fine := int64(-1), maxEventByteCount+1, int64(42)
	if validEventByteCounts(RecentEvent{BytesSent: &negative}) || validEventByteCounts(RecentEvent{BytesReceived: &huge}) || !validEventByteCounts(RecentEvent{BytesSent: &fine}) {
		t.Fatal("byte count validation is wrong")
	}
	for _, event := range []RecentEvent{
		{DestinationCategory: "advertising"},
		{DestinationOrganization: "Google", DestinationCategory: "unknown"},
		{DestinationOrganization: "Google", DestinationCategory: "made-up"},
		{DestinationOrganization: "Goo\ngle", DestinationCategory: "advertising"},
		{DestinationOrganization: strings.Repeat("x", 129), DestinationCategory: "advertising"},
	} {
		if validEventDestinationOwner(event) {
			t.Fatalf("invalid owner accepted: %+v", event)
		}
	}
	if !validEventDestinationOwner(RecentEvent{DestinationOrganization: "Google", DestinationCategory: "advertising"}) || !validEventDestinationOwner(RecentEvent{}) {
		t.Fatal("valid owner rejected")
	}
}

func TestOwnerAndCategoryFiltersCompileToSuffixMatches(t *testing.T) {
	for input, wantSuffix := range map[string]string{
		"owner:google":         "doubleclick.net",
		"category:advertising": "doubleclick.net",
		"owner:*":              "googleapis.com",
	} {
		filter, err := querylang.Parse(input)
		if err != nil {
			t.Fatalf("%s: %v", input, err)
		}
		var args []any
		clause, err := compileEventFilter(filter.Root, nil, nil, time.Time{}, false, &args)
		if err != nil {
			t.Fatalf("%s: %v", input, err)
		}
		if !strings.Contains(clause, "= ANY(") || !strings.Contains(clause, "LIKE ANY(") || len(args) != 2 {
			t.Fatalf("%s compiled to %s with %d args", input, clause, len(args))
		}
		suffixes := args[0].([]string)
		found := false
		for _, suffix := range suffixes {
			found = found || suffix == wantSuffix
		}
		if !found {
			t.Fatalf("%s does not select %s: %v", input, wantSuffix, suffixes)
		}
	}
	filter, err := querylang.Parse("owner!=nobody-at-all")
	if err != nil {
		t.Fatal(err)
	}
	var args []any
	clause, err := compileEventFilter(filter.Root, nil, nil, time.Time{}, false, &args)
	if err != nil || clause != "NOT FALSE" || len(args) != 0 {
		t.Fatalf("an owner nobody matches compiled to %q args=%v err=%v", clause, args, err)
	}
	for _, input := range []string{"owner:goo*", "owner:>google", "category:unknown", "category:shopping"} {
		if _, err := querylang.Parse(input); err == nil {
			t.Fatalf("%s was accepted", input)
		}
	}
}
