package ingest

import (
	"errors"
	"net/netip"
	"slices"
	"sort"
	"strings"

	"golang.org/x/net/publicsuffix"

	"shakerproxy.dev/shakerproxy/internal/domainclass"
)

// facetDomain is the name a host is grouped under in the Domains facet: its
// registrable domain under the ICANN section of the public suffix list. The
// private section is ignored, so hosts under provider suffixes such as
// googleapis.com or cloudfront.net group under that provider instead of
// each standing alone. It returns "" for an invalid host or an IP literal.
func facetDomain(host string) string {
	name, ok := domainclass.NormalizeHost(host)
	if !ok {
		return ""
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return ""
	}
	suffix, icann := publicsuffix.PublicSuffix(name)
	for !icann {
		_, parent, found := strings.Cut(suffix, ".")
		if !found {
			break
		}
		suffix, icann = publicsuffix.PublicSuffix(parent)
	}
	if name == suffix {
		return name
	}
	labels := strings.TrimSuffix(name, "."+suffix)
	if dot := strings.LastIndexByte(labels, '.'); dot >= 0 {
		labels = labels[dot+1:]
	}
	return labels + "." + suffix
}

// groupEventDomains folds host counts (largest first) into registrable
// domains and keeps the largest MaxEventDomainValues.
func groupEventDomains(hosts []EventFacetValue, total int64) EventDomainFacet {
	groups := map[string]*EventDomainValue{}
	for _, host := range hosts {
		domain := facetDomain(host.Value)
		if domain == "" || host.Count < 1 {
			continue
		}
		name, _ := domainclass.NormalizeHost(host.Value)
		group := groups[domain]
		if group == nil {
			group = &EventDomainValue{Domain: domain, Hosts: []string{}}
			groups[domain] = group
		}
		group.Count += host.Count
		if len(group.Hosts) < MaxEventDomainHosts && !slices.Contains(group.Hosts, name) {
			group.Hosts = append(group.Hosts, name)
		}
	}
	values := make([]EventDomainValue, 0, len(groups))
	for _, group := range groups {
		values = append(values, *group)
	}
	sort.Slice(values, func(i, j int) bool {
		if values[i].Count != values[j].Count {
			return values[i].Count > values[j].Count
		}
		return values[i].Domain < values[j].Domain
	})
	if len(values) > MaxEventDomainValues {
		values = values[:MaxEventDomainValues]
	}
	shown := int64(0)
	for _, value := range values {
		shown += value.Count
	}
	return EventDomainFacet{Values: values, OtherCount: max(0, total-shown)}
}

func validateEventDomains(domains EventDomainFacet) error {
	if domains.Values == nil || len(domains.Values) > MaxEventDomainValues || domains.OtherCount < 0 || domains.OtherCount > MaxEventFacetInput {
		return errors.New("event query service returned invalid domain bounds")
	}
	for index, value := range domains.Values {
		if value.Count < 1 || value.Count > MaxEventFacetInput || facetDomain(value.Domain) != value.Domain || len(value.Hosts) < 1 || len(value.Hosts) > MaxEventDomainHosts {
			return errors.New("event query service returned an invalid domain")
		}
		for _, host := range value.Hosts {
			if normalized, ok := domainclass.NormalizeHost(host); !ok || normalized != host || facetDomain(host) != value.Domain {
				return errors.New("event query service returned an invalid domain host")
			}
		}
		if index > 0 {
			previous := domains.Values[index-1]
			if value.Count > previous.Count || value.Count == previous.Count && value.Domain <= previous.Domain {
				return errors.New("event query service returned domains out of order")
			}
		}
	}
	return nil
}
