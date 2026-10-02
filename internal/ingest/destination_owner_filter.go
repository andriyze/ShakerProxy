package ingest

import (
	"errors"
	"fmt"
	"strings"

	"shakerproxy.dev/shakerproxy/internal/domainclass"
	"shakerproxy.dev/shakerproxy/internal/querylang"
)

// destinationNameSQL is destinationName in SQL: the server name, web host
// (without a port), looked-up name, or a connection's resolved name,
// normalized like domainclass does.
const destinationNameSQL = `lower(rtrim(regexp_replace(COALESCE(NULLIF(tls_server_name, ''), NULLIF(http_host, ''), NULLIF(dns_query, ''), NULLIF(dns_name, ''), ''), ':[0-9]+$', ''), '.'))`

// destinationSuffixes are the curated table suffixes a dst.owner or
// dst.category predicate selects: owners whose name contains the value
// (case-insensitive), or entries in the category. "*" selects every entry.
func destinationSuffixes(predicate querylang.Predicate) []string {
	want := strings.ToLower(strings.TrimSpace(predicate.Value))
	suffixes := []string{}
	for _, entry := range domainclass.Entries() {
		switch {
		case want == "*":
		case predicate.Field == querylang.DestinationOwnerField && strings.Contains(strings.ToLower(entry.Organization), want):
		case predicate.Field == querylang.DestinationCategoryField && string(entry.Category) == want:
		default:
			continue
		}
		suffixes = append(suffixes, entry.Suffix)
	}
	return suffixes
}

// compileDestinationOwnerPredicate matches the destination name against the
// selected suffixes on a label boundary, as domainclass.Classify does. It is
// two-valued like every other predicate: != matches events without a name.
func compileDestinationOwnerPredicate(predicate querylang.Predicate, args *[]any) (string, error) {
	if predicate.Operator != querylang.OperatorEqual && predicate.Operator != querylang.OperatorNotEqual {
		return "", errors.New("destination owner predicates support only equality or inequality")
	}
	suffixes := destinationSuffixes(predicate)
	clause := "FALSE"
	if len(suffixes) > 0 {
		patterns := make([]string, len(suffixes))
		for index, suffix := range suffixes {
			patterns[index] = "%." + likePattern(suffix)
		}
		*args = append(*args, suffixes, patterns)
		clause = fmt.Sprintf("(%[1]s = ANY($%[2]d::text[]) OR %[1]s LIKE ANY($%[3]d::text[]))", destinationNameSQL, len(*args)-1, len(*args))
	}
	if predicate.Operator == querylang.OperatorNotEqual {
		return "NOT " + clause, nil
	}
	return clause, nil
}
