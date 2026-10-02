package ingest

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"shakerproxy.dev/shakerproxy/internal/querylang"
)

func compileEventFilter(node *querylang.Node, nameResolutions, tagResolutions map[string][]string, timeAnchor time.Time, relativeUpperBound bool, args *[]any) (string, error) {
	if node == nil {
		return "", errors.New("typed event filter is empty")
	}
	switch node.Type {
	case querylang.NodeAnd, querylang.NodeOr:
		if len(node.Children) != 2 {
			return "", errors.New("typed event filter boolean node is invalid")
		}
		left, err := compileEventFilter(node.Children[0], nameResolutions, tagResolutions, timeAnchor, relativeUpperBound, args)
		if err != nil {
			return "", err
		}
		right, err := compileEventFilter(node.Children[1], nameResolutions, tagResolutions, timeAnchor, relativeUpperBound, args)
		if err != nil {
			return "", err
		}
		return "(" + left + " " + string(node.Type) + " " + right + ")", nil
	case querylang.NodeNot:
		if len(node.Children) != 1 {
			return "", errors.New("typed event filter negation is invalid")
		}
		child, err := compileEventFilter(node.Children[0], nameResolutions, tagResolutions, timeAnchor, relativeUpperBound, args)
		if err != nil {
			return "", err
		}
		return "(NOT " + child + ")", nil
	case querylang.NodePredicate:
		if node.Predicate == nil || len(node.Children) != 0 {
			return "", errors.New("typed event filter predicate is invalid")
		}
		return compileEventPredicate(*node.Predicate, nameResolutions, tagResolutions, timeAnchor, relativeUpperBound, args)
	default:
		return "", errors.New("typed event filter node type is unsupported")
	}
}

func compileEventPredicate(predicate querylang.Predicate, nameResolutions, tagResolutions map[string][]string, timeAnchor time.Time, relativeUpperBound bool, args *[]any) (string, error) {
	if predicate.Field == "device.name" || predicate.Field == "device.tag" {
		if predicate.Operator != querylang.OperatorEqual && predicate.Operator != querylang.OperatorNotEqual {
			return "", errors.New("typed device selector operator is unsupported")
		}
		resolutions := nameResolutions
		if predicate.Field == "device.tag" {
			resolutions = tagResolutions
		}
		ids, found := resolutions[predicate.Value]
		if !found {
			return "", errors.New("typed device selector resolution is missing")
		}
		if len(ids) == 0 {
			if predicate.Operator == querylang.OperatorEqual {
				return "FALSE", nil
			}
			return "TRUE", nil
		}
		*args = append(*args, ids)
		clause := fmt.Sprintf("COALESCE(device_id = ANY($%d::text[]), FALSE)", len(*args))
		if predicate.Operator == querylang.OperatorNotEqual {
			clause = "NOT " + clause
		}
		return clause, nil
	}
	if predicate.Field == "time" && predicate.Value != "*" {
		if predicate.IsRelativeTime {
			if predicate.Operator != querylang.OperatorEqual || timeAnchor.IsZero() || predicate.RelativeNanos < int64(time.Second) || predicate.RelativeNanos > int64(30*24*time.Hour) {
				return "", errors.New("typed relative time predicate is invalid")
			}
			*args = append(*args, timeAnchor.UTC().Add(-time.Duration(predicate.RelativeNanos)))
			clause := fmt.Sprintf("occurred_at >= $%d", len(*args))
			if relativeUpperBound {
				*args = append(*args, timeAnchor.UTC())
				clause = fmt.Sprintf("(%s AND occurred_at <= $%d)", clause, len(*args))
			}
			return clause, nil
		}
		if !predicate.IsTimestamp || predicate.Timestamp.IsZero() {
			return "", errors.New("typed absolute time predicate is invalid")
		}
		*args = append(*args, predicate.Timestamp.UTC())
		return fmt.Sprintf("occurred_at %s $%d", predicate.Operator, len(*args)), nil
	}
	if predicate.Field == querylang.TextField {
		return compileTextPredicate(predicate, args)
	}
	if predicate.Field == querylang.DestinationOwnerField || predicate.Field == querylang.DestinationCategoryField {
		return compileDestinationOwnerPredicate(predicate, args)
	}
	column := eventFilterColumns[predicate.Field]
	if column == "" {
		return "", errors.New("typed event filter field is unsupported")
	}
	if predicate.Value == "*" {
		switch predicate.Operator {
		case querylang.OperatorEqual:
			return column + " IS NOT NULL", nil
		case querylang.OperatorNotEqual:
			return column + " IS NULL", nil
		default:
			return "", errors.New("typed event existence operator is unsupported")
		}
	}
	// Every comparison is made two-valued: an event without the projected
	// field never matches a positive predicate, and it does match the negated
	// form. Without this, NOT/!= silently dropped every row whose column was NULL.
	negated := predicate.Operator == querylang.OperatorNotEqual
	operator := string(predicate.Operator)
	if negated {
		operator = string(querylang.OperatorEqual)
	}
	var clause string
	switch {
	case predicate.Field == "src.ip" || predicate.Field == "dst.ip":
		*args = append(*args, predicate.Value)
		if strings.Contains(predicate.Value, "/") {
			clause = fmt.Sprintf("%s <<= $%d::cidr", column, len(*args))
		} else {
			clause = fmt.Sprintf("%s %s $%d::inet", column, operator, len(*args))
		}
	case predicate.Field == "tls.pinning" || predicate.Field == "protocol.exotic":
		value, err := strconv.ParseBool(predicate.Value)
		if err != nil {
			return "", errors.New("typed boolean predicate is invalid")
		}
		*args = append(*args, value)
		clause = fmt.Sprintf("%s %s $%d", column, operator, len(*args))
	case predicate.IsNumeric:
		*args = append(*args, predicate.Numeric)
		clause = fmt.Sprintf("%s %s $%d", column, operator, len(*args))
	case strings.Contains(predicate.Value, "*"):
		if predicate.Operator != querylang.OperatorEqual && predicate.Operator != querylang.OperatorNotEqual {
			return "", errors.New("typed event wildcard operator is unsupported")
		}
		*args = append(*args, likePattern(predicate.Value))
		clause = fmt.Sprintf("%s LIKE $%d ESCAPE E'\\\\'", column, len(*args))
	default:
		*args = append(*args, predicate.Value)
		clause = fmt.Sprintf("%s %s $%d", column, operator, len(*args))
	}
	if negated {
		return "NOT COALESCE(" + clause + ", FALSE)", nil
	}
	return "COALESCE(" + clause + ", FALSE)", nil
}

// HTTP metadata is read from each source's own schema: mitmproxy's bounded
// http_* projection, Zeek http.log, and Suricata's nested http object. Only
// host, method, path, and status are ever read; query strings and fragments
// are stripped before a path comparison.
func httpFilterSource(mitmproxy, zeek, suricata string) string {
	return "CASE WHEN source = 'MITMPROXY' THEN " + mitmproxy +
		" WHEN source = 'ZEEK' AND kind = 'zeek.http' THEN " + zeek +
		" WHEN source = 'SURICATA' THEN " + suricata + " END"
}

var (
	httpHostFilterSource   = httpFilterSource("payload->>'http_host'", "regexp_replace(payload->>'host', ':[0-9]+$', '')", "payload#>>'{http,hostname}'")
	httpMethodFilterSource = httpFilterSource("payload->>'http_method'", "payload->>'method'", "payload#>>'{http,http_method}'")
	httpPathFilterSource   = httpFilterSource("payload->>'http_path'", "payload->>'uri'", "payload#>>'{http,url}'")
	httpStatusFilterSource = httpFilterSource("payload->>'http_status'", "payload->>'status_code'", "payload#>>'{http,status}'")
)

var eventFilterColumns = map[string]string{
	"source": "source", "kind": "kind", "device.id": "device_id", "capture.id": "capture_session_id",
	"src.ip": "source_ip", "dst.ip": "destination_ip", "src.port": "source_port", "dst.port": "destination_port",
	"protocol": "protocol", "service": "service", "bytes": "network_bytes", "confidence": "confidence", "time": "occurred_at",
	"dns.query": "dns_query", "dns.rcode": "dns_response_code",
	// Rows written before passive TLS projection existed only carry the SNI in
	// their Zeek ssl.log or Suricata tls payload.
	"tls.sni":   "COALESCE(tls_server_name, CASE WHEN source = 'ZEEK' AND kind = 'zeek.ssl' THEN lower(rtrim(payload->>'server_name', '.')) WHEN source = 'SURICATA' THEN lower(rtrim(payload#>>'{tls,sni}', '.')) END)",
	"tls.state": "tls_interception_state",
	// tls_pinning_suspected is stored only when true, so a TLS outcome without
	// it is an explicit false; non-TLS events have no pinning value at all.
	"tls.pinning": "(CASE WHEN tls_interception_state IS NOT NULL THEN COALESCE(tls_pinning_suspected, FALSE) END)",
	"http.host":   "lower(rtrim(" + httpHostFilterSource + ", '.'))",
	"http.method": "upper(" + httpMethodFilterSource + ")",
	"http.path":   "split_part(split_part(" + httpPathFilterSource + ", '?', 1), '#', 1)",
	"http.status": "(CASE WHEN (" + httpStatusFilterSource + ") ~ '^[0-9]{3}$' THEN (" + httpStatusFilterSource + ")::integer END)",
	// Protocol discovery columns are projected at ingest by protocolclass.
	"app.protocol": "app_protocol", "protocol.category": "protocol_category",
	"protocol.visibility": "protocol_visibility", "protocol.exotic": "protocol_exotic",
}

func likePattern(value string) string {
	return strings.NewReplacer("\\", "\\\\", "%", "\\%", "_", "\\_", "*", "%").Replace(value)
}

// compileTextPredicate implements a bare-word search: a case-insensitive
// substring match over the DNS query, TLS server name, and HTTP host, or, for
// a whole IP address or CIDR, a match on either endpoint of the event.
func compileTextPredicate(predicate querylang.Predicate, args *[]any) (string, error) {
	if predicate.IsAddress {
		if predicate.Operator != querylang.OperatorEqual && predicate.Operator != querylang.OperatorNotEqual {
			return "", errors.New("typed address search operator is unsupported")
		}
		*args = append(*args, predicate.Value)
		comparison := "= $%d::inet"
		if strings.Contains(predicate.Value, "/") {
			comparison = "<<= $%d::cidr"
		}
		comparison = fmt.Sprintf(comparison, len(*args))
		clause := fmt.Sprintf("(COALESCE(source_ip %[1]s, FALSE) OR COALESCE(destination_ip %[1]s, FALSE))", comparison)
		if predicate.Operator == querylang.OperatorNotEqual {
			clause = "NOT " + clause
		}
		return clause, nil
	}
	// dns_name is the looked-up name of a gateway-reported connection.
	fields := []string{"dns_query", "tls_server_name", "http_host", "dns_name"}
	if predicate.Value == "*" {
		clause := "(dns_query IS NOT NULL OR tls_server_name IS NOT NULL OR http_host IS NOT NULL OR dns_name IS NOT NULL)"
		if predicate.Operator == querylang.OperatorNotEqual {
			clause = "NOT " + clause
		}
		return clause, nil
	}
	if predicate.Operator != querylang.OperatorEqual && predicate.Operator != querylang.OperatorNotEqual {
		return "", errors.New("typed text search operator is unsupported")
	}
	*args = append(*args, "%"+likePattern(predicate.Value)+"%")
	placeholder := len(*args)
	matches := make([]string, 0, len(fields))
	for _, field := range fields {
		matches = append(matches, fmt.Sprintf("COALESCE(%s LIKE $%d ESCAPE E'\\\\', FALSE)", field, placeholder))
	}
	clause := "(" + strings.Join(matches, " OR ") + ")"
	if predicate.Operator == querylang.OperatorNotEqual {
		clause = "NOT " + clause
	}
	return clause, nil
}
