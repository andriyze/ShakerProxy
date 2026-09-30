package querylang

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"shakerproxy.dev/shakerproxy/internal/protocolclass"
)

const (
	MaxQueryBytes = 2048
	maxTokens     = 128
	maxDepth      = 12
)

type NodeType string

const (
	NodePredicate NodeType = "PREDICATE"
	NodeAnd       NodeType = "AND"
	NodeOr        NodeType = "OR"
	NodeNot       NodeType = "NOT"
)

type Operator string

const (
	OperatorEqual              Operator = "="
	OperatorNotEqual           Operator = "!="
	OperatorGreaterThan        Operator = ">"
	OperatorGreaterThanOrEqual Operator = ">="
	OperatorLessThan           Operator = "<"
	OperatorLessThanOrEqual    Operator = "<="
)

type Predicate struct {
	Field          string
	Operator       Operator
	Value          string
	Numeric        int64
	IsNumeric      bool
	RelativeNanos  int64
	IsRelativeTime bool
	Timestamp      time.Time
	IsTimestamp    bool
}

type Node struct {
	Type      NodeType
	Predicate *Predicate
	Children  []*Node
}

type Query struct {
	Root      *Node
	Canonical string
}

type tokenKind uint8

const (
	tokenWord tokenKind = iota
	tokenQuoted
	tokenOperator
	tokenLeftParen
	tokenRightParen
	tokenEOF
)

type token struct {
	kind tokenKind
	text string
}

type parser struct {
	tokens []token
	index  int
	depth  int
}

func Parse(input string) (Query, error) {
	if input == "" {
		return Query{}, nil
	}
	if len(input) > MaxQueryBytes || !utf8.ValidString(input) {
		return Query{}, errors.New("query is invalid or exceeds 2048 bytes")
	}
	tokens, err := lex(input)
	if err != nil {
		return Query{}, err
	}
	p := &parser{tokens: tokens}
	root, err := p.parseOr()
	if err != nil {
		return Query{}, err
	}
	if p.peek().kind != tokenEOF {
		return Query{}, fmt.Errorf("unexpected token %q", p.peek().text)
	}
	// The canonical form spells out implicit AND and "-" negation, so it can
	// be longer than the input. It is stored and reparsed, so it must fit the
	// same bounds or saved views and cursors would later fail to load.
	normalized := canonical(root, 0)
	if len(normalized) > MaxQueryBytes {
		return Query{}, errors.New("query is too long once normalized; remove some terms")
	}
	if _, err := lex(normalized); err != nil {
		return Query{}, errors.New("query has too many terms once normalized; remove some terms")
	}
	return Query{Root: root, Canonical: normalized}, nil
}

func lex(input string) ([]token, error) {
	tokens := make([]token, 0, 16)
	for offset := 0; offset < len(input); {
		r, size := utf8.DecodeRuneInString(input[offset:])
		if unicode.IsSpace(r) {
			offset += size
			continue
		}
		if len(tokens) >= maxTokens {
			return nil, errors.New("query contains too many tokens")
		}
		switch input[offset] {
		case '(':
			tokens = append(tokens, token{kind: tokenLeftParen, text: "("})
			offset++
		case ')':
			tokens = append(tokens, token{kind: tokenRightParen, text: ")"})
			offset++
		case '"':
			value, next, err := scanQuoted(input, offset)
			if err != nil {
				return nil, err
			}
			tokens = append(tokens, token{kind: tokenQuoted, text: value})
			offset = next
		case '!', '<', '>', '=':
			operator := input[offset : offset+1]
			offset++
			if offset < len(input) && input[offset] == '=' && operator != "=" {
				operator += "="
				offset++
			}
			if operator == "!" {
				return nil, errors.New("query contains an incomplete operator")
			}
			tokens = append(tokens, token{kind: tokenOperator, text: operator})
		default:
			start := offset
			for offset < len(input) {
				r, size = utf8.DecodeRuneInString(input[offset:])
				if unicode.IsSpace(r) || strings.ContainsRune("()\"!<>=", r) {
					break
				}
				offset += size
			}
			if start == offset {
				return nil, errors.New("query contains an invalid token")
			}
			tokens = append(tokens, token{kind: tokenWord, text: input[start:offset]})
		}
	}
	tokens = append(tokens, token{kind: tokenEOF})
	return tokens, nil
}

func scanQuoted(input string, start int) (string, int, error) {
	var value strings.Builder
	for offset := start + 1; offset < len(input); {
		if input[offset] == '"' {
			return value.String(), offset + 1, nil
		}
		if input[offset] == '\\' {
			offset++
			if offset >= len(input) || input[offset] != '\\' && input[offset] != '"' {
				return "", 0, errors.New("quoted query value contains an invalid escape")
			}
			value.WriteByte(input[offset])
			offset++
			continue
		}
		r, size := utf8.DecodeRuneInString(input[offset:])
		if unicode.IsControl(r) {
			return "", 0, errors.New("quoted query value contains a control character")
		}
		value.WriteRune(r)
		offset += size
	}
	return "", 0, errors.New("quoted query value is not terminated")
}

func (p *parser) parseOr() (*Node, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.isKeyword("OR") {
		p.index++
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = &Node{Type: NodeOr, Children: []*Node{left, right}}
	}
	return left, nil
}

func (p *parser) parseAnd() (*Node, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for {
		explicit := p.isKeyword("AND")
		if explicit {
			p.index++
		} else if !p.startsUnary() {
			break
		}
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = &Node{Type: NodeAnd, Children: []*Node{left, right}}
	}
	return left, nil
}

func (p *parser) parseUnary() (*Node, error) {
	if p.isKeyword("NOT") {
		p.index++
		child, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return &Node{Type: NodeNot, Children: []*Node{child}}, nil
	}
	if p.peek().kind == tokenWord && strings.HasPrefix(p.peek().text, "-") {
		p.tokens[p.index].text = strings.TrimPrefix(p.peek().text, "-")
		if p.tokens[p.index].text == "" {
			// A bare "-" negates the following group or predicate, e.g. -(a OR b).
			p.index++
		}
		child, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return &Node{Type: NodeNot, Children: []*Node{child}}, nil
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() (*Node, error) {
	if p.peek().kind == tokenLeftParen {
		p.depth++
		if p.depth > maxDepth {
			return nil, errors.New("query nesting is too deep")
		}
		p.index++
		node, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.peek().kind != tokenRightParen {
			return nil, errors.New("query parenthesis is not closed")
		}
		p.index++
		p.depth--
		return node, nil
	}
	return p.parsePredicate()
}

func (p *parser) parsePredicate() (*Node, error) {
	first := p.peek()
	if first.kind != tokenWord || p.isKeyword("AND") || p.isKeyword("OR") || p.isKeyword("NOT") {
		return nil, errors.New("query expected a field predicate")
	}
	p.index++
	field, value, hasColon := strings.Cut(first.text, ":")
	operator := OperatorEqual
	if !hasColon {
		field = first.text
		if p.peek().kind != tokenOperator {
			// A bare word is a free-text search over DNS names, TLS server
			// names, and HTTP hosts, so typing "netflix" just works.
			return normalizePredicateNode(TextField, OperatorEqual, first.text)
		}
		operator = Operator(p.peek().text)
		p.index++
	} else if value == "" && p.peek().kind == tokenOperator {
		operator = Operator(p.peek().text)
		p.index++
	}
	if value == "" {
		next := p.peek()
		if next.kind != tokenWord && next.kind != tokenQuoted {
			return nil, fmt.Errorf("query field %q requires a value", field)
		}
		value = next.text
		p.index++
	}
	return normalizePredicateNode(field, operator, value)
}

// TextField is the canonical field of a bare-word free-text search.
const TextField = "text"

var dateOnlyPattern = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)

// normalizePredicateNode normalizes one predicate. A date-only time value
// expands to the whole UTC day, which needs two timestamp predicates.
func normalizePredicateNode(field string, operator Operator, value string) (*Node, error) {
	if strings.EqualFold(field, "time") && dateOnlyPattern.MatchString(value) {
		return dayTimeNode(operator, value)
	}
	predicate, err := normalizePredicate(field, operator, value)
	if err != nil {
		return nil, err
	}
	return &Node{Type: NodePredicate, Predicate: &predicate}, nil
}

func dayTimeNode(operator Operator, value string) (*Node, error) {
	day, err := time.Parse("2006-01-02", value)
	if err != nil || day.Year() < 2000 || day.Year() > 2999 {
		return nil, errors.New("time requires a valid date such as 2026-09-01")
	}
	nextDay := day.AddDate(0, 0, 1)
	switch operator {
	case OperatorEqual:
		return &Node{Type: NodeAnd, Children: []*Node{timePredicateNode(OperatorGreaterThanOrEqual, day), timePredicateNode(OperatorLessThan, nextDay)}}, nil
	case OperatorNotEqual:
		return &Node{Type: NodeOr, Children: []*Node{timePredicateNode(OperatorLessThan, day), timePredicateNode(OperatorGreaterThanOrEqual, nextDay)}}, nil
	case OperatorGreaterThanOrEqual:
		return timePredicateNode(OperatorGreaterThanOrEqual, day), nil
	case OperatorGreaterThan:
		return timePredicateNode(OperatorGreaterThanOrEqual, nextDay), nil
	case OperatorLessThan:
		return timePredicateNode(OperatorLessThan, day), nil
	case OperatorLessThanOrEqual:
		return timePredicateNode(OperatorLessThan, nextDay), nil
	}
	return nil, errors.New("query predicate is invalid")
}

func timePredicateNode(operator Operator, instant time.Time) *Node {
	instant = instant.UTC()
	return &Node{Type: NodePredicate, Predicate: &Predicate{Field: "time", Operator: operator, Value: instant.Format(time.RFC3339Nano), Timestamp: instant, IsTimestamp: true}}
}

func normalizePredicate(field string, operator Operator, value string) (Predicate, error) {
	field = strings.ToLower(field)
	switch field {
	case "name", "device":
		field = "device.name"
	case "tag":
		field = "device.tag"
	case "proto", "app":
		field = "app.protocol"
	}
	if !validOperator(operator) || value == "" || len(value) > 1024 {
		return Predicate{}, errors.New("query predicate is invalid")
	}
	predicate := Predicate{Field: field, Operator: operator, Value: value}
	if value == "*" {
		if operator != OperatorEqual && operator != OperatorNotEqual {
			return Predicate{}, errors.New("existence checks support only equality or inequality")
		}
		if !knownField(field) {
			return Predicate{}, fmt.Errorf("query field %q is unsupported", field)
		}
		return predicate, nil
	}
	switch field {
	case "source":
		if !equalityOperator(operator) {
			return Predicate{}, errors.New("source supports only equality or inequality")
		}
		predicate.Value = strings.ToUpper(value)
		switch predicate.Value {
		case "HOST", "ZEEK", "SURICATA", "MITMPROXY":
		default:
			return Predicate{}, errors.New("source value is unsupported")
		}
	case "kind", "protocol", "service":
		if !equalityOperator(operator) || !validTextPattern(value) {
			return Predicate{}, fmt.Errorf("query field %q has an invalid value or operator", field)
		}
		predicate.Value = strings.ToLower(value)
	case "dns.query", "tls.sni", "http.host":
		if field == "dns.query" && equalityOperator(operator) && value == "." {
			// The DNS root is stored as "." and is a legitimate query name.
			break
		}
		if !equalityOperator(operator) || !validHostnamePattern(value) {
			return Predicate{}, fmt.Errorf("query field %q requires a canonical hostname pattern", field)
		}
		predicate.Value = strings.ToLower(strings.TrimSuffix(value, "."))
	case TextField:
		if !equalityOperator(operator) || !validHostnamePattern(value) {
			return Predicate{}, fmt.Errorf("%q is not a search term; search a hostname fragment such as netflix, or use field:value such as dns.query:example.com", value)
		}
		predicate.Value = strings.ToLower(strings.TrimSuffix(value, "."))
	case "app.protocol":
		if !equalityOperator(operator) || !validTextPattern(value) {
			return Predicate{}, errors.New("app.protocol requires a protocol ID such as mqtt, tls, or dns")
		}
		predicate.Value = strings.ToLower(value)
		if !strings.Contains(predicate.Value, "*") && !protocolclass.ValidID(predicate.Value) {
			normalized := protocolclass.NormalizeService(predicate.Value)
			if normalized == "" {
				return Predicate{}, fmt.Errorf("app.protocol %q is not a known protocol; list protocol IDs with GET /api/v1/protocols/catalog", value)
			}
			predicate.Value = normalized
		}
	case "protocol.category":
		predicate.Value = strings.ToLower(value)
		if !equalityOperator(operator) || !protocolclass.ValidCategory(predicate.Value) {
			return Predicate{}, errors.New("protocol.category requires a category such as iot-messaging, vpn-tunnel, or unknown")
		}
	case "protocol.visibility":
		predicate.Value = strings.ToUpper(value)
		if !equalityOperator(operator) || !protocolclass.ValidVisibility(predicate.Value) {
			return Predicate{}, errors.New("protocol.visibility must be DECRYPTED, CLEARTEXT, ENCRYPTED_METADATA, or OPAQUE")
		}
	case "protocol.exotic":
		if !equalityOperator(operator) {
			return Predicate{}, errors.New("protocol.exotic supports only equality or inequality")
		}
		predicate.Value = strings.ToLower(value)
		if predicate.Value != "true" && predicate.Value != "false" {
			return Predicate{}, errors.New("protocol.exotic requires true or false")
		}
	case "dns.rcode":
		if !equalityOperator(operator) || !validTextPattern(value) {
			return Predicate{}, errors.New("dns.rcode has an invalid value or operator")
		}
		predicate.Value = strings.ToUpper(value)
	case "tls.state":
		if !equalityOperator(operator) {
			return Predicate{}, errors.New("tls.state supports only equality or inequality")
		}
		predicate.Value = strings.ToUpper(value)
		switch predicate.Value {
		case "INTERCEPTED", "BYPASSED", "FAILED":
		default:
			return Predicate{}, errors.New("tls.state must be INTERCEPTED, BYPASSED, or FAILED")
		}
	case "tls.pinning":
		if !equalityOperator(operator) {
			return Predicate{}, errors.New("tls.pinning supports only equality or inequality")
		}
		predicate.Value = strings.ToLower(value)
		if predicate.Value != "true" && predicate.Value != "false" {
			return Predicate{}, errors.New("tls.pinning requires true or false")
		}
	case "http.method":
		if !equalityOperator(operator) || !validHTTPMethod(value) {
			return Predicate{}, errors.New("http.method has an invalid value or operator")
		}
		predicate.Value = strings.ToUpper(value)
	case "http.path":
		if !equalityOperator(operator) || !validHTTPPathPattern(value) {
			return Predicate{}, errors.New("http.path requires a bounded path pattern")
		}
	case "http.status":
		number, err := strconv.ParseInt(value, 10, 64)
		if err != nil || number < 100 || number > 599 {
			return Predicate{}, errors.New("http.status requires a status code from 100 to 599")
		}
		predicate.Numeric, predicate.IsNumeric, predicate.Value = number, true, strconv.FormatInt(number, 10)
	case "device.id":
		if !equalityOperator(operator) || len(value) != 39 || !strings.HasPrefix(value, "device-") || !isLowerHex(value[7:]) {
			return Predicate{}, errors.New("device.id requires a canonical ShakerProxy device ID")
		}
	case "device.name":
		if !equalityOperator(operator) || len(value) > 128 || value != strings.TrimSpace(value) || strings.Contains(value, "*") {
			return Predicate{}, errors.New("device.name requires a friendly name of at most 128 bytes")
		}
		for _, character := range value {
			if character < 0x20 || character == 0x7f {
				return Predicate{}, errors.New("device.name contains a control character")
			}
		}
	case "device.tag":
		if !equalityOperator(operator) || len(value) > 64 || value != strings.TrimSpace(value) || strings.Contains(value, "*") {
			return Predicate{}, errors.New("device.tag requires an exact tag of at most 64 bytes")
		}
		for _, character := range value {
			if character < 0x20 || character == 0x7f {
				return Predicate{}, errors.New("device.tag contains a control character")
			}
		}
		predicate.Value = strings.ToLower(value)
	case "capture.id":
		if !equalityOperator(operator) || len(value) != 40 || !strings.HasPrefix(value, "capture-") || !isLowerHex(value[8:]) {
			return Predicate{}, errors.New("capture.id requires a canonical ShakerProxy capture ID")
		}
	case "src.ip", "dst.ip":
		if !equalityOperator(operator) {
			return Predicate{}, fmt.Errorf("query field %q supports only equality or inequality", field)
		}
		// Zone-scoped addresses are rejected here instead of failing in SQL;
		// every other spelling is canonicalized to the stored form.
		canonicalIP, err := canonicalIPOrPrefix(value)
		if err != nil {
			return Predicate{}, fmt.Errorf("query field %q %s", field, err.Error())
		}
		predicate.Value = canonicalIP
	case "src.port", "dst.port":
		number, err := strconv.ParseInt(value, 10, 64)
		if err != nil || number < 1 || number > 65535 {
			return Predicate{}, fmt.Errorf("query field %q requires a port from 1 to 65535", field)
		}
		predicate.Numeric, predicate.IsNumeric, predicate.Value = number, true, strconv.FormatInt(number, 10)
	case "confidence":
		number, err := strconv.ParseInt(value, 10, 64)
		if err != nil || number < 0 || number > 100 {
			return Predicate{}, errors.New("confidence requires an integer from 0 to 100")
		}
		predicate.Numeric, predicate.IsNumeric, predicate.Value = number, true, strconv.FormatInt(number, 10)
	case "bytes":
		number, err := parseBytes(value)
		if err != nil {
			return Predicate{}, err
		}
		predicate.Numeric, predicate.IsNumeric, predicate.Value = number, true, strconv.FormatInt(number, 10)
	case "time":
		if strings.HasPrefix(strings.ToLower(value), "last_") {
			if operator != OperatorEqual {
				return Predicate{}, errors.New("relative time supports only equality")
			}
			duration, canonicalValue, err := parseRelativeTime(value)
			if err != nil {
				return Predicate{}, err
			}
			predicate.Value, predicate.RelativeNanos, predicate.IsRelativeTime = canonicalValue, int64(duration), true
			break
		}
		instant, err := time.Parse(time.RFC3339Nano, value)
		if err != nil || instant.Year() < 2000 || instant.Year() > 3000 {
			return Predicate{}, errors.New("time requires last_<duration> or an RFC3339 timestamp")
		}
		instant = instant.UTC()
		predicate.Value, predicate.Timestamp, predicate.IsTimestamp = instant.Format(time.RFC3339Nano), instant, true
	default:
		return Predicate{}, fmt.Errorf("query field %q is unsupported", field)
	}
	return predicate, nil
}

func parseRelativeTime(value string) (time.Duration, string, error) {
	raw := strings.ToLower(strings.TrimPrefix(strings.ToLower(value), "last_"))
	if len(raw) < 2 {
		return 0, "", errors.New("relative time requires last_<number><s|m|h|d>")
	}
	unit := raw[len(raw)-1]
	numberText := raw[:len(raw)-1]
	if len(numberText) > 1 && numberText[0] == '0' {
		return 0, "", errors.New("relative time must be canonical")
	}
	number, err := strconv.ParseInt(numberText, 10, 64)
	if err != nil || number < 1 {
		return 0, "", errors.New("relative time requires a positive integer")
	}
	multiplier := time.Second
	switch unit {
	case 's':
	case 'm':
		multiplier = time.Minute
	case 'h':
		multiplier = time.Hour
	case 'd':
		multiplier = 24 * time.Hour
	default:
		return 0, "", errors.New("relative time supports s, m, h, or d units")
	}
	if number > int64((30*24*time.Hour)/multiplier) {
		return 0, "", errors.New("relative time exceeds the 30-day query bound")
	}
	return time.Duration(number) * multiplier, "last_" + strconv.FormatInt(number, 10) + string(unit), nil
}

// canonicalIPOrPrefix accepts any spelling of an address or network and
// returns the form ingest stores: IPv4-mapped IPv6 is unmapped, IPv6 is
// lowercase and compressed, and CIDRs are masked to their network.
func canonicalIPOrPrefix(value string) (string, error) {
	if address, err := netip.ParseAddr(value); err == nil {
		if address.Zone() != "" {
			return "", errors.New("does not support IPv6 zone identifiers such as %eth0")
		}
		return address.Unmap().String(), nil
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return "", errors.New("requires an IP address or CIDR such as 10.77.0.0/24")
	}
	if prefix.Addr().Is4In6() {
		if prefix.Bits() < 96 {
			return "", errors.New("requires an IPv4-mapped prefix of at least /96")
		}
		prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
	}
	return prefix.Masked().String(), nil
}

func parseBytes(value string) (int64, error) {
	upper := strings.ToUpper(value)
	multiplier := int64(1)
	for _, unit := range []struct {
		suffix     string
		multiplier int64
	}{{"TIB", 1 << 40}, {"TB", 1 << 40}, {"GIB", 1 << 30}, {"GB", 1 << 30}, {"MIB", 1 << 20}, {"MB", 1 << 20}, {"KIB", 1 << 10}, {"KB", 1 << 10}, {"B", 1}} {
		if strings.HasSuffix(upper, unit.suffix) {
			upper = strings.TrimSuffix(upper, unit.suffix)
			multiplier = unit.multiplier
			break
		}
	}
	number, err := strconv.ParseInt(upper, 10, 64)
	if err != nil || number < 0 || number > (1<<63-1)/multiplier {
		return 0, errors.New("bytes requires a nonnegative integer with an optional KB, MB, GB, or TB unit")
	}
	return number * multiplier, nil
}

func validTextPattern(value string) bool {
	if len(value) > 128 || strings.Count(value, "*") > 2 {
		return false
	}
	for _, character := range []byte(value) {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("._+*-", rune(character))) {
			return false
		}
	}
	return true
}

func validHostnamePattern(value string) bool {
	value = strings.TrimSuffix(value, ".")
	// Empty labels ("a..b", "a..") are never valid names and would make the
	// canonical form unstable because only one trailing dot is removed.
	if value == "" || len(value) > 253 || strings.Count(value, "*") > 2 || strings.ContainsAny(value, "/:@ ") || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") || strings.Contains(value, "..") {
		return false
	}
	for _, character := range []byte(value) {
		// Underscores are legal in DNS labels used by SRV, DNS-SD, and mDNS
		// (for example _googlecast._tcp.local) and are stored by projections.
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '.' || character == '-' || character == '_' || character == '*') {
			return false
		}
	}
	return true
}

func validHTTPMethod(value string) bool {
	if value == "" || len(value) > 32 || strings.Contains(value, "*") {
		return false
	}
	for _, character := range []byte(value) {
		if !(character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || strings.ContainsRune("!#$%&'*+.^_`|~-", rune(character))) {
			return false
		}
	}
	return true
}

func validHTTPPathPattern(value string) bool {
	if value == "" || len(value) > 1024 || value != "*" && !strings.HasPrefix(value, "/") || strings.ContainsAny(value, "?#") || strings.Count(value, "*") > 8 {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func canonical(node *Node, parentPrecedence int) string {
	if node == nil {
		return ""
	}
	precedence := map[NodeType]int{NodeOr: 1, NodeAnd: 2, NodeNot: 3, NodePredicate: 4}[node.Type]
	var value string
	switch node.Type {
	case NodePredicate:
		predicate := node.Predicate
		operator := string(predicate.Operator)
		if predicate.Operator == OperatorEqual {
			operator = ":"
		}
		value = predicate.Field + operator + quoteCanonical(predicate.Value)
	case NodeNot:
		value = "NOT " + canonical(node.Children[0], precedence)
	case NodeAnd, NodeOr:
		// The parser is left-associative, so a right operand with the same
		// precedence must keep its parentheses to round-trip to the same tree.
		value = canonical(node.Children[0], precedence) + " " + string(node.Type) + " " + canonical(node.Children[1], precedence+1)
	}
	if precedence < parentPrecedence {
		return "(" + value + ")"
	}
	return value
}

// quoteCanonical quotes every value the lexer would otherwise split or
// reinterpret: any Unicode space, parentheses, quotes, and the comparison
// operator characters.
func quoteCanonical(value string) string {
	if value != "" && !strings.ContainsAny(value, "()\"!<>=") && strings.IndexFunc(value, unicode.IsSpace) < 0 {
		return value
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value) + `"`
}

func (p *parser) peek() token { return p.tokens[p.index] }

func (p *parser) isKeyword(keyword string) bool {
	return p.peek().kind == tokenWord && strings.EqualFold(p.peek().text, keyword)
}

func (p *parser) startsUnary() bool {
	if p.peek().kind == tokenLeftParen {
		return true
	}
	return p.peek().kind == tokenWord && !p.isKeyword("OR") && !p.isKeyword("AND")
}

func validOperator(operator Operator) bool {
	switch operator {
	case OperatorEqual, OperatorNotEqual, OperatorGreaterThan, OperatorGreaterThanOrEqual, OperatorLessThan, OperatorLessThanOrEqual:
		return true
	default:
		return false
	}
}

func equalityOperator(operator Operator) bool {
	return operator == OperatorEqual || operator == OperatorNotEqual
}

func knownField(field string) bool {
	for _, metadata := range metadataFields {
		if metadata.Name == field {
			return true
		}
	}
	return false
}

func HasRelativeTime(query Query) bool {
	var found bool
	var visit func(*Node)
	visit = func(node *Node) {
		if node == nil || found {
			return
		}
		if node.Type == NodePredicate && node.Predicate != nil && node.Predicate.Field == "time" && node.Predicate.IsRelativeTime {
			found = true
			return
		}
		for _, child := range node.Children {
			visit(child)
		}
	}
	visit(query.Root)
	return found
}

// DeviceNameValues returns the distinct friendly-name operands in stable AST
// order. Callers can resolve them once and freeze that immutable resolution for
// a recent page or live stream without exposing inventory names to storage.
func DeviceNameValues(query Query) []string {
	return predicateValues(query, "device.name")
}

// DeviceTagValues returns the distinct normalized device-tag operands in
// stable AST order so the control plane can freeze their device membership.
func DeviceTagValues(query Query) []string {
	return predicateValues(query, "device.tag")
}

func predicateValues(query Query, field string) []string {
	values := make([]string, 0, 4)
	seen := make(map[string]struct{})
	var visit func(*Node)
	visit = func(node *Node) {
		if node == nil {
			return
		}
		if node.Type == NodePredicate && node.Predicate != nil && node.Predicate.Field == field {
			if _, exists := seen[node.Predicate.Value]; !exists {
				seen[node.Predicate.Value] = struct{}{}
				values = append(values, node.Predicate.Value)
			}
		}
		for _, child := range node.Children {
			visit(child)
		}
	}
	visit(query.Root)
	return values
}

// RewriteDeviceNames returns a deep, reparsed query whose device.name operands
// are replaced by opaque references. This lets a trusted control-plane client
// preserve boolean structure while keeping inventory names out of a storage
// request. Every distinct operand must have exactly one replacement.
func RewriteDeviceNames(query Query, replacements map[string]string) (Query, error) {
	return rewritePredicateValues(query, "device.name", replacements)
}

// RewriteDeviceTags replaces public tag operands with opaque references while
// preserving the independently parsed boolean structure.
func RewriteDeviceTags(query Query, replacements map[string]string) (Query, error) {
	return rewritePredicateValues(query, "device.tag", replacements)
}

func rewritePredicateValues(query Query, field string, replacements map[string]string) (Query, error) {
	parsed, err := Parse(query.Canonical)
	if err != nil || parsed.Root == nil && query.Root != nil || parsed.Canonical != query.Canonical {
		return Query{}, errors.New("query cannot be rewritten")
	}
	values := predicateValues(parsed, field)
	if len(values) != len(replacements) {
		return Query{}, errors.New("device selector rewrite is incomplete")
	}
	var rewrite func(*Node) (*Node, error)
	rewrite = func(node *Node) (*Node, error) {
		if node == nil {
			return nil, nil
		}
		copyNode := &Node{Type: node.Type}
		if node.Predicate != nil {
			predicate := *node.Predicate
			if predicate.Field == field {
				replacement, found := replacements[predicate.Value]
				if !found {
					return nil, errors.New("device selector rewrite is incomplete")
				}
				predicate, err = normalizePredicate(predicate.Field, predicate.Operator, replacement)
				if err != nil {
					return nil, errors.New("device selector rewrite is invalid")
				}
			}
			copyNode.Predicate = &predicate
		}
		copyNode.Children = make([]*Node, len(node.Children))
		for index, child := range node.Children {
			copyNode.Children[index], err = rewrite(child)
			if err != nil {
				return nil, err
			}
		}
		return copyNode, nil
	}
	root, err := rewrite(parsed.Root)
	if err != nil {
		return Query{}, err
	}
	return Query{Root: root, Canonical: canonical(root, 0)}, nil
}

func isLowerHex(value string) bool {
	for _, character := range value {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return value != ""
}
