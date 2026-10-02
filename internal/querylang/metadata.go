package querylang

import "shakerproxy.dev/shakerproxy/internal/protocolclass"

// MetadataSchemaVersion changes only when the autocomplete contract changes
// incompatibly. It is independent from the event envelope schema.
const MetadataSchemaVersion = 1

type FieldMetadata struct {
	Name        string     `json:"name"`
	Aliases     []string   `json:"aliases,omitempty"`
	ValueType   string     `json:"value_type"`
	Operators   []Operator `json:"operators"`
	EnumValues  []string   `json:"enum_values,omitempty"`
	Suggestions []string   `json:"suggestions"`
	Wildcard    bool       `json:"wildcard"`
}

type Metadata struct {
	Schema        int             `json:"schema"`
	MaxQueryBytes int             `json:"max_query_bytes"`
	MaxTokens     int             `json:"max_tokens"`
	MaxDepth      int             `json:"max_depth"`
	Fields        []FieldMetadata `json:"fields"`
}

var equalityOperators = []Operator{OperatorEqual, OperatorNotEqual}
var orderedOperators = []Operator{OperatorEqual, OperatorNotEqual, OperatorGreaterThan, OperatorGreaterThanOrEqual, OperatorLessThan, OperatorLessThanOrEqual}

var metadataFields = []FieldMetadata{
	{Name: "source", ValueType: "enum", Operators: equalityOperators, EnumValues: []string{"HOST", "ZEEK", "SURICATA", "MITMPROXY"}, Suggestions: []string{"source:ZEEK", "source:SURICATA", "source:HOST", "source:MITMPROXY"}},
	{Name: "kind", ValueType: "text", Operators: equalityOperators, Suggestions: []string{"kind:zeek.conn", "kind:suricata.alert"}, Wildcard: true},
	{Name: "device.id", ValueType: "device_id", Operators: equalityOperators, Suggestions: []string{"device.id:device-0123456789abcdef0123456789abcdef"}},
	{Name: "device.name", Aliases: []string{"name", "device"}, ValueType: "device_name", Operators: equalityOperators, Suggestions: []string{`device.name:"Bench Camera"`}},
	{Name: "device.tag", Aliases: []string{"tag"}, ValueType: "device_tag", Operators: equalityOperators, Suggestions: []string{"device.tag:camera"}},
	{Name: "capture.id", ValueType: "capture_id", Operators: equalityOperators, Suggestions: []string{"capture.id:capture-0123456789abcdef0123456789abcdef"}},
	{Name: "src.ip", ValueType: "ip_or_cidr", Operators: equalityOperators, Suggestions: []string{"src.ip:10.77.0.0/24"}},
	{Name: "dst.ip", ValueType: "ip_or_cidr", Operators: equalityOperators, Suggestions: []string{"dst.ip:1.1.1.1"}},
	{Name: "src.port", ValueType: "port", Operators: orderedOperators, Suggestions: []string{"src.port:>=1024"}},
	{Name: "dst.port", ValueType: "port", Operators: orderedOperators, Suggestions: []string{"dst.port:443"}},
	{Name: "protocol", ValueType: "text", Operators: equalityOperators, Suggestions: []string{"protocol:tcp", "protocol:udp"}, Wildcard: true},
	{Name: "service", ValueType: "text", Operators: equalityOperators, Suggestions: []string{"service:dns", "service:http*"}, Wildcard: true},
	{Name: "app.protocol", Aliases: []string{"proto", "app"}, ValueType: "protocol", Operators: equalityOperators, EnumValues: protocolIDs(), Suggestions: []string{"app.protocol:mqtt", "app.protocol:dns", "app.protocol:quic", "app.protocol:unknown-*"}, Wildcard: true},
	{Name: "protocol.category", ValueType: "enum", Operators: equalityOperators, EnumValues: protocolCategories(), Suggestions: []string{"protocol.category:iot-messaging", "protocol.category:vpn-tunnel", "protocol.category:encrypted-dns"}},
	{Name: "protocol.visibility", ValueType: "enum", Operators: equalityOperators, EnumValues: []string{"DECRYPTED", "CLEARTEXT", "ENCRYPTED_METADATA", "OPAQUE"}, Suggestions: []string{"protocol.visibility:OPAQUE", "protocol.visibility:CLEARTEXT", "protocol.visibility:DECRYPTED"}},
	{Name: "protocol.exotic", ValueType: "boolean", Operators: equalityOperators, EnumValues: []string{"true", "false"}, Suggestions: []string{"protocol.exotic:true"}},
	{Name: TextField, ValueType: "hostname", Operators: equalityOperators, Suggestions: []string{"netflix", "192.168.10.20", "text:*.example.com"}, Wildcard: true},
	{Name: "dns.query", ValueType: "hostname", Operators: equalityOperators, Suggestions: []string{"dns.query:example.com", "dns.query:*.example.com"}, Wildcard: true},
	{Name: "dns.rcode", ValueType: "enum_text", Operators: equalityOperators, Suggestions: []string{"dns.rcode:NOERROR", "dns.rcode:NXDOMAIN"}, Wildcard: true},
	{Name: "tls.sni", ValueType: "hostname", Operators: equalityOperators, Suggestions: []string{"tls.sni:api.example.com", "tls.sni:*.example.com"}, Wildcard: true},
	{Name: "tls.state", ValueType: "enum", Operators: equalityOperators, EnumValues: []string{"INTERCEPTED", "BYPASSED", "FAILED"}, Suggestions: []string{"tls.state:INTERCEPTED", "tls.state:BYPASSED", "tls.state:FAILED"}},
	{Name: "tls.pinning", ValueType: "boolean", Operators: equalityOperators, EnumValues: []string{"true", "false"}, Suggestions: []string{"tls.pinning:true"}},
	{Name: "http.host", ValueType: "hostname", Operators: equalityOperators, Suggestions: []string{"http.host:api.example.com", "http.host:*.example.com"}, Wildcard: true},
	{Name: "http.method", ValueType: "http_method", Operators: equalityOperators, Suggestions: []string{"http.method:GET", "http.method:POST"}},
	{Name: "http.status", ValueType: "http_status", Operators: orderedOperators, Suggestions: []string{"http.status:>=400", "http.status:500"}},
	{Name: "http.path", ValueType: "http_path", Operators: equalityOperators, Suggestions: []string{"http.path:/v1/orders", "http.path:/api/*"}, Wildcard: true},
	{Name: "bytes", ValueType: "bytes", Operators: orderedOperators, Suggestions: []string{"bytes:>10MB"}},
	{Name: "confidence", ValueType: "percentage", Operators: orderedOperators, Suggestions: []string{"confidence:>=80"}},
	{Name: "time", ValueType: "time", Operators: orderedOperators, Suggestions: []string{"time:last_15m", "time>=2026-09-01T12:00:00Z"}},
}

func protocolIDs() []string {
	catalog := protocolclass.Catalog()
	ids := make([]string, 0, len(catalog))
	for _, protocol := range catalog {
		ids = append(ids, protocol.ID)
	}
	return ids
}

func protocolCategories() []string {
	categories := protocolclass.Categories()
	values := make([]string, 0, len(categories))
	for _, category := range categories {
		values = append(values, string(category))
	}
	return values
}

// AutocompleteMetadata returns a defensive copy of the bounded parser
// vocabulary. Consumers cannot mutate the package-level source of truth.
func AutocompleteMetadata() Metadata {
	fields := make([]FieldMetadata, len(metadataFields))
	for index, field := range metadataFields {
		field.Aliases = append([]string(nil), field.Aliases...)
		field.Operators = append([]Operator(nil), field.Operators...)
		field.EnumValues = append([]string(nil), field.EnumValues...)
		field.Suggestions = append([]string(nil), field.Suggestions...)
		fields[index] = field
	}
	return Metadata{Schema: MetadataSchemaVersion, MaxQueryBytes: MaxQueryBytes, MaxTokens: maxTokens, MaxDepth: maxDepth, Fields: fields}
}
