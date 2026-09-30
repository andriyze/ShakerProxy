package ingest

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"regexp"
	"strings"
)

var (
	tlsServerNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,253}$`)
	tlsReasonPattern     = regexp.MustCompile(`^[a-z0-9_]{1,96}$`)
)

type TLSProjection struct {
	ServerName             string
	InterceptionState      string
	FailureReason          string
	PinningSuspected       bool
	ClientRecentSuccess    *bool
	DynamicBypassActivated bool
	Platform               string
}

func validTLSProjection(event RecentEvent) bool {
	empty := event.TLSServerName == "" && event.TLSInterceptionState == "" && event.TLSFailureReason == "" && !event.TLSPinningSuspected && event.TLSClientRecentSuccess == nil && !event.TLSBypassActivated && event.TLSPlatform == ""
	if empty {
		return true
	}
	if event.Source == SourceZeek || event.Source == SourceSuricata {
		// Passive analyzers only contribute the observed SNI; interception
		// outcomes can only come from the MITM path.
		return event.TLSServerName != "" && tlsServerName(event.TLSServerName) == event.TLSServerName && event.TLSInterceptionState == "" && event.TLSFailureReason == "" && !event.TLSPinningSuspected && event.TLSClientRecentSuccess == nil && !event.TLSBypassActivated && event.TLSPlatform == ""
	}
	if event.Source != SourceMitmproxy || tlsServerName(event.TLSServerName) != event.TLSServerName || event.TLSFailureReason != "" && tlsReason(event.TLSFailureReason) != event.TLSFailureReason || event.TLSPlatform != "" && tlsPlatform(event.TLSPlatform) != event.TLSPlatform {
		return false
	}
	expectedState := ""
	switch event.Kind {
	case "tls_intercepted":
		expectedState = "INTERCEPTED"
	case "tls_passthrough":
		expectedState = "BYPASSED"
	case "tls_interception_failed":
		expectedState = "FAILED"
	}
	if event.TLSInterceptionState != expectedState || expectedState == "" {
		return false
	}
	if expectedState != "FAILED" && (event.TLSPinningSuspected || event.TLSClientRecentSuccess != nil || event.TLSBypassActivated) {
		return false
	}
	if event.TLSPinningSuspected && event.TLSFailureReason != "probable_certificate_pinning_or_custom_trust_store" {
		return false
	}
	return true
}

// ProjectTLSFields exposes only bounded, operator-useful MITM outcomes plus the
// SNI observed passively by Zeek (ssl.log server_name) or Suricata (tls.sni). It
// does not project request paths, headers, bodies, credentials, or raw
// certificates.
func ProjectTLSFields(envelope Envelope) TLSProjection {
	switch envelope.Source {
	case SourceZeek, SourceSuricata:
		return TLSProjection{ServerName: passiveTLSServerName(envelope)}
	case SourceMitmproxy:
	default:
		return TLSProjection{}
	}
	state := ""
	switch envelope.Kind {
	case "tls_intercepted":
		state = "INTERCEPTED"
	case "tls_passthrough":
		state = "BYPASSED"
	case "tls_interception_failed":
		state = "FAILED"
	default:
		return TLSProjection{}
	}
	var payload struct {
		SNI                any   `json:"sni"`
		Reason             any   `json:"reason"`
		Platform           any   `json:"platform"`
		RecentSuccess      *bool `json:"client_has_recent_successful_interception"`
		DynamicBypassAdded bool  `json:"dynamic_bypass_added"`
	}
	decoder := json.NewDecoder(bytes.NewReader(envelope.Payload))
	decoder.UseNumber()
	if decoder.Decode(&payload) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return TLSProjection{}
	}
	serverName := tlsServerName(payload.SNI)
	reason := tlsReason(payload.Reason)
	platform := tlsPlatform(payload.Platform)
	pinning := reason == "probable_certificate_pinning_or_custom_trust_store"
	return TLSProjection{
		ServerName:             serverName,
		InterceptionState:      state,
		FailureReason:          reason,
		PinningSuspected:       pinning,
		ClientRecentSuccess:    payload.RecentSuccess,
		DynamicBypassActivated: payload.DynamicBypassAdded,
		Platform:               platform,
	}
}

func tlsServerName(value any) string {
	text, ok := value.(string)
	if !ok {
		return ""
	}
	text = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(text), "."))
	if text == "" {
		return ""
	}
	if parsed := net.ParseIP(text); parsed != nil {
		return parsed.String()
	}
	if !tlsServerNamePattern.MatchString(text) {
		return ""
	}
	return text
}

func tlsReason(value any) string {
	text, ok := value.(string)
	if !ok || !tlsReasonPattern.MatchString(text) {
		return ""
	}
	return text
}

func tlsPlatform(value any) string {
	text, ok := value.(string)
	if !ok {
		return ""
	}
	switch text {
	case "android", "android-tv", "ios", "tvos":
		return text
	default:
		return ""
	}
}

func passiveTLSServerName(envelope Envelope) string {
	// QUIC carries a TLS ClientHello too: Zeek logs it in quic.log and
	// Suricata in its quic object.
	if envelope.Source == SourceZeek && envelope.Kind != "zeek.ssl" && envelope.Kind != "zeek.quic" {
		return ""
	}
	type sniObject struct {
		SNI any `json:"sni"`
	}
	var payload struct {
		ServerName any        `json:"server_name"`
		TLS        *sniObject `json:"tls"`
		QUIC       *sniObject `json:"quic"`
	}
	if json.Unmarshal(envelope.Payload, &payload) != nil {
		return ""
	}
	if envelope.Source == SourceZeek {
		return tlsServerName(payload.ServerName)
	}
	if payload.TLS != nil {
		return tlsServerName(payload.TLS.SNI)
	}
	if payload.QUIC != nil {
		return tlsServerName(payload.QUIC.SNI)
	}
	return ""
}
