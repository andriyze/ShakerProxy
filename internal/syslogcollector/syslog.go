package syslogcollector

import (
	"strconv"
	"strings"
	"time"
	"unicode"
)

// Message is one parsed syslog line: its priority, timestamp, the program that
// emitted it (app-name / tag), and the free-form content after the header. The
// UniFi layer reads App and Content; the rest is kept for context.
type Message struct {
	Priority  int
	Timestamp time.Time
	Host      string
	App       string
	Content   string
}

// rfc3164Layouts are the timestamp forms BSD syslog and UniFi devices emit.
var rfc3164Layouts = []string{
	"Jan _2 15:04:05",
	"Jan 2 15:04:05",
	"Jan _2 15:04:05 2006",
}

// ParseSyslog parses an RFC5424 or RFC3164 syslog message. It is deliberately
// tolerant: a line that matches neither framing is still returned with its
// whole text as Content, so the UniFi layer can try to recognize it and an
// unrecognized line is counted, never executed. now supplies the year for
// RFC3164 timestamps, which omit it, and the fallback time for lines without
// a parseable timestamp.
func ParseSyslog(raw []byte, now time.Time) Message {
	line := strings.TrimRight(string(raw), "\r\n\x00")
	message := Message{Timestamp: now.UTC()}
	rest := line
	if strings.HasPrefix(rest, "<") {
		if end := strings.IndexByte(rest, '>'); end > 1 && end <= 4 {
			if priority, err := strconv.Atoi(rest[1:end]); err == nil && priority >= 0 && priority <= 191 {
				message.Priority = priority
				rest = rest[end+1:]
			}
		}
	}
	// RFC5424: "1 TIMESTAMP HOST APP PROCID MSGID [SD] MSG".
	if strings.HasPrefix(rest, "1 ") {
		if parsed, ok := parseRFC5424(rest[2:], &message); ok {
			message.Content = parsed
			return message
		}
	}
	parseRFC3164(rest, now, &message)
	return message
}

func parseRFC5424(rest string, message *Message) (string, bool) {
	fields := strings.SplitN(rest, " ", 6)
	if len(fields) < 6 {
		return "", false
	}
	if timestamp, err := time.Parse(time.RFC3339Nano, fields[0]); err == nil {
		message.Timestamp = timestamp.UTC()
	}
	message.Host = nilDash(fields[1])
	message.App = nilDash(fields[2])
	content := fields[5]
	// Skip structured data: "-" or one or more "[...]" elements.
	content = strings.TrimSpace(content)
	if strings.HasPrefix(content, "-") {
		content = strings.TrimSpace(content[1:])
	} else {
		for strings.HasPrefix(content, "[") {
			end := structuredDataEnd(content)
			if end < 0 {
				break
			}
			content = strings.TrimSpace(content[end+1:])
		}
	}
	message.Content = content
	return content, true
}

// structuredDataEnd returns the index of the closing bracket of the first
// structured-data element, honoring the "\]" escape, or -1.
func structuredDataEnd(content string) int {
	for index := 1; index < len(content); index++ {
		if content[index] == '\\' {
			index++
			continue
		}
		if content[index] == ']' {
			return index
		}
	}
	return -1
}

func parseRFC3164(rest string, now time.Time, message *Message) {
	rest = strings.TrimSpace(rest)
	for _, layout := range rfc3164Layouts {
		width := len(layout)
		if len(rest) < width {
			continue
		}
		if timestamp, err := time.Parse(layout, rest[:width]); err == nil {
			year := timestamp.Year()
			if year == 0 {
				year = now.Year()
			}
			message.Timestamp = time.Date(year, timestamp.Month(), timestamp.Day(), timestamp.Hour(), timestamp.Minute(), timestamp.Second(), 0, time.UTC)
			rest = strings.TrimSpace(rest[width:])
			break
		}
	}
	// "HOST TAG: content" or "HOST TAG[pid]: content"; some UniFi lines omit
	// the host. Take the first whitespace token as the host only when a tag
	// with a colon follows.
	if host, after, ok := splitHostTag(rest); ok {
		message.Host = host
		rest = after
	}
	if app, content, ok := splitTag(rest); ok {
		message.App = app
		message.Content = strings.TrimSpace(content)
		return
	}
	message.Content = rest
}

func splitHostTag(rest string) (string, string, bool) {
	space := strings.IndexByte(rest, ' ')
	if space <= 0 {
		return "", rest, false
	}
	candidate := rest[:space]
	// A host token has no colon; the tag (which does) comes next.
	if strings.ContainsAny(candidate, ":[") || strings.ContainsAny(candidate, "=") {
		return "", rest, false
	}
	after := strings.TrimSpace(rest[space+1:])
	if !strings.Contains(after, ":") {
		return "", rest, false
	}
	return candidate, after, true
}

func splitTag(rest string) (string, string, bool) {
	colon := strings.IndexByte(rest, ':')
	if colon <= 0 {
		return "", rest, false
	}
	tag := rest[:colon]
	// Strip a "[pid]" suffix from the tag.
	if bracket := strings.IndexByte(tag, '['); bracket >= 0 {
		tag = tag[:bracket]
	}
	if tag == "" || strings.ContainsFunc(tag, func(r rune) bool {
		return unicode.IsSpace(r)
	}) {
		return "", rest, false
	}
	return tag, rest[colon+1:], true
}

func nilDash(value string) string {
	if value == "-" {
		return ""
	}
	return value
}
