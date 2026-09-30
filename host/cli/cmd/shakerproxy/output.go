package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// ANSI styles. They are only emitted when stdout is a terminal, NO_COLOR is
// unset, and --no-color was not given.
const (
	styleReset  = "\x1b[0m"
	styleBold   = "\x1b[1m"
	styleDim    = "\x1b[2m"
	styleRed    = "\x1b[31m"
	styleGreen  = "\x1b[32m"
	styleYellow = "\x1b[33m"
	styleBlue   = "\x1b[34m"
	styleCyan   = "\x1b[36m"
)

func (c *cli) style(style, text string) string {
	if !c.color || text == "" {
		return text
	}
	return style + text + styleReset
}

func (c *cli) bold(text string) string { return c.style(styleBold, text) }
func (c *cli) dim(text string) string  { return c.style(styleDim, text) }

// statusWord colours PASS/WARNING/FAIL style words consistently.
func (c *cli) statusWord(status string) string {
	switch strings.ToUpper(status) {
	case "PASS", "OK", "ON", "ONLINE", "RUNNING", "INSTALLED", "DECRYPTED", "ALLOW":
		return c.style(styleGreen, status)
	case "WARNING", "WARN", "UNKNOWN", "MEDIUM", "STOPPED", "BLOCK":
		return c.style(styleYellow, status)
	case "FAIL", "FAILED", "CRITICAL", "HIGH", "OFFLINE", "NOT_INSTALLED":
		return c.style(styleRed, status)
	case "LOW", "INFO":
		return c.style(styleCyan, status)
	default:
		return status
	}
}

func (c *cli) printf(format string, args ...any) { fmt.Fprintf(c.stdout, format, args...) }
func (c *cli) println(args ...any)               { fmt.Fprintln(c.stdout, args...) }

// printJSON writes a value as indented JSON for scripts.
func (c *cli) printJSON(value any) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(c.stdout, string(encoded))
	return err
}

// printCompactJSON writes one value per line (JSON Lines) for streams.
func (c *cli) printCompactJSON(value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(c.stdout, string(encoded))
	return err
}

// printRawJSON re-indents a server response without losing unknown fields.
func (c *cli) printRawJSON(raw []byte) error {
	var buffer bytes.Buffer
	if err := json.Indent(&buffer, bytes.TrimSpace(raw), "", "  "); err != nil {
		_, writeErr := c.stdout.Write(raw)
		return writeErr
	}
	buffer.WriteByte('\n')
	_, err := c.stdout.Write(buffer.Bytes())
	return err
}

// table renders aligned columns. Widths are measured on visible text so
// coloured cells stay aligned.
type table struct {
	headers []string
	rows    [][]string
	max     int
}

func newTable(headers ...string) *table { return &table{headers: headers, max: 48} }

func (t *table) add(cells ...string) { t.rows = append(t.rows, cells) }

func (t *table) render(w io.Writer, c *cli) {
	widths := make([]int, len(t.headers))
	cells := make([][]string, len(t.rows))
	for index, header := range t.headers {
		widths[index] = visibleWidth(header)
	}
	for rowIndex, row := range t.rows {
		cells[rowIndex] = make([]string, len(t.headers))
		for index := range t.headers {
			value := ""
			if index < len(row) {
				value = truncate(row[index], t.max)
			}
			cells[rowIndex][index] = value
			if width := visibleWidth(value); width > widths[index] {
				widths[index] = width
			}
		}
	}
	writeRow := func(values []string, header bool) {
		var line strings.Builder
		line.WriteString("  ")
		for index, value := range values {
			if header {
				value = c.dim(value)
			}
			line.WriteString(value)
			if index < len(values)-1 {
				line.WriteString(strings.Repeat(" ", widths[index]-visibleWidth(value)+2))
			}
		}
		fmt.Fprintln(w, strings.TrimRight(line.String(), " "))
	}
	writeRow(t.headers, true)
	for _, row := range cells {
		writeRow(row, false)
	}
}

func visibleWidth(value string) int {
	width := 0
	for index := 0; index < len(value); {
		if value[index] == 0x1b {
			end := strings.IndexByte(value[index:], 'm')
			if end < 0 {
				break
			}
			index += end + 1
			continue
		}
		_, size := utf8.DecodeRuneInString(value[index:])
		index += size
		width++
	}
	return width
}

// truncate shortens plain text to maximum visible characters. Styled text is
// returned unchanged because its escape codes cannot be cut safely.
func truncate(value string, maximum int) string {
	if maximum <= 1 || strings.ContainsRune(value, 0x1b) || utf8.RuneCountInString(value) <= maximum {
		return value
	}
	runes := []rune(value)
	return string(runes[:maximum-1]) + "…"
}

// sanitize removes control characters from server-provided text so device
// names or domains observed on the network cannot inject terminal escapes.
func sanitize(value string) string {
	if value == "" {
		return value
	}
	return strings.Map(func(r rune) rune {
		if r == '\t' {
			return ' '
		}
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return -1
		}
		return r
	}, value)
}

func orDash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}

func humanBytes(value int64) string {
	if value < 0 {
		value = 0
	}
	units := []string{"B", "KB", "MB", "GB", "TB"}
	amount := float64(value)
	unit := 0
	for amount >= 1000 && unit < len(units)-1 {
		amount /= 1000
		unit++
	}
	if unit == 0 {
		return fmt.Sprintf("%d B", value)
	}
	if amount >= 100 {
		return fmt.Sprintf("%.0f %s", amount, units[unit])
	}
	return fmt.Sprintf("%.1f %s", amount, units[unit])
}

func humanCount(value int64) string {
	text := strconv.FormatInt(value, 10)
	if len(text) <= 3 {
		return text
	}
	var result strings.Builder
	prefix := len(text) % 3
	if prefix > 0 {
		result.WriteString(text[:prefix])
	}
	for index := prefix; index < len(text); index += 3 {
		if result.Len() > 0 {
			result.WriteByte(',')
		}
		result.WriteString(text[index : index+3])
	}
	return result.String()
}

// invokingUser returns the account that ran `sudo shakerproxy ...`, so files the
// CLI writes for the user (reports, PCAP exports) are not left owned by root.
func invokingUser() (int, int, bool) {
	if os.Geteuid() != 0 {
		return 0, 0, false
	}
	uid, uidErr := strconv.Atoi(os.Getenv("SUDO_UID"))
	gid, gidErr := strconv.Atoi(os.Getenv("SUDO_GID"))
	if uidErr != nil || gidErr != nil || uid <= 0 || gid < 0 {
		return 0, 0, false
	}
	return uid, gid, true
}

// giveToInvokingUser chowns an open file to the sudo user before it is
// published under its final name.
func giveToInvokingUser(file *os.File) error {
	if uid, gid, ok := invokingUser(); ok {
		return file.Chown(uid, gid)
	}
	return nil
}

func parseTime(value string) (time.Time, bool) {
	if value == "" {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, false
	}
	return parsed, true
}

// humanAgo renders a timestamp relative to now ("5m ago").
func humanAgo(now time.Time, value string) string {
	parsed, ok := parseTime(value)
	if !ok {
		return "-"
	}
	return humanAgoTime(now, parsed)
}

func humanAgoTime(now, parsed time.Time) string {
	if parsed.IsZero() {
		return "-"
	}
	elapsed := now.Sub(parsed)
	switch {
	case elapsed < 0:
		return "just now"
	case elapsed < time.Minute:
		return "just now"
	case elapsed < time.Hour:
		return fmt.Sprintf("%dm ago", int(elapsed/time.Minute))
	case elapsed < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(elapsed/time.Hour))
	default:
		return fmt.Sprintf("%dd ago", int(elapsed/(24*time.Hour)))
	}
}

func humanDuration(value time.Duration) string {
	if value < 0 {
		value = 0
	}
	switch {
	case value < time.Minute:
		return fmt.Sprintf("%ds", int(value/time.Second))
	case value < time.Hour:
		return fmt.Sprintf("%dm", int(value/time.Minute))
	case value < 48*time.Hour:
		return fmt.Sprintf("%dh %dm", int(value/time.Hour), int(value%time.Hour/time.Minute))
	default:
		return fmt.Sprintf("%dd %dh", int(value/(24*time.Hour)), int(value%(24*time.Hour)/time.Hour))
	}
}

// shortTime formats an RFC 3339 timestamp in local time for tables.
func shortTime(value string) string {
	parsed, ok := parseTime(value)
	if !ok {
		return orDash(value)
	}
	return parsed.Local().Format("2006-01-02 15:04")
}

func clockTime(value string) string {
	parsed, ok := parseTime(value)
	if !ok {
		return "--:--:--"
	}
	return parsed.Local().Format("15:04:05")
}

func plural(count int, singular, pluralForm string) string {
	if count == 1 {
		return fmt.Sprintf("%d %s", count, singular)
	}
	return fmt.Sprintf("%d %s", count, pluralForm)
}

func joinLimited(values []string, limit int) string {
	if len(values) == 0 {
		return "-"
	}
	cleaned := make([]string, 0, len(values))
	for _, value := range values {
		cleaned = append(cleaned, sanitize(value))
	}
	if limit > 0 && len(cleaned) > limit {
		return strings.Join(cleaned[:limit], ", ") + fmt.Sprintf(" (+%d)", len(cleaned)-limit)
	}
	return strings.Join(cleaned, ", ")
}
