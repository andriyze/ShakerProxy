// Package notify turns the appliance's notable moments — a new device, a
// device whose traffic bypasses ShakerProxy, a secret sent in the clear, a
// connection to a flagged domain — into de-duplicated notifications and
// delivers them to the channels a tester has configured (an in-app list, and
// webhooks including Slack-compatible ones).
//
// A notification states what happened and the subject (a device, a host, a
// finding kind). It never carries a secret value: the cleartext finding it is
// built from already keeps only the kind and location, and this package
// carries only that.
package notify

import (
	"errors"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Trigger is the kind of notable moment a rule subscribes to.
type Trigger string

const (
	TriggerNewDevice     Trigger = "NEW_DEVICE"
	TriggerBypassing     Trigger = "BYPASSING_DEVICE"
	TriggerCleartext     Trigger = "CLEARTEXT_EXPOSURE"
	TriggerFlaggedDomain Trigger = "FLAGGED_DOMAIN"
	TriggerSecurityAlert Trigger = "SECURITY_ALERT"
)

// Severity orders notifications so a rule can ask for only the important ones.
type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityWarning  Severity = "WARNING"
	SeverityCritical Severity = "CRITICAL"
)

func (s Severity) rank() int {
	switch s {
	case SeverityCritical:
		return 3
	case SeverityWarning:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// AtLeast reports whether s is at least as severe as minimum.
func (s Severity) AtLeast(minimum Severity) bool { return s.rank() >= minimum.rank() }

// ValidTrigger reports whether value is a known trigger.
func ValidTrigger(value Trigger) bool {
	switch value {
	case TriggerNewDevice, TriggerBypassing, TriggerCleartext, TriggerFlaggedDomain, TriggerSecurityAlert:
		return true
	}
	return false
}

func validSeverity(value Severity) bool {
	switch value {
	case SeverityInfo, SeverityWarning, SeverityCritical:
		return true
	}
	return false
}

// ChannelKind is how a channel delivers.
type ChannelKind string

const (
	// ChannelInApp stores the notification in the appliance's own list.
	ChannelInApp ChannelKind = "IN_APP"
	// ChannelWebhook POSTs a signed JSON body to a URL.
	ChannelWebhook ChannelKind = "WEBHOOK"
	// ChannelSlack POSTs a Slack-compatible incoming-webhook body, which
	// Slack, Mattermost and Discord-compatible endpoints accept.
	ChannelSlack ChannelKind = "SLACK"
)

// Channel is one delivery destination.
type Channel struct {
	ID      string      `json:"id"`
	Kind    ChannelKind `json:"kind"`
	Name    string      `json:"name"`
	Enabled bool        `json:"enabled"`
	// URL is required for WEBHOOK and SLACK; it must be https.
	URL string `json:"url,omitempty"`
	// Secret signs the WEBHOOK body (HMAC-SHA256); optional.
	Secret string `json:"secret,omitempty"`
}

// Rule subscribes a trigger (optionally scoped to one device, and to a minimum
// severity) to one or more channels.
type Rule struct {
	ID          string   `json:"id"`
	Trigger     Trigger  `json:"trigger"`
	DeviceID    string   `json:"device_id,omitempty"`
	MinSeverity Severity `json:"min_severity,omitempty"`
	Channels    []string `json:"channels"`
	Enabled     bool     `json:"enabled"`
}

// ConfigSchema versions the persisted configuration.
const ConfigSchema = 1

// MaxChannels and MaxRules bound the configuration.
const (
	MaxChannels = 32
	MaxRules    = 64
	// DedupWindow is how long the same trigger for the same subject is
	// suppressed after it fires, so a chatty condition is one notification.
	DedupWindow = 10 * time.Minute
)

// Config is the persisted notifications configuration. It is off by default:
// with no enabled rule, nothing is ever delivered.
type Config struct {
	Schema    int       `json:"schema"`
	Revision  int       `json:"revision"`
	UpdatedAt time.Time `json:"updated_at,omitzero"`
	UpdatedBy string    `json:"updated_by,omitempty"`
	Channels  []Channel `json:"channels"`
	Rules     []Rule    `json:"rules"`
}

// DefaultConfig is the empty, inert configuration with only the built-in
// in-app channel present and nothing subscribed.
func DefaultConfig() Config {
	return Config{
		Schema:   ConfigSchema,
		Channels: []Channel{{ID: InAppChannelID, Kind: ChannelInApp, Name: "In-app notifications", Enabled: true}},
		Rules:    nil,
	}
}

// InAppChannelID is the fixed identifier of the always-present in-app channel.
const InAppChannelID = "in-app"

var (
	idPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)
	namePattern = regexp.MustCompile(`^[\x20-\x7e]{1,80}$`)
)

// Validate checks the configuration is well-formed and self-consistent.
func (c Config) Validate() error {
	if c.Schema != ConfigSchema {
		return errors.New("notifications config schema is unsupported")
	}
	if len(c.Channels) > MaxChannels {
		return errors.New("too many channels")
	}
	if len(c.Rules) > MaxRules {
		return errors.New("too many rules")
	}
	known := map[string]ChannelKind{}
	inApp := false
	for _, channel := range c.Channels {
		if !idPattern.MatchString(channel.ID) {
			return errors.New("channel id is invalid")
		}
		if _, seen := known[channel.ID]; seen {
			return errors.New("duplicate channel id")
		}
		if !namePattern.MatchString(channel.Name) {
			return errors.New("channel name is invalid")
		}
		switch channel.Kind {
		case ChannelInApp:
			inApp = true
			if channel.URL != "" || channel.Secret != "" {
				return errors.New("the in-app channel takes no URL")
			}
		case ChannelWebhook, ChannelSlack:
			if err := validateWebhookURL(channel.URL); err != nil {
				return err
			}
			if len(channel.Secret) > 256 {
				return errors.New("channel secret is too long")
			}
		default:
			return errors.New("channel kind is unknown")
		}
		known[channel.ID] = channel.Kind
	}
	if !inApp {
		return errors.New("the in-app channel must be present")
	}
	for _, rule := range c.Rules {
		if !idPattern.MatchString(rule.ID) {
			return errors.New("rule id is invalid")
		}
		if !ValidTrigger(rule.Trigger) {
			return errors.New("rule trigger is unknown")
		}
		if rule.MinSeverity != "" && !validSeverity(rule.MinSeverity) {
			return errors.New("rule severity is unknown")
		}
		if rule.DeviceID != "" && !deviceIDPattern.MatchString(rule.DeviceID) {
			return errors.New("rule device id is invalid")
		}
		if len(rule.Channels) == 0 || len(rule.Channels) > MaxChannels {
			return errors.New("a rule needs between one and MaxChannels channels")
		}
		for _, id := range rule.Channels {
			if _, ok := known[id]; !ok {
				return errors.New("rule names an unknown channel")
			}
		}
	}
	return nil
}

var deviceIDPattern = regexp.MustCompile(`^device-[a-f0-9]{32}$`)

// validateWebhookURL requires a plain https URL. It does not resolve the host;
// delivery resolves it and refuses private, loopback and link-local addresses.
func validateWebhookURL(raw string) error {
	if raw == "" {
		return errors.New("a webhook channel needs a URL")
	}
	if len(raw) > 2048 {
		return errors.New("webhook URL is too long")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return errors.New("webhook URL is invalid")
	}
	if parsed.Scheme != "https" {
		return errors.New("webhook URL must be https")
	}
	if parsed.Host == "" || strings.ContainsAny(raw, " \t\r\n") {
		return errors.New("webhook URL is invalid")
	}
	return nil
}

// Enabled reports whether any rule is enabled, i.e. whether the evaluator has
// anything to do.
func (c Config) Enabled() bool {
	for _, rule := range c.Rules {
		if rule.Enabled {
			return true
		}
	}
	return false
}

// channelByID indexes the enabled channels.
func (c Config) channelByID() map[string]Channel {
	out := make(map[string]Channel, len(c.Channels))
	for _, channel := range c.Channels {
		out[channel.ID] = channel
	}
	return out
}
