package notify

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"time"
)

// Subject identifies what a notification is about, for display and for
// de-duplication. It holds no secret: Host is a destination name, Kind a
// finding kind, never a credential value.
type Subject struct {
	DeviceID   string `json:"device_id,omitempty"`
	DeviceName string `json:"device_name,omitempty"`
	Host       string `json:"host,omitempty"`
	Kind       string `json:"kind,omitempty"`
}

// Candidate is one notable moment the evaluator may turn into notifications.
// Key identifies the subject for de-duplication, independent of any rule.
type Candidate struct {
	Trigger  Trigger
	Severity Severity
	Subject  Subject
	Title    string
	Body     string
	Key      string
}

// Notification is the delivered record. It is also what the in-app list and
// the webhook body are built from.
type Notification struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	Trigger   Trigger   `json:"trigger"`
	Severity  Severity  `json:"severity"`
	Title     string    `json:"title"`
	Body      string    `json:"body"`
	Subject   Subject   `json:"subject"`
	// Channels are the channel IDs this notification is to be delivered to.
	Channels []string `json:"channels,omitempty"`
	// Read is for the in-app list; it is false when first stored.
	Read bool `json:"read"`
}

// matches reports whether a rule subscribes to a candidate.
func (r Rule) matches(candidate Candidate) bool {
	if !r.Enabled || r.Trigger != candidate.Trigger {
		return false
	}
	if r.DeviceID != "" && r.DeviceID != candidate.Subject.DeviceID {
		return false
	}
	minimum := r.MinSeverity
	if minimum == "" {
		minimum = SeverityInfo
	}
	return candidate.Severity.AtLeast(minimum)
}

// Evaluate turns candidates into notifications for the matching enabled rules,
// suppressing a trigger+subject that already fired within the window. It is
// pure: it returns the notifications to deliver and the updated fired-at map,
// and never mutates its inputs. lastFired maps a trigger+subject+rule key to
// when it last fired.
//
// idFor derives a stable notification id from the candidate key and now, so
// the same call is deterministic in tests.
func Evaluate(candidates []Candidate, config Config, lastFired map[string]time.Time, now time.Time) ([]Notification, map[string]time.Time) {
	updated := make(map[string]time.Time, len(lastFired))
	for key, when := range lastFired {
		// Drop entries older than twice the window so the map stays bounded.
		if now.Sub(when) <= 2*DedupWindow {
			updated[key] = when
		}
	}
	// Collect, per candidate subject, the union of channels from the rules
	// that newly fire for it, so one subject is one notification even when
	// several rules match.
	type pending struct {
		candidate Candidate
		channels  map[string]struct{}
	}
	bySubject := map[string]*pending{}
	order := []string{}
	for _, candidate := range candidates {
		for _, rule := range config.Rules {
			if !rule.matches(candidate) {
				continue
			}
			fireKey := rule.ID + "\x00" + candidate.Key
			if previous, ok := updated[fireKey]; ok && now.Sub(previous) < DedupWindow {
				continue
			}
			updated[fireKey] = now
			entry := bySubject[candidate.Key]
			if entry == nil {
				entry = &pending{candidate: candidate, channels: map[string]struct{}{}}
				bySubject[candidate.Key] = entry
				order = append(order, candidate.Key)
			}
			for _, id := range rule.Channels {
				entry.channels[id] = struct{}{}
			}
		}
	}
	var notifications []Notification
	for _, key := range order {
		entry := bySubject[key]
		channels := make([]string, 0, len(entry.channels))
		for id := range entry.channels {
			channels = append(channels, id)
		}
		sort.Strings(channels)
		notifications = append(notifications, Notification{
			ID:        idFor(key, now),
			CreatedAt: now.UTC(),
			Trigger:   entry.candidate.Trigger,
			Severity:  entry.candidate.Severity,
			Title:     entry.candidate.Title,
			Body:      entry.candidate.Body,
			Subject:   entry.candidate.Subject,
			Channels:  channels,
		})
	}
	return notifications, updated
}

func idFor(key string, now time.Time) string {
	sum := sha256.Sum256([]byte(now.UTC().Format(time.RFC3339Nano) + "\x00" + key))
	return "ntf-" + hex.EncodeToString(sum[:12])
}
