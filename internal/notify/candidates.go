package notify

import (
	"fmt"
	"strings"
)

// These constructors keep the wording of every notification in one place and
// make the de-duplication key explicit. None of them takes or carries a
// secret value.

func deviceLabel(name, address string) string {
	switch {
	case name != "" && address != "":
		return name + " · " + address
	case name != "":
		return name
	case address != "":
		return address
	default:
		return "a device"
	}
}

// NewDeviceCandidate fires when a device is first seen on the lab.
func NewDeviceCandidate(deviceID, name, address string) Candidate {
	label := deviceLabel(name, address)
	return Candidate{
		Trigger:  TriggerNewDevice,
		Severity: SeverityInfo,
		Subject:  Subject{DeviceID: deviceID, DeviceName: name, Host: address},
		Title:    "New device on the lab: " + label,
		Body:     label + " joined the lab network.",
		Key:      string(TriggerNewDevice) + "\x00" + deviceID,
	}
}

// BypassingCandidate fires when a device's traffic does not go through
// ShakerProxy.
func BypassingCandidate(deviceID, name, address, reason string) Candidate {
	label := deviceLabel(name, address)
	body := label + "'s traffic does not go through ShakerProxy, so its connections cannot be seen."
	if reason != "" {
		body = strings.TrimSpace(reason)
	}
	return Candidate{
		Trigger:  TriggerBypassing,
		Severity: SeverityWarning,
		Subject:  Subject{DeviceID: deviceID, DeviceName: name, Host: address},
		Title:    "Device bypassing ShakerProxy: " + label,
		Body:     body,
		Key:      string(TriggerBypassing) + "\x00" + deviceID,
	}
}

// CleartextCandidate fires on a cleartext credential/secret exposure. kind is
// the finding kind (e.g. "form-password"); where is a location name (a header
// or field). Neither is a secret value.
func CleartextCandidate(deviceID, name, host, kind, where string) Candidate {
	label := deviceLabel(name, "")
	who := label
	if who == "a device" && deviceID != "" {
		who = "A device"
	}
	target := host
	if target == "" {
		target = "a server"
	}
	detail := "a credential"
	if kind != "" {
		detail = humanKind(kind)
	}
	body := fmt.Sprintf("%s sent %s in the clear to %s.", who, detail, target)
	if where != "" {
		body += " (" + where + ")"
	}
	return Candidate{
		Trigger:  TriggerCleartext,
		Severity: SeverityCritical,
		Subject:  Subject{DeviceID: deviceID, DeviceName: name, Host: host, Kind: kind},
		Title:    "Secret sent in the clear: " + label,
		Body:     body,
		Key:      string(TriggerCleartext) + "\x00" + deviceID + "\x00" + host + "\x00" + kind,
	}
}

// FlaggedDomainCandidate fires when a device contacts a flagged domain.
func FlaggedDomainCandidate(deviceID, name, domain, category string) Candidate {
	label := deviceLabel(name, "")
	who := label
	if who == "a device" {
		who = "A device"
	}
	body := fmt.Sprintf("%s contacted %s", who, domain)
	if category != "" {
		body += " (" + category + ")"
	}
	body += "."
	return Candidate{
		Trigger:  TriggerFlaggedDomain,
		Severity: SeverityWarning,
		Subject:  Subject{DeviceID: deviceID, DeviceName: name, Host: domain, Kind: category},
		Title:    "Flagged domain: " + domain,
		Body:     body,
		Key:      string(TriggerFlaggedDomain) + "\x00" + deviceID + "\x00" + domain,
	}
}

// SecurityAlertCandidate fires on a Suricata alert or native detection other
// than cleartext. summary is a bounded, secret-free description.
func SecurityAlertCandidate(deviceID, name, kind, summary string, severity Severity) Candidate {
	label := deviceLabel(name, "")
	if severity == "" {
		severity = SeverityWarning
	}
	title := "Security alert"
	if summary != "" {
		title = "Security alert: " + summary
	}
	body := summary
	if label != "a device" {
		body = strings.TrimSpace(summary + " (" + label + ")")
	}
	return Candidate{
		Trigger:  TriggerSecurityAlert,
		Severity: severity,
		Subject:  Subject{DeviceID: deviceID, DeviceName: name, Kind: kind},
		Title:    title,
		Body:     body,
		Key:      string(TriggerSecurityAlert) + "\x00" + deviceID + "\x00" + kind,
	}
}

// TestCandidate is the notification a "send test" produces.
func TestCandidate() Candidate {
	return Candidate{
		Trigger:  TriggerSecurityAlert,
		Severity: SeverityInfo,
		Title:    "Test notification",
		Body:     "This is a test from ShakerProxy. Notifications are working.",
		Key:      "TEST",
	}
}

func humanKind(kind string) string {
	switch kind {
	case "basic-auth":
		return "an HTTP Basic auth credential"
	case "bearer-token":
		return "a sign-in token"
	case "form-password":
		return "a password"
	case "url-credential", "token-in-url":
		return "a token in the URL"
	case "cleartext-cookie":
		return "a session cookie"
	default:
		return "a credential (" + kind + ")"
	}
}
