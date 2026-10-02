package coverage

import "fmt"

// ResultWiFiRadio is the coverage row for Wi-Fi visibility: whether
// ShakerProxy listens on the radio, where the probes cannot reach.
const ResultWiFiRadio = "wifi-radio"

// WiFiRadio is the Wi-Fi monitor's state as gatewayd reports it.
type WiFiRadio struct {
	Unknown       bool
	Enabled       bool
	Active        bool
	Available     bool
	Reason        string
	Adapter       string
	ChannelMode   string
	Channel       int
	WorkerRunning bool
}

// WiFiRadioResult is PASS while the monitor records, and SKIP with the
// reason otherwise. It is not probed: the virtual test lab has no radio.
func WiFiRadioResult(radio WiFiRadio) Result {
	result := Result{ID: ResultWiFiRadio, Name: "Wi-Fi radio", Category: "Wi-Fi", Status: StatusSkip, EventKinds: []string{}}
	switch {
	case radio.Unknown:
		result.Summary = "The gateway did not say whether Wi-Fi visibility runs."
	case radio.Active && radio.WorkerRunning:
		result.Status = StatusPass
		where := fmt.Sprintf("channel %d", radio.Channel)
		if radio.ChannelMode == "hop" {
			where = "hopping across channels"
		}
		result.Summary = fmt.Sprintf("Listening with %s (%s): searching, joining, roaming and disconnects of lab devices are recorded.", radio.Adapter, where)
		result.EventKinds = []string{"wifi.probe", "wifi.auth", "wifi.assoc", "wifi.deauth", "wifi.disassoc", "wifi.beacon_summary"}
		result.AppProtocol = "wifi"
	case radio.Enabled:
		result.Summary = "Wi-Fi visibility is on but not running."
		if radio.Reason != "" {
			result.Summary += " " + radio.Reason
		}
		result.Missing = "Wi-Fi management frames"
	case !radio.Available:
		result.Summary = "Wi-Fi visibility is off. " + radio.Reason
		result.Missing = "Wi-Fi management frames"
	default:
		result.Summary = "Wi-Fi visibility is off; turn it on on the System page or with `shakerproxy wifi on` to see how devices search for and join networks."
		result.Missing = "Wi-Fi management frames"
	}
	return result
}
