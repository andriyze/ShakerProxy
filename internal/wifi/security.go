package wifi

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Security names a network's protection as a beacon or probe response
// advertises it.
const (
	SecurityOpen             = "open"
	SecurityEnhancedOpen     = "enhanced-open"
	SecurityWEP              = "wep"
	SecurityWPA              = "wpa"
	SecurityWPA2Personal     = "wpa2-personal"
	SecurityWPA3Personal     = "wpa3-personal"
	SecurityWPA2WPA3Personal = "wpa2-wpa3-personal"
	SecurityWPA2Enterprise   = "wpa2-enterprise"
	SecurityWPA3Enterprise   = "wpa3-enterprise"
	capabilityPrivacy        = 0x0010
	rsnCapabilityMFPRequired = 0x0040
	rsnCapabilityMFPCapable  = 0x0080
)

var ieee80211OUI = []byte{0x00, 0x0f, 0xac}
var microsoftOUI = []byte{0x00, 0x50, 0xf2}

// RSN is what a network's RSN element says about it.
type RSN struct {
	AKMs        []uint8
	MFPRequired bool
	MFPCapable  bool
}

// ParseRSN reads the version, cipher suites, AKM suites and capabilities of
// an RSN element. It returns false for a malformed element.
func ParseRSN(data []byte) (RSN, bool) {
	if len(data) < 2 || binary.LittleEndian.Uint16(data[0:2]) != 1 {
		return RSN{}, false
	}
	data = data[2:]
	if len(data) < 4 {
		return RSN{}, true
	}
	data = data[4:] // group data cipher
	if len(data) < 2 {
		return RSN{}, true
	}
	pairwise := int(binary.LittleEndian.Uint16(data[0:2]))
	if pairwise > 16 || len(data) < 2+4*pairwise {
		return RSN{}, false
	}
	data = data[2+4*pairwise:]
	if len(data) < 2 {
		return RSN{}, true
	}
	count := int(binary.LittleEndian.Uint16(data[0:2]))
	if count > 16 || len(data) < 2+4*count {
		return RSN{}, false
	}
	result := RSN{}
	for index := 0; index < count; index++ {
		suite := data[2+4*index : 6+4*index]
		if bytes.Equal(suite[:3], ieee80211OUI) {
			result.AKMs = append(result.AKMs, suite[3])
		}
	}
	data = data[2+4*count:]
	if len(data) >= 2 {
		capabilities := binary.LittleEndian.Uint16(data[0:2])
		result.MFPRequired = capabilities&rsnCapabilityMFPRequired != 0
		result.MFPCapable = capabilities&rsnCapabilityMFPCapable != 0
	}
	return result, true
}

// NetworkSecurity is the protection a beacon or probe response advertises.
func (m Management) NetworkSecurity() string {
	if raw, ok := m.Element(ElementRSN); ok {
		if rsn, valid := ParseRSN(raw); valid {
			personal2, personal3, enterprise2, enterprise3, owe := false, false, false, false, false
			for _, akm := range rsn.AKMs {
				switch akm {
				case 2, 4, 6:
					personal2 = true
				case 8, 9, 24, 25:
					personal3 = true
				case 1, 3, 5:
					enterprise2 = true
				case 11, 12, 13:
					enterprise3 = true
				case 18:
					owe = true
				}
			}
			switch {
			case personal2 && personal3:
				return SecurityWPA2WPA3Personal
			case personal3:
				return SecurityWPA3Personal
			case personal2:
				return SecurityWPA2Personal
			case enterprise3 || enterprise2 && rsn.MFPRequired:
				return SecurityWPA3Enterprise
			case enterprise2:
				return SecurityWPA2Enterprise
			case owe:
				return SecurityEnhancedOpen
			}
		}
	}
	for _, element := range m.Elements {
		if element.ID == ElementVendor && len(element.Data) >= 4 && bytes.Equal(element.Data[:3], microsoftOUI) && element.Data[3] == 1 {
			return SecurityWPA
		}
	}
	if m.Capability&capabilityPrivacy != 0 {
		return SecurityWEP
	}
	return SecurityOpen
}

// AuthAlgorithmName names an authentication algorithm number.
func AuthAlgorithmName(algorithm uint16) string {
	switch algorithm {
	case 0:
		return "open"
	case 1:
		return "shared-key"
	case 2:
		return "fast-transition"
	case 3:
		return "sae"
	case 4, 5, 6:
		return "fils"
	case 8:
		return "pasn"
	}
	return fmt.Sprintf("algorithm-%d", algorithm)
}

// authComplete reports the authentication frame that finishes an exchange
// from the access point's side: open and FT finish at sequence 2, shared
// key at 4, SAE with the confirm (2).
func authComplete(algorithm, sequence uint16) bool {
	switch algorithm {
	case 1:
		return sequence == 4
	default:
		return sequence == 2
	}
}

// reasonText is the IEEE 802.11 reason code table, for the codes devices
// and access points actually send.
var reasonText = map[uint16]string{
	1:  "unspecified reason",
	2:  "previous authentication no longer valid",
	3:  "station is leaving (or has left)",
	4:  "disassociated due to inactivity",
	5:  "access point is unable to handle all associated stations",
	6:  "class 2 frame received from a non-authenticated station",
	7:  "class 3 frame received from a non-associated station",
	8:  "station is leaving the network (roaming or turning Wi-Fi off)",
	9:  "station requesting association is not authenticated",
	10: "power capability unacceptable",
	11: "supported channels unacceptable",
	12: "BSS transition (steered to another access point)",
	13: "invalid element",
	14: "message integrity check failure",
	15: "4-way handshake timeout (often a wrong password)",
	16: "group key handshake timeout",
	17: "element in the 4-way handshake differs",
	18: "invalid group cipher",
	19: "invalid pairwise cipher",
	20: "invalid AKM",
	21: "unsupported RSN version",
	22: "invalid RSN capabilities",
	23: "IEEE 802.1X authentication failed",
	24: "cipher suite rejected by security policy",
	25: "TDLS teardown: peer unreachable",
	26: "TDLS teardown: unspecified",
	32: "unspecified QoS reason",
	33: "QoS access point lacks bandwidth",
	34: "too many unacknowledged frames (poor channel conditions)",
	35: "station transmitting outside its TXOPs",
	36: "station leaving the BSS or resetting",
	39: "requested timeout",
	45: "peer does not support the cipher",
	46: "authorized access limit reached",
	47: "external service requirements",
	48: "invalid FT action frame count",
	49: "invalid PMKID",
	50: "invalid MDE",
	51: "invalid FTE",
	66: "mesh channel switch",
}

// ReasonText describes a deauthentication or disassociation reason code.
func ReasonText(code uint16) string {
	if text, ok := reasonText[code]; ok {
		return text
	}
	return fmt.Sprintf("reason %d", code)
}

var statusText = map[uint16]string{
	0:   "success",
	1:   "unspecified failure",
	10:  "cannot support all requested capabilities",
	11:  "reassociation denied: no association exists",
	12:  "denied for a reason outside the standard",
	13:  "authentication algorithm not supported",
	14:  "authentication transaction sequence out of order",
	15:  "challenge failure",
	16:  "authentication timeout",
	17:  "access point is full",
	18:  "basic rates not supported",
	30:  "rejected temporarily; try again later",
	31:  "robust management frame policy violation",
	37:  "request declined",
	40:  "invalid element",
	41:  "invalid group cipher",
	42:  "invalid pairwise cipher",
	43:  "invalid AKM",
	45:  "cipher suite rejected",
	53:  "invalid PMKID",
	72:  "SAE: unknown password identifier",
	76:  "anti-clogging token required",
	77:  "finite cyclic group not supported",
	82:  "rejected with a suggested BSS transition",
	93:  "denied: not authorized in this location",
	126: "SAE hash-to-element required",
}

// StatusText describes an authentication or association status code.
func StatusText(code uint16) string {
	if text, ok := statusText[code]; ok {
		return text
	}
	return fmt.Sprintf("status %d", code)
}
