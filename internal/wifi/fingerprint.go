package wifi

import (
	"crypto/sha256"
	"encoding/hex"
)

// Fingerprint summarizes what a device's probe or association request says
// about its radio, independent of the address it uses: which elements it
// sends, in which order, and its rate, HT, VHT and extended capabilities.
// Devices of the same model and OS version usually share a fingerprint, so a
// match is a hint, never proof. Returns "" for frames with too little to go
// on.
func (m Management) Fingerprint() string {
	if m.Protected || len(m.Elements) < 3 {
		return ""
	}
	hash := sha256.New()
	hash.Write([]byte{m.Subtype &^ 0x2}) // association and reassociation requests match
	for _, element := range m.Elements {
		switch element.ID {
		case ElementSSID, ElementDSParameter:
			// The network asked for and the channel change per frame.
			hash.Write([]byte{element.ID})
		case ElementSupportedRates, ElementExtendedRates, ElementHTCapabilities, ElementExtCapability, ElementVHTCapability:
			hash.Write([]byte{element.ID, byte(len(element.Data))})
			data := element.Data
			if element.ID == ElementHTCapabilities && len(data) > 2 {
				data = data[:2]
			}
			if element.ID == ElementVHTCapability && len(data) > 4 {
				data = data[:4]
			}
			hash.Write(data)
		case ElementVendor:
			hash.Write([]byte{element.ID})
			if len(element.Data) >= 4 {
				hash.Write(element.Data[:4])
			}
		case ElementExtension:
			hash.Write([]byte{element.ID})
			if len(element.Data) >= 1 {
				hash.Write(element.Data[:1])
			}
		default:
			hash.Write([]byte{element.ID})
		}
	}
	return hex.EncodeToString(hash.Sum(nil)[:8])
}
