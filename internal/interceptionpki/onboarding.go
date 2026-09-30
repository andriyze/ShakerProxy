package interceptionpki

import (
	"bytes"
	"crypto/md5" // #nosec G501 -- OpenSSL subject_hash_old is defined as MD5; not a security use.
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// PlatformInstructions are the device-side steps shown on the lab onboarding
// page and returned by the admin onboarding API.
type PlatformInstructions struct {
	Platform    string   `json:"platform"`
	Title       string   `json:"title"`
	Steps       []string `json:"steps"`
	Limitations []string `json:"limitations"`
}

// Onboarding file names served on the lab network.
const (
	OnboardingPEMPath          = "/shakerproxy-ca.pem"
	OnboardingDERPath          = "/shakerproxy-ca.crt"
	OnboardingMobileConfigPath = "/shakerproxy-ca.mobileconfig"
	OnboardingAndroidPath      = "/shakerproxy-ca-android.0"
)

// LoadPublicCertificate reads and parses the public interception CA.
func LoadPublicCertificate(publicRoot string) (*x509.Certificate, error) {
	data, err := os.ReadFile(filepath.Join(publicRoot, "interception-ca.pem"))
	if err != nil {
		return nil, err
	}
	if len(data) > 64<<10 {
		return nil, errors.New("interception CA certificate exceeds maximum size")
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("interception CA certificate is not PEM")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	if !certificate.IsCA {
		return nil, errors.New("interception certificate is not a CA")
	}
	return certificate, nil
}

// CertificatePEM encodes only the public certificate.
func CertificatePEM(certificate *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
}

// FormatFingerprint renders a SHA-256 fingerprint as upper-case colon pairs,
// the form most certificate viewers display.
func FormatFingerprint(certificate *x509.Certificate) string {
	digest := sha256.Sum256(certificate.Raw)
	encoded := strings.ToUpper(hex.EncodeToString(digest[:]))
	pairs := make([]string, 0, len(encoded)/2)
	for index := 0; index < len(encoded); index += 2 {
		pairs = append(pairs, encoded[index:index+2])
	}
	return strings.Join(pairs, ":")
}

// SubjectHashOld reproduces `openssl x509 -subject_hash_old`, the file name
// Android uses for certificates in its system store.
func SubjectHashOld(certificate *x509.Certificate) string {
	digest := md5.Sum(certificate.RawSubject) // #nosec G401 -- file naming only
	return fmt.Sprintf("%08x", binary.LittleEndian.Uint32(digest[:4]))
}

// AndroidSystemStoreFile is the PEM body for /system/etc/security/cacerts.
func AndroidSystemStoreFile(certificate *x509.Certificate) []byte {
	return CertificatePEM(certificate)
}

// MobileConfig returns an unsigned iOS/iPadOS/macOS configuration profile
// that installs the certificate as a trusted root payload. Payload UUIDs are
// derived from the certificate so re-downloads replace the same profile.
func MobileConfig(certificate *x509.Certificate) []byte {
	digest := sha256.Sum256(certificate.Raw)
	identifier := "dev.shakerproxy.interception-ca." + hex.EncodeToString(digest[:8])
	name := certificate.Subject.CommonName
	if name == "" {
		name = "ShakerProxy Interception CA"
	}
	var buffer bytes.Buffer
	escape := func(value string) string {
		var escaped bytes.Buffer
		_ = xml.EscapeText(&escaped, []byte(value))
		return escaped.String()
	}
	fmt.Fprintf(&buffer, `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>PayloadCertificateFileName</key>
			<string>shakerproxy-ca.cer</string>
			<key>PayloadContent</key>
			<data>%s</data>
			<key>PayloadDescription</key>
			<string>Lets ShakerProxy decrypt this device's HTTPS for testing.</string>
			<key>PayloadDisplayName</key>
			<string>%s</string>
			<key>PayloadIdentifier</key>
			<string>%s.certificate</string>
			<key>PayloadType</key>
			<string>com.apple.security.root</string>
			<key>PayloadUUID</key>
			<string>%s</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>
	</array>
	<key>PayloadDescription</key>
	<string>Installs the ShakerProxy interception certificate authority for HTTPS testing. Remove this profile when testing is finished.</string>
	<key>PayloadDisplayName</key>
	<string>%s</string>
	<key>PayloadIdentifier</key>
	<string>%s</string>
	<key>PayloadOrganization</key>
	<string>ShakerProxy</string>
	<key>PayloadRemovalDisallowed</key>
	<false/>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>%s</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
</dict>
</plist>
`, base64.StdEncoding.EncodeToString(certificate.Raw), escape(name), identifier, derivedUUID(digest[:], 1), escape(name), identifier, derivedUUID(digest[:], 2))
	return buffer.Bytes()
}

func derivedUUID(seed []byte, variant byte) string {
	input := append(append([]byte(nil), seed...), variant)
	digest := sha256.Sum256(input)
	value := digest[:16]
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	return fmt.Sprintf("%X-%X-%X-%X-%X", value[0:4], value[4:6], value[6:8], value[8:10], value[10:16])
}

// OnboardingInstructions returns accurate per-platform steps. pageURL is the
// lab-side onboarding page (for example http://10.77.0.1/); when empty, a
// placeholder tells the reader where to find it.
func OnboardingInstructions(pageURL string) []PlatformInstructions {
	if pageURL == "" {
		pageURL = "http://<ShakerProxy lab address>/"
	}
	check := "Check that the fingerprint shown on the page matches the one in ShakerProxy (System → Interception CA) before trusting it; the page is plain HTTP on your lab network."
	return []PlatformInstructions{
		{
			Platform: "ios",
			Title:    "iPhone / iPad",
			Steps: []string{
				"Connect the iPhone or iPad to the ShakerProxy lab network.",
				"Open " + pageURL + " in Safari (other browsers cannot install profiles) and tap \"iPhone / iPad profile\". Tap Allow to download it.",
				"Open Settings → General → VPN & Device Management (or tap \"Profile Downloaded\" at the top of Settings), choose \"ShakerProxy Interception CA\", tap Install and enter the passcode.",
				"Open Settings → General → About → Certificate Trust Settings and turn on full trust for \"ShakerProxy Interception CA\". Without this step iOS installs the profile but does not trust it for HTTPS.",
				"In ShakerProxy, turn on Decrypt HTTPS for the device.",
				check,
			},
			Limitations: []string{
				"Apps that pin certificates (many banking apps and Apple services such as the App Store, iCloud and push notifications) refuse the connection; ShakerProxy reports them as probable pinning and passes them through.",
				"Remove the profile after testing: Settings → General → VPN & Device Management → ShakerProxy Interception CA → Remove Profile.",
			},
		},
		{
			Platform: "android",
			Title:    "Android phone or tablet",
			Steps: []string{
				"Connect the device to the ShakerProxy lab network.",
				"Open " + pageURL + " in Chrome and tap \"Android / Windows certificate (.crt)\" to download it.",
				"Open Settings, search for \"CA certificate\" (usually Security & privacy → More security settings → Encryption & credentials → Install a certificate → CA certificate), tap Install anyway and pick the downloaded file.",
				"Check that it is listed under Trusted credentials → User.",
				"In ShakerProxy, turn on Decrypt HTTPS for the device.",
				check,
			},
			Limitations: []string{
				"Since Android 7, apps ignore user-installed CAs unless the app opts in through its network security configuration. Expect most app traffic to be passed through or reported as pinning; Chrome and debuggable builds do trust it.",
				"To decrypt apps, use a debuggable build of the app, or an emulator or rooted device with the certificate in the system store: copy shakerproxy-ca-android.0 from the page to /system/etc/security/cacerts/ with mode 644 and reboot (Android 14 and later read system CAs from the Conscrypt APEX module and need an emulator image or module that supports this).",
				"If apps cannot be decrypted, run the certificate validation test instead: leave the CA uninstalled and turn on Decrypt HTTPS; any connection that still works means the app accepts untrusted certificates.",
				"Android may show \"Network may be monitored\" while the CA is installed. Remove it afterwards under Trusted credentials → User.",
			},
		},
		{
			Platform: "android-tv",
			Title:    "Android TV / Google TV",
			Steps: []string{
				"Leave the CA uninstalled: most Android TV and Google TV devices have no screen for installing CAs, and their apps ignore user CAs anyway.",
				"Run the certificate validation test: turn on Decrypt HTTPS for the TV in ShakerProxy and use its apps.",
				"Connections that keep working through ShakerProxy are flagged as \"accepts untrusted certificates\", a real vulnerability. Connections that fail show as TLS failures, which is the correct behaviour.",
			},
			Limitations: []string{
				"To actually decrypt TV apps you need an emulator or rooted device with the certificate in the system store (shakerproxy-ca-android.0).",
			},
		},
		{
			Platform: "smart-tv",
			Title:    "Smart TVs, streaming sticks, cameras and other IoT devices",
			Steps: []string{
				"These devices cannot install custom CAs, so run the certificate validation test: turn on Decrypt HTTPS for the device in ShakerProxy without installing anything on it.",
				"Use the device normally. Anything that still works through ShakerProxy means the device does not validate certificates, which ShakerProxy reports as a finding.",
				"Use Block internet or Block domain in ShakerProxy to see how the device behaves offline.",
			},
			Limitations: []string{
				"Devices that validate certificates correctly will show TLS failures while decryption is on; turn decryption off or bypass the host to restore them.",
			},
		},
		{
			Platform: "macos",
			Title:    "Mac",
			Steps: []string{
				"Open " + pageURL + " and download the PEM certificate.",
				"Double-click the file. Keychain Access opens; add it to the System keychain.",
				"In Keychain Access double-click \"ShakerProxy Interception CA\", expand Trust, set \"When using this certificate\" to Always Trust, close the window and enter your password.",
				"Or in Terminal: sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain shakerproxy-ca.pem",
				check,
			},
			Limitations: []string{
				"Firefox uses its own certificate store unless security.enterprise_roots.enabled is on.",
				"Apps that pin certificates, and some Apple services, still refuse the connection.",
			},
		},
		{
			Platform: "windows",
			Title:    "Windows",
			Steps: []string{
				"Open " + pageURL + " and download \"Android / Windows certificate (.crt)\".",
				"Double-click the file, choose Install Certificate → Local Machine → Place all certificates in the following store → Trusted Root Certification Authorities, then Finish.",
				"Or in an administrator terminal: certutil -addstore -f Root shakerproxy-ca.crt",
				check,
			},
			Limitations: []string{
				"Firefox uses its own store unless security.enterprise_roots.enabled is on; Java applications use their own truststore.",
				"Apps that pin certificates still refuse the connection.",
			},
		},
		{
			Platform: "linux",
			Title:    "Linux",
			Steps: []string{
				"Download the PEM certificate from " + pageURL + ".",
				"Debian or Ubuntu: sudo cp shakerproxy-ca.pem /usr/local/share/ca-certificates/shakerproxy-ca.crt && sudo update-ca-certificates",
				"Fedora or RHEL: sudo cp shakerproxy-ca.pem /etc/pki/ca-trust/source/anchors/ && sudo update-ca-trust",
				check,
			},
			Limitations: []string{
				"Firefox and Chrome on Linux use their own NSS databases: import the certificate in the browser's settings.",
				"Language runtimes may bring their own bundle: set REQUESTS_CA_BUNDLE for Python requests and NODE_EXTRA_CA_CERTS for Node.js.",
			},
		},
		{
			Platform: "other",
			Title:    "Anything else",
			Steps: []string{
				"If the device can install a CA, download the PEM or DER certificate from " + pageURL + " and install it as a trusted root.",
				"If it cannot, run the certificate validation test: turn on Decrypt HTTPS without installing the CA; anything that still works means the device accepts untrusted certificates.",
			},
			Limitations: []string{
				"Certificate pinning, mutual TLS, QUIC-only apps and VPNs cannot be decrypted; ShakerProxy reports them and passes them through.",
			},
		},
	}
}
