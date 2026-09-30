package server

import (
	"context"
	"errors"
	"net/http"
	"os"
	"time"

	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/interceptionpki"
)

type onboardingURL struct {
	Label string `json:"label"`
	URL   string `json:"url"`
}

type interceptionOnboarding struct {
	Schema            int                                    `json:"schema"`
	Available         bool                                   `json:"available"`
	Reason            string                                 `json:"reason"`
	SHA256Fingerprint string                                 `json:"sha256_fingerprint"`
	CommonName        string                                 `json:"common_name"`
	NotAfter          string                                 `json:"not_after"`
	URLs              []onboardingURL                        `json:"urls"`
	Instructions      []interceptionpki.PlatformInstructions `json:"instructions"`
}

// interceptionCAOnboarding tells an admin (UI, CLI) where lab devices can get
// the CA and how to install it on each platform. It is a status resource:
// when the lab page is not reachable, available is false and reason says
// what to do next.
func (s *Server) interceptionCAOnboarding(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" {
		writeError(w, http.StatusBadRequest, "invalid_query", "Interception CA onboarding does not accept query parameters.")
		return
	}
	response := interceptionOnboarding{Schema: 1, URLs: []onboardingURL{}}
	certificate, err := interceptionpki.LoadPublicCertificate(interceptionPublicRoot())
	switch {
	case errors.Is(err, os.ErrNotExist):
		response.Reason = "ShakerProxy has not created its interception certificate yet. Run `sudo systemctl restart shakerproxy-interception-pki`, then reload."
	case err != nil:
		response.Reason = "The interception certificate could not be read. Check `sudo systemctl status shakerproxy-interception-pki`."
	default:
		response.SHA256Fingerprint = interceptionpki.FormatFingerprint(certificate)
		response.CommonName = certificate.Subject.CommonName
		response.NotAfter = certificate.NotAfter.UTC().Format(time.RFC3339)
		response.Reason = s.onboardingPageStatus(r.Context(), &response)
		response.Available = response.Reason == ""
	}
	pageURL := ""
	if len(response.URLs) != 0 {
		pageURL = response.URLs[0].URL
	}
	response.Instructions = interceptionpki.OnboardingInstructions(pageURL)
	writeJSON(w, http.StatusOK, response)
}

// onboardingPageStatus fills the lab-side URLs and returns "" when the page
// is published, otherwise the next step for the admin.
func (s *Server) onboardingPageStatus(ctx context.Context, response *interceptionOnboarding) string {
	var lab gatewayprotocol.LabOnboarding
	if err := s.gateway.Call(ctx, "GetLabOnboarding", gatewayprotocol.EmptyParams{}, &lab); err != nil {
		return "ShakerProxy's gateway service is not reachable, so the lab address is unknown. Check `sudo systemctl status shakerproxy-gatewayd`."
	}
	switch {
	case !lab.Routed || lab.GatewayIPv4 == "":
		return "Apply a routed network plan first (Network → Apply) so lab devices can reach ShakerProxy."
	case lab.FleetManaged:
		return "Interception on this appliance is managed by ShakerProxy Fleet, which does not publish the lab onboarding page. Download the certificate from System → Interception CA instead."
	case lab.EmergencyBypass:
		return "Emergency bypass is on, so ShakerProxy is not intercepting and the onboarding page is closed. Turn emergency bypass off first."
	case !lab.InterceptionConfigured:
		return "Turn on Decrypt HTTPS for a device first; the onboarding page opens on the lab network while decryption is on."
	case !lab.Published:
		return "Decryption is configured but not active, usually because the interception service is not running. Check it with `sudo shakerproxy app status`; an appliance installed with --profile standard has no decryption service."
	}
	response.URLs = append(response.URLs, onboardingURL{Label: "Lab network", URL: "http://" + lab.GatewayIPv4 + "/"})
	if lab.GatewayIPv6 != "" {
		response.URLs = append(response.URLs, onboardingURL{Label: "Lab network (IPv6)", URL: "http://[" + lab.GatewayIPv6 + "]/"})
	}
	return ""
}
