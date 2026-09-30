package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"shakerproxy.dev/shakerproxy/internal/apitoken"
	"shakerproxy.dev/shakerproxy/internal/gatewayclient"
	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/interceptionpki"
	deviceinventory "shakerproxy.dev/shakerproxy/internal/inventory"
	"shakerproxy.dev/shakerproxy/internal/trafficpolicy"
)

// labControlsMu serializes read-modify-apply cycles of the traffic policy
// made by the device controls and bypass endpoints, so two quick clicks do
// not race each other into a revision conflict.
var labControlsMu sync.Mutex

// registerLabControlRoutes adds the device lab controls (contract §6), the
// one-click TLS bypass and the CA onboarding status (contract §7). Changes
// accept a session or a lab:write token (contract §6/§9) and need no
// password: they decrypt or block individual devices, and a bypass only ever
// reduces decryption. Turning on decryption for every lab client stays on
// PUT /api/v1/traffic-policy with its password tier.
func (s *Server) registerLabControlRoutes(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/devices/{deviceID}/controls", s.requireAuthOrScope(apitoken.ScopeDevicesRead, http.HandlerFunc(s.getDeviceControls)))
	mux.Handle("PUT /api/v1/devices/{deviceID}/controls", s.requireLabWrite(http.HandlerFunc(s.putDeviceControls)))
	mux.Handle("POST /api/v1/traffic-policy/bypass", s.requireLabWrite(http.HandlerFunc(s.addTLSBypass)))
	mux.Handle("DELETE /api/v1/traffic-policy/bypass", s.requireLabWrite(http.HandlerFunc(s.removeTLSBypass)))
	mux.Handle("GET /api/v1/interception-ca/onboarding", s.requireAuthOrScope(apitoken.ScopeSystemRead, http.HandlerFunc(s.interceptionCAOnboarding)))
}

type deviceControlsView struct {
	Schema         int       `json:"schema"`
	DeviceID       string    `json:"device_id"`
	DecryptHTTPS   bool      `json:"decrypt_https"`
	Internet       string    `json:"internet"`
	BlockedDomains []string  `json:"blocked_domains"`
	UpdatedAt      time.Time `json:"updated_at"`
	Effective      bool      `json:"effective"`
	Notes          []string  `json:"notes"`
}

type deviceControlsRequest struct {
	DecryptHTTPS   *bool     `json:"decrypt_https"`
	Internet       *string   `json:"internet"`
	BlockedDomains *[]string `json:"blocked_domains"`
}

// resolveLabDevice resolves any device reference (ID, MAC, IP or name) with
// the shared resolver and re-checks API token device restrictions.
func (s *Server) resolveLabDevice(ctx context.Context, ref string) (deviceinventory.Device, error) {
	device, err := s.resolveDeviceRef(ctx, ref)
	if err != nil {
		return deviceinventory.Device{}, err
	}
	if err := requireDeviceAccess(ctx, device.ID); err != nil {
		return deviceinventory.Device{}, err
	}
	return device, nil
}

func containsFold(values []string, wanted string) bool {
	for _, value := range values {
		if strings.EqualFold(value, wanted) {
			return true
		}
	}
	return false
}

// labDeviceMACs returns the device's most recently seen MAC identities in
// canonical form (at most the policy's bound), the evidence the gateway
// matches packets by.
func labDeviceMACs(device deviceinventory.Device) []string {
	identities := append([]deviceinventory.Identity(nil), device.Identities...)
	sort.SliceStable(identities, func(i, j int) bool { return identities[i].LastSeen.After(identities[j].LastSeen) })
	result := []string{}
	for _, identity := range identities {
		if identity.Kind != deviceinventory.IdentityMAC || len(result) >= maxControlHardwareAddresses {
			continue
		}
		if normalized, err := trafficpolicy.NormalizeHardwareAddress(identity.Value); err == nil && !containsFold(result, normalized) {
			result = append(result, normalized)
		}
	}
	sort.Strings(result)
	return result
}

// Bounds of the identity evidence a device control may carry.
const (
	maxControlHardwareAddresses = 8
	maxControlAddresses         = 16
)

func currentDeviceAddresses(device deviceinventory.Device, now time.Time) []string {
	result := []string{}
	for _, observed := range device.Addresses {
		if !observed.Active || observed.ValidUntil.Before(now) {
			continue
		}
		if address, err := netip.ParseAddr(observed.Address); err == nil && !containsFold(result, address.Unmap().String()) && len(result) < maxControlAddresses {
			result = append(result, address.Unmap().String())
		}
	}
	sort.Strings(result)
	return result
}

func (s *Server) getDeviceControls(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	device, err := s.resolveLabDevice(r.Context(), r.PathValue("deviceID"))
	if err != nil {
		writeDeviceRefError(w, err)
		return
	}
	var document trafficpolicy.Document
	if err := s.gateway.Call(r.Context(), "GetTrafficPolicy", gatewayprotocol.EmptyParams{}, &document); err != nil {
		writeTrafficReadError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s.deviceControlsView(r.Context(), document, device, nil))
}

func (s *Server) putDeviceControls(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var request deviceControlsRequest
	if err := decodeJSON(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Send JSON with any of decrypt_https (true/false), internet (\"ALLOW\" or \"BLOCK\") and blocked_domains (a list of names).")
		return
	}
	internet := ""
	if request.Internet != nil {
		internet = strings.ToUpper(strings.TrimSpace(*request.Internet))
		if internet != "ALLOW" && internet != "BLOCK" {
			writeError(w, http.StatusBadRequest, "invalid_internet", "internet must be \"ALLOW\" or \"BLOCK\".")
			return
		}
	}
	var domains []string
	if request.BlockedDomains != nil {
		if len(*request.BlockedDomains) > trafficpolicy.MaxBlockedDomainsPerDevice {
			writeError(w, http.StatusBadRequest, "too_many_domains", fmt.Sprintf("A device can have at most %d blocked domains.", trafficpolicy.MaxBlockedDomainsPerDevice))
			return
		}
		domains = []string{}
		for _, raw := range *request.BlockedDomains {
			domain, err := trafficpolicy.NormalizeDomain(raw)
			if err != nil {
				writeError(w, http.StatusBadRequest, "invalid_domain", fmt.Sprintf("%q is not a domain name. Use a name such as example.com; subdomains are blocked too.", raw))
				return
			}
			if !containsFold(domains, domain) {
				domains = append(domains, domain)
			}
		}
		sort.Strings(domains)
	}
	device, err := s.resolveLabDevice(r.Context(), r.PathValue("deviceID"))
	if err != nil {
		writeDeviceRefError(w, err)
		return
	}

	labControlsMu.Lock()
	defer labControlsMu.Unlock()
	var current trafficpolicy.Document
	if err := s.gateway.Call(r.Context(), "GetTrafficPolicy", gatewayprotocol.EmptyParams{}, &current); err != nil {
		writeTrafficReadError(w, err)
		return
	}
	next := clonePolicy(current.Policy)
	notes := []string{}
	if request.DecryptHTTPS != nil {
		selected := containsFold(next.TLS.SelectedDeviceIDs, device.ID)
		allDevices := next.TLS.Enabled && len(next.TLS.SelectedDeviceIDs) == 0
		switch {
		case *request.DecryptHTTPS && allDevices:
			notes = append(notes, "HTTPS decryption is already on for every lab device.")
		case *request.DecryptHTTPS && !selected:
			if !next.TLS.Enabled {
				if _, err := interceptionpki.LoadPublicStatus(interceptionPublicRoot()); err != nil {
					writeError(w, http.StatusConflict, "interception_ca_missing", "ShakerProxy has not created its interception certificate yet. Run `sudo systemctl restart shakerproxy-interception-pki`, then try again.")
					return
				}
			}
			next.TLS.Enabled = true
			next.TLS.SelectedDeviceIDs = append(next.TLS.SelectedDeviceIDs, device.ID)
		case !*request.DecryptHTTPS && allDevices:
			writeError(w, http.StatusConflict, "decryption_all_devices", "HTTPS decryption is on for every lab device. Switch it to selected devices in Policy → HTTPS, then turn it off for this device.")
			return
		case !*request.DecryptHTTPS && selected:
			next.TLS.SelectedDeviceIDs = removeString(next.TLS.SelectedDeviceIDs, device.ID)
			if len(next.TLS.SelectedDeviceIDs) == 0 {
				next.TLS.Enabled = false
			}
		}
	}
	control, _ := trafficpolicy.FindDeviceControl(next, device.ID)
	control.DeviceID = device.ID
	if internet != "" {
		control.BlockInternet = internet == "BLOCK"
	}
	if domains != nil {
		control.BlockedDomains = domains
	}
	control.HardwareAddresses = labDeviceMACs(device)
	control.Addresses = currentDeviceAddresses(device, time.Now().UTC())
	next.DeviceControls = replaceDeviceControl(next.DeviceControls, control, control.Effective() || containsFold(next.TLS.SelectedDeviceIDs, device.ID))

	document := current
	if !policiesEqual(current.Policy, next) {
		next.Revision = current.Policy.Revision + 1
		params := gatewayprotocol.ApplyTrafficPolicyParams{ExpectedRevision: current.Policy.Revision, Policy: next}
		// Decode into a fresh value: decoding into the current document would
		// reuse its slices and keep old values for omitted (false) fields.
		var applied trafficpolicy.Document
		if err := s.gateway.Call(r.Context(), "ApplyTrafficPolicy", params, &applied); err != nil {
			status, code, message := classifyTrafficApplyError(err)
			writeError(w, status, code, message)
			return
		}
		document = applied
		view := s.deviceControlsView(r.Context(), document, device, notes)
		s.logger.Info("device lab controls changed", "username", sessionUsername(r.Context()), "device_id", device.ID, "decrypt_https", view.DecryptHTTPS, "internet", view.Internet, "blocked_domains", len(view.BlockedDomains), "revision", document.Policy.Revision, "digest", document.Digest)
		writeJSON(w, http.StatusOK, view)
		return
	}
	writeJSON(w, http.StatusOK, s.deviceControlsView(r.Context(), document, device, notes))
}

// deviceControlsView reports what is configured and whether it is enforced
// right now, with plain-language notes for the tester.
func (s *Server) deviceControlsView(ctx context.Context, document trafficpolicy.Document, device deviceinventory.Device, notes []string) deviceControlsView {
	policy := document.Policy
	control, _ := trafficpolicy.FindDeviceControl(policy, device.ID)
	allDevices := policy.TLS.Enabled && len(policy.TLS.SelectedDeviceIDs) == 0
	view := deviceControlsView{
		Schema:         1,
		DeviceID:       device.ID,
		DecryptHTTPS:   allDevices || (policy.TLS.Enabled && containsFold(policy.TLS.SelectedDeviceIDs, device.ID)),
		Internet:       "ALLOW",
		BlockedDomains: append([]string{}, control.BlockedDomains...),
		UpdatedAt:      document.AppliedAt,
		Effective:      true,
		Notes:          append([]string{}, notes...),
	}
	if control.BlockInternet {
		view.Internet = "BLOCK"
	}
	active := view.DecryptHTTPS || control.Effective()
	if !active {
		return view
	}
	var onboarding gatewayprotocol.LabOnboarding
	if err := s.gateway.Call(ctx, "GetLabOnboarding", gatewayprotocol.EmptyParams{}, &onboarding); err == nil {
		switch {
		case onboarding.FleetManaged:
			view.Effective = false
			view.Notes = append(view.Notes, "Traffic policy on this appliance is managed by ShakerProxy Fleet, so these local controls are saved but not enforced.")
		case onboarding.EmergencyBypass:
			view.Effective = false
			view.Notes = append(view.Notes, "Emergency bypass is on: controls are saved but not enforced until it is turned off.")
		case !onboarding.Routed:
			view.Effective = false
			view.Notes = append(view.Notes, "Apply a routed network plan first so ShakerProxy sits between the device and the internet.")
		}
		if view.DecryptHTTPS && view.Effective && onboarding.GatewayIPv4 != "" && onboarding.Published {
			view.Notes = append(view.Notes, fmt.Sprintf("To decrypt, the device must trust the ShakerProxy CA: open http://%s/ on the device. Devices that cannot install it show whether they validate certificates.", onboarding.GatewayIPv4))
		}
	}
	if len(control.HardwareAddresses) == 0 && len(control.Addresses) == 0 && (control.Effective() || (view.DecryptHTTPS && !allDevices)) {
		view.Effective = false
		view.Notes = append(view.Notes, "ShakerProxy does not know this device's MAC or IP address yet. Connect it to the lab network, then save its controls again so they can be applied.")
	}
	if view.DecryptHTTPS && !policy.TLS.AllowQUIC {
		view.Notes = append(view.Notes, "QUIC (UDP 443) is blocked for this device so apps fall back to HTTPS over TCP, which ShakerProxy can decrypt.")
	}
	if len(control.BlockedDomains) != 0 {
		if policy.EncryptedDNS.Mode != trafficpolicy.EncryptedDNSEnforceLocal {
			view.Notes = append(view.Notes, "Domain blocking needs ShakerProxy DNS enforcement; it was enabled for this device.")
		}
		view.Notes = append(view.Notes, "DNS over TLS/QUIC is blocked for this device. Apps using DNS over HTTPS, cached answers or hard-coded IP addresses can still reach blocked names.")
	}
	if control.BlockInternet {
		view.Notes = append(view.Notes, "Internet is blocked for this device: traffic leaving the lab is dropped; ShakerProxy's DHCP, DNS and other lab devices still work.")
	}
	return view
}

type tlsBypassRequest struct {
	Host   string `json:"host"`
	Device string `json:"device"`
}

type tlsBypassView struct {
	Schema   int      `json:"schema"`
	Host     string   `json:"host"`
	DeviceID *string  `json:"device_id"`
	Scope    string   `json:"scope"`
	Removed  bool     `json:"removed,omitempty"`
	Revision uint64   `json:"revision"`
	Notes    []string `json:"notes"`
}

func (s *Server) addTLSBypass(w http.ResponseWriter, r *http.Request) {
	var request tlsBypassRequest
	if err := decodeJSON(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Send JSON with host (for example api.example.com) and optionally device (ID, MAC, IP or name).")
		return
	}
	s.changeTLSBypass(w, r, request.Host, request.Device, false)
}

func (s *Server) removeTLSBypass(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	s.changeTLSBypass(w, r, query.Get("host"), query.Get("device"), true)
}

func (s *Server) changeTLSBypass(w http.ResponseWriter, r *http.Request, rawHost, deviceRef string, remove bool) {
	w.Header().Set("Cache-Control", "no-store")
	host, err := trafficpolicy.NormalizeDomain(rawHost)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_host", fmt.Sprintf("%q is not a host name. Use the name shown in the TLS event, such as api.example.com.", rawHost))
		return
	}
	var device *deviceinventory.Device
	if strings.TrimSpace(deviceRef) != "" {
		resolved, err := s.resolveLabDevice(r.Context(), deviceRef)
		if err != nil {
			writeDeviceRefError(w, err)
			return
		}
		device = &resolved
	}

	labControlsMu.Lock()
	defer labControlsMu.Unlock()
	var current trafficpolicy.Document
	if err := s.gateway.Call(r.Context(), "GetTrafficPolicy", gatewayprotocol.EmptyParams{}, &current); err != nil {
		writeTrafficReadError(w, err)
		return
	}
	next := clonePolicy(current.Policy)
	view := tlsBypassView{Schema: 1, Host: host, Scope: "all_devices", Removed: remove}
	if device == nil {
		present := containsFold(next.TLS.ExcludeHosts, host)
		switch {
		case remove && !present:
			writeError(w, http.StatusNotFound, "bypass_not_found", fmt.Sprintf("%s is not bypassed for all devices.", host))
			return
		case remove:
			next.TLS.ExcludeHosts = removeString(next.TLS.ExcludeHosts, host)
		case !present:
			next.TLS.ExcludeHosts = append(next.TLS.ExcludeHosts, host)
		}
	} else {
		view.Scope = "device"
		view.DeviceID = &device.ID
		control, _ := trafficpolicy.FindDeviceControl(next, device.ID)
		control.DeviceID = device.ID
		present := containsFold(control.BypassHosts, host)
		switch {
		case remove && !present:
			writeError(w, http.StatusNotFound, "bypass_not_found", fmt.Sprintf("%s is not bypassed for this device.", host))
			return
		case remove:
			control.BypassHosts = removeString(control.BypassHosts, host)
		case !present:
			if len(control.BypassHosts) >= trafficpolicy.MaxBypassHostsPerDevice {
				writeError(w, http.StatusConflict, "too_many_bypasses", fmt.Sprintf("A device can bypass at most %d hosts. Remove one first.", trafficpolicy.MaxBypassHostsPerDevice))
				return
			}
			control.BypassHosts = append(control.BypassHosts, host)
		}
		control.HardwareAddresses = labDeviceMACs(*device)
		control.Addresses = currentDeviceAddresses(*device, time.Now().UTC())
		next.DeviceControls = replaceDeviceControl(next.DeviceControls, control, control.Effective() || containsFold(next.TLS.SelectedDeviceIDs, device.ID))
	}
	document := current
	if !policiesEqual(current.Policy, next) {
		next.Revision = current.Policy.Revision + 1
		params := gatewayprotocol.ApplyTrafficPolicyParams{ExpectedRevision: current.Policy.Revision, Policy: next}
		// Decode into a fresh value: decoding into the current document would
		// reuse its slices and keep old values for omitted (false) fields.
		var applied trafficpolicy.Document
		if err := s.gateway.Call(r.Context(), "ApplyTrafficPolicy", params, &applied); err != nil {
			status, code, message := classifyTrafficApplyError(err)
			writeError(w, status, code, message)
			return
		}
		document = applied
		s.logger.Info("TLS bypass changed", "username", sessionUsername(r.Context()), "host", host, "device_id", deviceIDOrAll(device), "removed", remove, "revision", document.Policy.Revision, "digest", document.Digest)
	}
	view.Revision = document.Policy.Revision
	if remove {
		view.Notes = []string{fmt.Sprintf("ShakerProxy decrypts %s again from the next connection.", host)}
	} else {
		view.Notes = []string{fmt.Sprintf("The next connection to %s passes through without decryption. Retry the action on the device.", host)}
	}
	writeJSON(w, http.StatusOK, view)
}

func deviceIDOrAll(device *deviceinventory.Device) string {
	if device == nil {
		return "all"
	}
	return device.ID
}

// Gateway JSON-RPC codes used by the traffic-policy methods.
const (
	gatewayCodeTrafficUnavailable = -32070
	gatewayCodeTrafficApply       = -32073
	gatewayCodeConfigurationLock  = -32060
	gatewayCodeInvalidParameters  = -32602
)

// classifyTrafficApplyError turns privileged gateway failures into the
// standard error shape with the next step for the tester.
func classifyTrafficApplyError(err error) (int, string, string) {
	var remote *gatewayclient.RemoteError
	if !errors.As(err, &remote) {
		return http.StatusServiceUnavailable, "gateway_unavailable", "ShakerProxy's gateway service is not reachable. Check `sudo systemctl status shakerproxy-gatewayd`."
	}
	message := remote.Message
	switch remote.Code {
	case gatewayCodeTrafficUnavailable:
		return http.StatusServiceUnavailable, "traffic_policy_unavailable", "This ShakerProxy install cannot change traffic policy (the gateway runs without network apply). Use an installed appliance."
	case gatewayCodeConfigurationLock:
		return http.StatusConflict, "configuration_locked", "Another network or policy change is being applied. Try again in a moment."
	case gatewayCodeInvalidParameters:
		return http.StatusBadRequest, "invalid_policy", "The gateway rejected the change as malformed: " + message
	case gatewayCodeTrafficApply:
	default:
		return http.StatusBadGateway, "gateway_error", "The gateway could not apply the change: " + message
	}
	switch {
	case strings.Contains(message, "confirmed routed network plan") || strings.Contains(message, "IPv4 lab interface"):
		return http.StatusConflict, "network_not_ready", "Apply a routed network plan first (Network → Apply) so ShakerProxy sits between the device and the internet."
	case strings.Contains(message, "TLS interception service is not ready"):
		return http.StatusServiceUnavailable, "decryption_service_unavailable", "The HTTPS decryption service (mitmproxy) is not running. Check it with `sudo shakerproxy app status`; if this appliance was installed with --profile standard, reinstall with the default full profile, otherwise run `sudo shakerproxy repair`."
	case strings.Contains(message, "local DNS forwarder is not ready"):
		return http.StatusServiceUnavailable, "dns_service_unavailable", "The ShakerProxy DNS forwarder is not running. Run `sudo systemctl restart shakerproxy-dnsd` and try again."
	case strings.Contains(message, "managed by Fleet"):
		return http.StatusConflict, "managed_by_fleet", "Traffic policy on this appliance is managed by ShakerProxy Fleet; change it there."
	case strings.Contains(message, "revision conflict") || strings.Contains(message, "revision must increase"):
		return http.StatusConflict, "policy_conflict", "The traffic policy changed while saving. Reload and try again."
	default:
		return http.StatusUnprocessableEntity, "policy_rejected", "The change could not be applied: " + message
	}
}

func writeTrafficReadError(w http.ResponseWriter, err error) {
	var remote *gatewayclient.RemoteError
	if errors.As(err, &remote) && remote.Code == gatewayCodeTrafficUnavailable {
		writeError(w, http.StatusServiceUnavailable, "traffic_policy_unavailable", "This ShakerProxy install cannot change traffic policy (the gateway runs without network apply). Use an installed appliance.")
		return
	}
	writeError(w, http.StatusServiceUnavailable, "gateway_unavailable", "ShakerProxy's gateway service is not reachable. Check `sudo systemctl status shakerproxy-gatewayd`.")
}

func clonePolicy(policy trafficpolicy.Policy) trafficpolicy.Policy {
	encoded, err := json.Marshal(policy)
	if err != nil {
		return policy
	}
	var clone trafficpolicy.Policy
	if json.Unmarshal(encoded, &clone) != nil {
		return policy
	}
	return clone
}

func policiesEqual(left, right trafficpolicy.Policy) bool {
	leftNormalized, leftErr := trafficpolicy.Normalize(left)
	rightNormalized, rightErr := trafficpolicy.Normalize(right)
	if leftErr != nil || rightErr != nil {
		return false
	}
	return reflect.DeepEqual(leftNormalized, rightNormalized)
}

// attachSelectedDeviceIdentity gives every device selected for HTTPS
// decryption the MAC and current addresses the host needs to match its
// traffic, exactly as the per-device controls do, so selecting devices in the
// policy editor works the same as the per-device toggle. Identity-only entries
// for devices that are no longer selected are dropped.
func (s *Server) attachSelectedDeviceIdentity(policy trafficpolicy.Policy) trafficpolicy.Policy {
	if s.inventory == nil {
		return policy
	}
	now := time.Now().UTC()
	selected := make(map[string]bool, len(policy.TLS.SelectedDeviceIDs))
	for _, deviceID := range policy.TLS.SelectedDeviceIDs {
		selected[deviceID] = true
		device, err := s.inventory.Get(deviceID)
		if err != nil {
			continue
		}
		control, _ := trafficpolicy.FindDeviceControl(policy, deviceID)
		control.DeviceID = deviceID
		control.HardwareAddresses = labDeviceMACs(device)
		control.Addresses = currentDeviceAddresses(device, now)
		policy.DeviceControls = replaceDeviceControl(policy.DeviceControls, control, true)
	}
	var kept []trafficpolicy.DeviceControl
	for _, control := range policy.DeviceControls {
		if control.Effective() || selected[control.DeviceID] {
			kept = append(kept, control)
		}
	}
	policy.DeviceControls = kept
	return policy
}

func replaceDeviceControl(controls []trafficpolicy.DeviceControl, control trafficpolicy.DeviceControl, keep bool) []trafficpolicy.DeviceControl {
	result := make([]trafficpolicy.DeviceControl, 0, len(controls)+1)
	for _, existing := range controls {
		if existing.DeviceID != control.DeviceID {
			result = append(result, existing)
		}
	}
	if keep {
		result = append(result, control)
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func removeString(values []string, unwanted string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if !strings.EqualFold(value, unwanted) {
			result = append(result, value)
		}
	}
	return result
}
