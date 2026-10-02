package server

import (
	"errors"
	"net/http"
	"strings"

	"shakerproxy.dev/shakerproxy/internal/gatewayclient"
	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	deviceinventory "shakerproxy.dev/shakerproxy/internal/inventory"
	"shakerproxy.dev/shakerproxy/internal/vpn"
)

// VPN mode routes a phone's or laptop's whole connection through
// ShakerProxy over WireGuard: the tester scans a QR code in the WireGuard
// app, and every connection the device makes appears in Traffic under its
// name. gatewayd runs the VPN; this file is its API.

// vpnDeviceSuffix marks VPN devices in Devices and Traffic, so "Pixel" on
// the lab and over the VPN are told apart: "Pixel (VPN) · 10.89.0.2".
const vpnDeviceSuffix = " (VPN)"

func (s *Server) getVPN(w http.ResponseWriter, r *http.Request) {
	var status gatewayprotocol.VPNStatus
	if err := s.gateway.Call(r.Context(), "GetVPN", gatewayprotocol.EmptyParams{}, &status); err != nil {
		writeVPNGatewayError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

type putVPNRequest struct {
	Password string `json:"password"`
	// ExpectedRevision guards against overwriting a concurrent change; it
	// defaults to the current revision.
	ExpectedRevision *uint64 `json:"expected_revision"`
	Enabled          *bool   `json:"enabled"`
	ListenPort       *int    `json:"listen_port"`
	Endpoint         *string `json:"endpoint"`
	IPv4CIDR         *string `json:"ipv4_cidr"`
	AllowPeerToPeer  *bool   `json:"allow_peer_to_peer"`
}

// putVPN turns VPN mode on or off and changes its settings; fields left
// out keep their current value.
func (s *Server) putVPN(w http.ResponseWriter, r *http.Request) {
	var request putVPNRequest
	if err := decodeJSON(r, &request); err != nil {
		writeDecodeError(w, err, "VPN settings")
		return
	}
	if !s.confirmAdministrator(w, r, request.Password, passwordRecent) {
		return
	}
	var current gatewayprotocol.VPNStatus
	if err := s.gateway.Call(r.Context(), "GetVPN", gatewayprotocol.EmptyParams{}, &current); err != nil {
		writeVPNGatewayError(w, err)
		return
	}
	params := gatewayprotocol.SetVPNParams{
		ExpectedRevision: current.Revision, Enabled: current.Enabled, ListenPort: current.ListenPort,
		Endpoint: current.EndpointSetting, IPv4CIDR: current.IPv4CIDR, AllowPeerToPeer: current.AllowPeerToPeer,
	}
	if request.ExpectedRevision != nil {
		params.ExpectedRevision = *request.ExpectedRevision
	}
	if request.Enabled != nil {
		params.Enabled = *request.Enabled
	}
	if request.ListenPort != nil {
		params.ListenPort = *request.ListenPort
	}
	if request.Endpoint != nil {
		params.Endpoint = strings.TrimSpace(*request.Endpoint)
	}
	if request.IPv4CIDR != nil {
		params.IPv4CIDR = strings.TrimSpace(*request.IPv4CIDR)
	}
	if request.AllowPeerToPeer != nil {
		params.AllowPeerToPeer = *request.AllowPeerToPeer
	}
	var status gatewayprotocol.VPNStatus
	if err := s.gateway.Call(r.Context(), "SetVPN", params, &status); err != nil {
		writeVPNGatewayError(w, err)
		return
	}
	s.logger.Info("VPN settings changed", "username", sessionUsername(r.Context()), "enabled", status.Enabled, "listen_port", status.ListenPort, "revision", status.Revision)
	writeJSON(w, http.StatusOK, status)
}

type addVPNDeviceRequest struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

// addVPNDeviceResponse carries the device's configuration once: it holds
// the device's private key, which ShakerProxy does not keep.
type addVPNDeviceResponse struct {
	Peer       gatewayprotocol.VPNPeerStatus `json:"peer"`
	Config     string                        `json:"config"`
	FileName   string                        `json:"file_name"`
	DeviceID   string                        `json:"device_id,omitempty"`
	DeviceName string                        `json:"device_name"`
	Warnings   []string                      `json:"warnings"`
}

// addVPNDevice adds a VPN device and names it in Devices at its VPN
// address, so its traffic shows under its name from the first packet.
func (s *Server) addVPNDevice(w http.ResponseWriter, r *http.Request) {
	var request addVPNDeviceRequest
	if err := decodeJSON(r, &request); err != nil {
		writeDecodeError(w, err, "VPN device")
		return
	}
	name, err := vpn.ValidateName(strings.TrimSuffix(strings.TrimSpace(request.Name), strings.TrimSpace(vpnDeviceSuffix)))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_name", err.Error())
		return
	}
	if !s.confirmAdministrator(w, r, request.Password, passwordRecent) {
		return
	}
	actor := sessionUsername(r.Context())
	var added gatewayprotocol.VPNPeerConfig
	if err := s.gateway.Call(r.Context(), "AddVPNPeer", gatewayprotocol.AddVPNPeerParams{Name: name, Actor: actor}, &added); err != nil {
		writeVPNGatewayError(w, err)
		return
	}
	response := addVPNDeviceResponse{Peer: added.Peer, Config: added.Config, FileName: added.FileName, DeviceName: name + vpnDeviceSuffix, Warnings: []string{}}
	deviceID, warning := s.nameVPNDevice(actor, response.DeviceName, added.Peer.IPv4)
	if warning != "" {
		response.Warnings = append(response.Warnings, warning)
	}
	if deviceID != "" {
		response.DeviceID = deviceID
		var peer gatewayprotocol.VPNPeerStatus
		if err := s.gateway.Call(r.Context(), "SetVPNPeerDevice", gatewayprotocol.SetVPNPeerDeviceParams{PeerID: added.Peer.ID, DeviceID: deviceID}, &peer); err != nil {
			response.Warnings = append(response.Warnings, "Per-device controls (blocking, decryption) do not apply to this VPN device yet: "+err.Error())
		} else {
			response.Peer = peer
		}
	}
	s.invalidateDeviceNames()
	s.logger.Info("VPN device added", "username", actor, "peer_id", added.Peer.ID, "address", added.Peer.IPv4, "device_id", deviceID)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, response)
}

// nameVPNDevice pins the VPN address to a new device with the given name.
// A device still named by this address from an earlier, revoked VPN device
// (addresses are reused only once the whole network has been used) stops
// being named by it first, so the new device does not inherit its history.
func (s *Server) nameVPNDevice(actor, name, address string) (string, string) {
	if s.inventory == nil {
		return "", "Device inventory is not configured, so this VPN device appears by its address only."
	}
	if snapshot, err := s.inventory.Snapshot(); err == nil {
		for _, device := range snapshot.Devices {
			if device.PinnedAddress != address {
				continue
			}
			operationID, _ := newOperationID()
			if _, err := s.inventory.UnpinAddress(device.ID, actor, operationID); err != nil {
				return "", "The VPN address could not be named (" + err.Error() + "); name it on the Devices page."
			}
		}
	}
	operationID, _ := newOperationID()
	result, err := s.inventory.NameAddress(actor, operationID, deviceinventory.AddressName{Name: name, Address: address})
	if err != nil {
		return "", "The VPN address could not be named (" + err.Error() + "); name it on the Devices page."
	}
	if len(result.Devices) == 0 {
		return "", ""
	}
	return result.Devices[0].ID, ""
}

type revokeVPNDeviceRequest struct {
	Password string `json:"password"`
}

// revokeVPNDevice disconnects a VPN device at once. Its entry in Devices
// keeps its name and recorded traffic.
func (s *Server) revokeVPNDevice(w http.ResponseWriter, r *http.Request) {
	peerID := r.PathValue("peerID")
	if !vpn.ValidPeerID(peerID) {
		writeError(w, http.StatusBadRequest, "invalid_vpn_device_id", "VPN device IDs look like vpn-0123456789abcdef; list them with GET /api/v1/vpn.")
		return
	}
	var request revokeVPNDeviceRequest
	if err := decodeOptionalJSON(r, &request, 4096); err != nil {
		writeDecodeError(w, err, "VPN device")
		return
	}
	if !s.confirmAdministrator(w, r, request.Password, passwordRecent) {
		return
	}
	var revoked gatewayprotocol.VPNPeerStatus
	if err := s.gateway.Call(r.Context(), "RevokeVPNPeer", gatewayprotocol.RevokeVPNPeerParams{PeerID: peerID}, &revoked); err != nil {
		writeVPNGatewayError(w, err)
		return
	}
	s.logger.Info("VPN device revoked", "username", sessionUsername(r.Context()), "peer_id", peerID)
	writeJSON(w, http.StatusOK, revoked)
}

func writeVPNGatewayError(w http.ResponseWriter, err error) {
	var remote *gatewayclient.RemoteError
	switch {
	case errors.As(err, &remote) && remote.Code == -32080:
		writeError(w, http.StatusServiceUnavailable, "vpn_unavailable", "VPN mode is not available in this appliance profile.")
	case errors.As(err, &remote) && remote.Code == -32081 && strings.Contains(remote.Message, "no such VPN device"):
		writeError(w, http.StatusNotFound, "vpn_device_not_found", "No VPN device has this ID; list them with GET /api/v1/vpn.")
	case errors.As(err, &remote) && (remote.Code == -32081 || remote.Code == -32060):
		writeError(w, http.StatusConflict, "vpn_change_rejected", remote.Message)
	case errors.As(err, &remote) && remote.Code == -32602:
		writeError(w, http.StatusBadRequest, "invalid_request", "The VPN request is invalid.")
	case errors.As(err, &remote):
		writeError(w, http.StatusServiceUnavailable, "vpn_unavailable", "The VPN is temporarily unavailable: "+remote.Message+".")
	default:
		writeError(w, http.StatusServiceUnavailable, "gateway_unavailable", "The host gateway service is unavailable; check that shakerproxy-gatewayd is running.")
	}
}
