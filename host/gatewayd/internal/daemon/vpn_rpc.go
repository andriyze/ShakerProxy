package daemon

import (
	"context"
	"regexp"

	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/vpn"
)

var vpnDeviceIDPattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)

// dispatchVPN answers the VPN requests: GetVPN (read-only), SetVPN,
// AddVPNPeer, SetVPNPeerDevice and RevokeVPNPeer.
func (s *Server) dispatchVPN(ctx context.Context, req gatewayprotocol.Request) (any, *gatewayprotocol.RPCError) {
	if s.vpn == nil {
		return nil, &gatewayprotocol.RPCError{Code: -32080, Message: "VPN mode is unavailable in this daemon profile"}
	}
	invalid := &gatewayprotocol.RPCError{Code: -32602, Message: "invalid parameters"}
	failed := func(err error) *gatewayprotocol.RPCError {
		return &gatewayprotocol.RPCError{Code: -32081, Message: err.Error()}
	}
	switch req.Method {
	case "GetVPN":
		var params gatewayprotocol.EmptyParams
		if err := gatewayprotocol.DecodeParams(req.Params, &params); err != nil {
			return nil, invalid
		}
		status, err := s.vpn.Status(ctx)
		if err != nil {
			return nil, failed(err)
		}
		return status, nil
	case "SetVPN":
		var params gatewayprotocol.SetVPNParams
		if err := gatewayprotocol.DecodeParams(req.Params, &params); err != nil {
			return nil, invalid
		}
		status, err := s.vpn.Set(ctx, params)
		if err != nil {
			return nil, failed(err)
		}
		return status, nil
	case "AddVPNPeer":
		var params gatewayprotocol.AddVPNPeerParams
		if err := gatewayprotocol.DecodeParams(req.Params, &params); err != nil {
			return nil, invalid
		}
		result, err := s.vpn.AddPeer(ctx, params)
		if err != nil {
			return nil, failed(err)
		}
		return result, nil
	case "SetVPNPeerDevice":
		var params gatewayprotocol.SetVPNPeerDeviceParams
		if err := gatewayprotocol.DecodeParams(req.Params, &params); err != nil || !vpn.ValidPeerID(params.PeerID) || (params.DeviceID != "" && !vpnDeviceIDPattern.MatchString(params.DeviceID)) {
			return nil, invalid
		}
		result, err := s.vpn.SetPeerDevice(params)
		if err != nil {
			return nil, failed(err)
		}
		return result, nil
	case "RevokeVPNPeer":
		var params gatewayprotocol.RevokeVPNPeerParams
		if err := gatewayprotocol.DecodeParams(req.Params, &params); err != nil || !vpn.ValidPeerID(params.PeerID) {
			return nil, invalid
		}
		result, err := s.vpn.RevokePeer(ctx, params)
		if err != nil {
			return nil, failed(err)
		}
		return result, nil
	}
	return nil, &gatewayprotocol.RPCError{Code: -32601, Message: "method not found"}
}
