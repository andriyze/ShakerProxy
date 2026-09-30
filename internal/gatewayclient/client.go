package gatewayclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
)

type Client struct{ SocketPath string }

// RemoteError is a structured error returned by the gateway daemon. Callers can
// use errors.As to map the JSON-RPC code to an HTTP status; Error() keeps the
// historical "gateway daemon: <message>" text.
type RemoteError struct {
	Code    int
	Message string
}

func (e *RemoteError) Error() string { return "gateway daemon: " + e.Message }

// Gateway daemon JSON-RPC codes that callers commonly branch on.
const (
	CodeCaptureUnavailable      = -32040
	CodeCaptureStatus           = -32044
	CodeNetworkApplyUnavailable = -32030
	CodeNetworkRevertFailed     = -32036
)

// Call invokes a privileged method with the method's standard budget from
// gatewayprotocol.MethodTimeout, so slow host operations such as the
// connectivity probe or PCAP rewrites are not cut off by a generic default.
func (c Client) Call(ctx context.Context, method string, params any, result any) error {
	return c.CallWithTimeout(ctx, method, params, result, gatewayprotocol.MethodTimeout(method))
}

func (c Client) CallWithTimeout(ctx context.Context, method string, params any, result any, timeout time.Duration) error {
	if timeout < time.Second || timeout > gatewayprotocol.MaxMethodTimeout {
		return fmt.Errorf("gateway call timeout is invalid")
	}
	dialer := net.Dialer{Timeout: 2 * time.Second}
	conn, err := dialer.DialContext(ctx, "unix", c.SocketPath)
	if err != nil {
		return fmt.Errorf("connect to gateway daemon: %w", err)
	}
	defer conn.Close()
	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	_ = conn.SetDeadline(deadline)
	raw, err := json.Marshal(params)
	if err != nil {
		return err
	}
	req := gatewayprotocol.Request{JSONRPC: gatewayprotocol.JSONRPCVersion, ID: fmt.Sprintf("local-%d", time.Now().UnixNano()), Method: method, Params: raw}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return fmt.Errorf("send %s to gateway daemon: %w", method, err)
	}
	var response gatewayprotocol.Response
	if err := gatewayprotocol.DecodeStrict(conn, &response, gatewayprotocol.MaxResponseBytes); err != nil {
		return fmt.Errorf("read %s response from gateway daemon: %w", method, err)
	}
	if response.Error != nil {
		return &RemoteError{Code: response.Error.Code, Message: response.Error.Message}
	}
	encoded, err := json.Marshal(response.Result)
	if err != nil {
		return err
	}
	if result == nil {
		return nil
	}
	return json.Unmarshal(encoded, result)
}
