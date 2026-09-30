//go:build !linux

package daemon

import (
	"fmt"
	"net"
	"runtime"
)

func peerIdentity(_ net.Conn) (uint32, int32, error) {
	return 0, 0, fmt.Errorf("shakerproxy-gatewayd is supported only on Linux")
}

func kernelRelease() string { return runtime.GOOS }

type interfaceMetadata struct {
	StableID, Driver, DevicePath, OperState, Carrier string
	SpeedMbps                                        int
}

func interfaceDetails(name, hardwareAddress string) interfaceMetadata {
	return interfaceMetadata{StableID: "name:" + name + "|mac:" + hardwareAddress}
}
