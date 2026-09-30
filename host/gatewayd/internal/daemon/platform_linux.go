//go:build linux

package daemon

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

type interfaceMetadata struct {
	StableID, Driver, DevicePath, OperState, Carrier string
	SpeedMbps                                        int
}

func interfaceDetails(name, hardwareAddress string) interfaceMetadata {
	base := filepath.Join("/sys/class/net", name)
	devicePath, _ := filepath.EvalSymlinks(filepath.Join(base, "device"))
	driverPath, _ := filepath.EvalSymlinks(filepath.Join(base, "device/driver"))
	metadata := interfaceMetadata{DevicePath: devicePath, Driver: filepath.Base(driverPath), OperState: readTrimmed(filepath.Join(base, "operstate")), Carrier: readTrimmed(filepath.Join(base, "carrier"))}
	if metadata.Driver == "." {
		metadata.Driver = ""
	}
	stableBasis := devicePath
	if stableBasis == "" {
		stableBasis = "virtual:" + name
	}
	metadata.StableID = fmt.Sprintf("path:%s|mac:%s", stableBasis, hardwareAddress)
	if speed, err := strconv.Atoi(readTrimmed(filepath.Join(base, "speed"))); err == nil && speed > 0 {
		metadata.SpeedMbps = speed
	}
	return metadata
}

func readTrimmed(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func peerIdentity(conn net.Conn) (uint32, int32, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, 0, fmt.Errorf("connection is not Unix")
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var cred *unix.Ucred
	var socketErr error
	if err := raw.Control(func(fd uintptr) { cred, socketErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil {
		return 0, 0, err
	}
	if socketErr != nil {
		return 0, 0, socketErr
	}
	return cred.Uid, cred.Pid, nil
}

func kernelRelease() string {
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(b))
}
