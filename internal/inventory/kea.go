package inventory

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	MaxLeaseFileBytes = 32 << 20
	MaxLeaseRecords   = 100000
	MaxLeaseField     = 1024

	maxKeaLifetimeSeconds = 1<<32 - 1
)

func ReadKeaDHCP4Leases(path string) ([]DHCP4Lease, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > MaxLeaseFileBytes {
		return nil, errors.New("Kea DHCPv4 lease source is not a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(info, openedInfo) || !openedInfo.Mode().IsRegular() || openedInfo.Size() > MaxLeaseFileBytes {
		return nil, errors.New("Kea DHCPv4 lease source changed during validation")
	}
	b, err := io.ReadAll(io.LimitReader(file, MaxLeaseFileBytes+1))
	if err != nil || len(b) > MaxLeaseFileBytes {
		return nil, errors.New("Kea DHCPv4 lease source exceeds its size limit")
	}
	return ParseKeaDHCP4Leases(b)
}

func ParseKeaDHCP4Leases(data []byte) ([]DHCP4Lease, error) {
	reader := csv.NewReader(bytes.NewReader(data))
	reader.FieldsPerRecord = -1
	reader.ReuseRecord = false
	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("read Kea DHCPv4 lease header: %w", err)
	}
	columns := make(map[string]int, len(header))
	for index, value := range header {
		columns[strings.TrimSpace(value)] = index
	}
	for _, required := range []string{"address", "hwaddr", "client_id", "valid_lifetime", "expire", "hostname", "state"} {
		if _, ok := columns[required]; !ok {
			return nil, fmt.Errorf("Kea DHCPv4 lease source is missing %q", required)
		}
	}
	leases := make([]DHCP4Lease, 0)
	for recordNumber := 1; ; recordNumber++ {
		record, readErr := reader.Read()
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return nil, fmt.Errorf("read Kea DHCPv4 lease record %d: %w", recordNumber, readErr)
		}
		if len(leases) >= MaxLeaseRecords {
			return nil, errors.New("Kea DHCPv4 lease record limit exceeded")
		}
		for _, value := range record {
			if len(value) > MaxLeaseField {
				return nil, errors.New("Kea DHCPv4 lease field exceeds its size limit")
			}
		}
		field := func(name string) (string, error) {
			index := columns[name]
			if index >= len(record) {
				return "", errors.New("Kea DHCPv4 lease record has too few fields")
			}
			return strings.TrimSpace(record[index]), nil
		}
		addressText, err := field("address")
		if err != nil {
			return nil, err
		}
		address, err := netip.ParseAddr(addressText)
		if err != nil || !address.Is4() || address.IsUnspecified() || address.IsMulticast() {
			return nil, fmt.Errorf("Kea DHCPv4 lease record %d has an invalid address", recordNumber)
		}
		hardware, _ := field("hwaddr")
		if hardware != "" {
			parsed, parseErr := net.ParseMAC(hardware)
			if parseErr != nil || len(parsed) != 6 {
				return nil, fmt.Errorf("Kea DHCPv4 lease record %d has an invalid hardware address", recordNumber)
			}
			hardware = strings.ToLower(parsed.String())
		}
		clientID, _ := field("client_id")
		clientID = strings.ToLower(clientID)
		if clientID != "" && !validClientID(clientID) {
			return nil, fmt.Errorf("Kea DHCPv4 lease record %d has an invalid client identity", recordNumber)
		}
		stateText, _ := field("state")
		state, err := strconv.Atoi(stateText)
		if err != nil || state < 0 || state > 4 {
			return nil, fmt.Errorf("Kea DHCPv4 lease record %d has an invalid state", recordNumber)
		}
		if hardware == "" && clientID == "" {
			if state != 0 {
				// Kea clears the hardware address and client identifier of a
				// declined lease (state 1). Such a record carries no device
				// evidence and must not fail the whole lease import.
				continue
			}
			return nil, fmt.Errorf("Kea DHCPv4 lease record %d has no device identity", recordNumber)
		}
		lifetimeText, _ := field("valid_lifetime")
		lifetime, err := strconv.ParseInt(lifetimeText, 10, 64)
		// Kea lifetimes are unsigned 32-bit seconds; 0xFFFFFFFF means infinite.
		if err != nil || lifetime <= 0 || lifetime > maxKeaLifetimeSeconds {
			return nil, fmt.Errorf("Kea DHCPv4 lease record %d has an invalid lifetime", recordNumber)
		}
		expireText, _ := field("expire")
		expire, err := strconv.ParseInt(expireText, 10, 64)
		if err != nil || expire <= 0 {
			return nil, fmt.Errorf("Kea DHCPv4 lease record %d has an invalid expiry", recordNumber)
		}
		hostname, _ := field("hostname")
		leases = append(leases, DHCP4Lease{
			Address: address, HardwareAddr: hardware, ClientID: clientID,
			Hostname: normalizeHostname(hostname), ValidLifetime: time.Duration(lifetime) * time.Second,
			ExpiresAt: time.Unix(expire, 0).UTC(), State: state,
		})
	}
	return leases, nil
}

func validClientID(value string) bool {
	if len(value) < 2 || len(value) > 512 {
		return false
	}
	for _, char := range value {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f') || char == ':') {
			return false
		}
	}
	return true
}
