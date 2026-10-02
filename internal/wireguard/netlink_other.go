//go:build !linux

package wireguard

import "net/netip"

func GetDevice(string) (Device, error)         { return Device{}, ErrUnsupported }
func Configure(string, Config) error           { return ErrUnsupported }
func GetLink(string) (Link, error)             { return Link{}, ErrUnsupported }
func CreateLink(string, int) error             { return ErrUnsupported }
func DeleteLink(string) error                  { return nil }
func SetLinkUp(string) error                   { return ErrUnsupported }
func Addresses(string) ([]netip.Prefix, error) { return nil, ErrUnsupported }
func AddAddress(string, netip.Prefix) error    { return ErrUnsupported }
func DeleteAddress(string, netip.Prefix) error { return ErrUnsupported }
func InterfaceExists(string) bool              { return false }
