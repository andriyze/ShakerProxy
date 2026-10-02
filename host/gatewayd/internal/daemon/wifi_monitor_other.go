//go:build !linux

package daemon

import "errors"

func linkUp(string) (bool, error) { return false, errors.New("interface flags need Linux") }

func setLinkUp(string, bool) error { return errors.New("interface flags need Linux") }
