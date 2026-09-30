//go:build !linux

package analyzer

import (
	"errors"
	"os/exec"
)

func isolateParserCommand(*exec.Cmd) error {
	return errors.New("analyzer parser isolation is supported only on Linux")
}
