//go:build linux

package analyzer

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

const parserUID = 65533

func isolateParserCommand(command *exec.Cmd) error {
	if command == nil || os.Geteuid() != 0 {
		return errors.New("analyzer broker must start as container root before isolating its parser")
	}
	command.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: parserUID, Gid: parserUID, Groups: []uint32{}},
		Pdeathsig:  syscall.SIGKILL,
	}
	return nil
}
