package capture

import (
	"context"
	"errors"
	"os/exec"
	"strings"
)

type CommandRunner interface {
	Run(context.Context, string, ...string) error
}

type SystemdController struct{ Runner CommandRunner }

func (c SystemdController) Start(ctx context.Context, id string) error {
	if !ValidSessionID(id) || c.Runner == nil {
		return errors.New("invalid capture service start request")
	}
	return c.Runner.Run(ctx, "/usr/bin/systemctl", "start", captureUnit(id))
}

func (c SystemdController) Stop(ctx context.Context, id string) error {
	if !ValidSessionID(id) || c.Runner == nil {
		return errors.New("invalid capture service stop request")
	}
	return c.Runner.Run(ctx, "/usr/bin/systemctl", "stop", "--no-block", captureUnit(id))
}

func (c SystemdController) Active(ctx context.Context, id string) (bool, error) {
	if !ValidSessionID(id) || c.Runner == nil {
		return false, errors.New("invalid capture service status request")
	}
	err := c.Runner.Run(ctx, "/usr/bin/systemctl", "is-active", "--quiet", captureUnit(id))
	if err == nil {
		return true, nil
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) && exitError.ExitCode() == 3 {
		return false, nil
	}
	return false, err
}

func captureUnit(id string) string {
	return "shakerproxy-capture@" + strings.TrimPrefix(id, "capture-") + ".service"
}

type OSCommandRunner struct{}

func (OSCommandRunner) Run(ctx context.Context, path string, arguments ...string) error {
	if !allowedSystemdCommand(path, arguments) {
		return errors.New("capture service command is not allowlisted")
	}
	command := exec.CommandContext(ctx, path, arguments...)
	command.Env = []string{"HOME=/nonexistent", "LANG=C", "LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	return command.Run()
}

func allowedSystemdCommand(path string, arguments []string) bool {
	if path != "/usr/bin/systemctl" {
		return false
	}
	var unit string
	switch {
	case len(arguments) == 2 && arguments[0] == "start":
		unit = arguments[1]
	case len(arguments) == 3 && arguments[0] == "stop" && arguments[1] == "--no-block":
		unit = arguments[2]
	case len(arguments) == 3 && arguments[0] == "is-active" && arguments[1] == "--quiet":
		unit = arguments[2]
	default:
		return false
	}
	const prefix = "shakerproxy-capture@"
	const suffix = ".service"
	if !strings.HasPrefix(unit, prefix) || !strings.HasSuffix(unit, suffix) {
		return false
	}
	hexID := strings.TrimSuffix(strings.TrimPrefix(unit, prefix), suffix)
	return ValidSessionID("capture-" + hexID)
}
