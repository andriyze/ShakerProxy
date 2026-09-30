package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// version is stamped at build time with -ldflags "-X main.version=<version>".
var version = "0.1.0-dev"

const defaultSocketPath = "/run/shakerproxy/gatewayd.sock"

// Exit codes are part of the CLI contract: 0 success, 1 failure, 2 usage.
const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2
)

type cli struct {
	stdout io.Writer
	stderr io.Writer
	stdin  io.Reader

	socket     string
	jsonOutput bool
	color      bool
	stdoutTTY  bool
	stdinTTY   bool

	now     func() time.Time
	geteuid func() int
	// execProgram replaces the process (release lifecycle commands).
	execProgram func(path string, args []string, env []string) error
	// runProgram runs a helper such as journalctl with inherited output.
	runProgram func(path string, args []string) error
	// outputProgram runs a helper and returns its standard output.
	outputProgram func(path string, args []string, env []string) ([]byte, error)
	sleep         func(time.Duration)
	// findExecutable returns the first existing executable candidate.
	findExecutable func(candidates ...string) string
	// maxPolls stops polling loops (watch, capture stop --wait) in tests.
	maxPolls int
}

func newCLI() *cli {
	c := &cli{
		stdout:  os.Stdout,
		stderr:  os.Stderr,
		stdin:   os.Stdin,
		socket:  envOr("SHAKERPROXY_GATEWAY_SOCKET", defaultSocketPath),
		now:     time.Now,
		geteuid: os.Geteuid,
		execProgram: func(path string, args []string, env []string) error {
			return syscall.Exec(path, args, env)
		},
		runProgram: func(path string, args []string) error {
			command := exec.Command(path, args...)
			command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
			command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8"}
			return command.Run()
		},
		outputProgram: func(path string, args []string, env []string) ([]byte, error) {
			command := exec.Command(path, args...)
			command.Stderr, command.Env = os.Stderr, env
			return command.Output()
		},
		sleep:          time.Sleep,
		findExecutable: firstExecutable,
	}
	c.stdoutTTY = isTerminal(fileDescriptor(os.Stdout))
	c.stdinTTY = isTerminal(fileDescriptor(os.Stdin))
	return c
}

func main() {
	os.Exit(newCLI().main(os.Args[1:]))
}

// usageError is a mistake in how a command was invoked (exit 2).
type usageError struct {
	command string
	message string
	// plain suppresses the usage block, e.g. for "Unknown command".
	plain bool
}

func (e *usageError) Error() string { return e.message }

func usagef(command, format string, args ...any) error {
	return &usageError{command: command, message: fmt.Sprintf(format, args...)}
}

// hintError is a failure with concrete next steps for the user (exit 1).
type hintError struct {
	message string
	hints   []string
	cause   error
}

func (e *hintError) Error() string { return e.message }

func (e *hintError) Unwrap() error { return e.cause }

func withHints(message string, hints ...string) error {
	return &hintError{message: message, hints: hints}
}

// silentFailure reports a non-zero exit whose explanation was already printed.
type silentFailure struct{ code int }

func (e *silentFailure) Error() string { return fmt.Sprintf("exit status %d", e.code) }

type globalOptions struct {
	socket  string
	json    bool
	noColor bool
	help    bool
	version bool
}

// extractGlobalFlags removes global flags from any position so
// `shakerproxy status --socket X` and `shakerproxy --json devices` both work.
// Everything after a literal "--" is left untouched.
func extractGlobalFlags(args []string) ([]string, globalOptions, error) {
	var options globalOptions
	rest := make([]string, 0, len(args))
	for index := 0; index < len(args); index++ {
		argument := args[index]
		switch {
		case argument == "--":
			rest = append(rest, args[index:]...)
			return rest, options, nil
		case argument == "--json" || argument == "-json":
			options.json = true
		case argument == "--no-color" || argument == "--no-colour":
			options.noColor = true
		case argument == "-h" || argument == "--help" || argument == "-help":
			options.help = true
		case argument == "--version":
			options.version = true
		case argument == "--socket" || argument == "-socket":
			if index+1 >= len(args) || args[index+1] == "" {
				return nil, options, usagef("", "--socket needs a path, for example --socket /run/shakerproxy/gatewayd.sock")
			}
			options.socket = args[index+1]
			index++
		case strings.HasPrefix(argument, "--socket=") || strings.HasPrefix(argument, "-socket="):
			options.socket = argument[strings.IndexByte(argument, '=')+1:]
			if options.socket == "" {
				return nil, options, usagef("", "--socket needs a path")
			}
		default:
			rest = append(rest, argument)
		}
	}
	return rest, options, nil
}

// main runs one CLI invocation and returns the process exit code.
func (c *cli) main(args []string) int {
	rest, options, err := extractGlobalFlags(args)
	if err == nil {
		c.jsonOutput = options.json
		c.color = c.stdoutTTY && !options.noColor && os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb"
		if options.socket != "" {
			c.socket = options.socket
		}
		err = c.dispatch(rest, options)
	}
	return c.report(err)
}

func (c *cli) dispatch(args []string, options globalOptions) error {
	if len(args) == 0 {
		switch {
		case options.version:
			return c.versionCommand(nil)
		case options.help:
			c.printFullHelp(c.stdout)
		default:
			c.printOverview(c.stdout)
		}
		return nil
	}
	name := args[0]
	if name == "help" {
		return c.helpCommand(args[1:])
	}
	command := lookupCommand(name)
	if command == nil {
		return unknownCommandError(name)
	}
	if options.help {
		c.printCommandHelp(c.stdout, command)
		return nil
	}
	return command.run(c, args[1:])
}

// report prints an error in a consistent, friendly format and maps it to an
// exit code.
func (c *cli) report(err error) int {
	if err == nil {
		return exitOK
	}
	var silent *silentFailure
	if errors.As(err, &silent) {
		return silent.code
	}
	var usage *usageError
	if errors.As(err, &usage) {
		fmt.Fprintln(c.stderr, usage.message)
		if usage.plain {
			return exitUsage
		}
		if command := lookupCommand(usage.command); command != nil {
			fmt.Fprintln(c.stderr)
			fmt.Fprintln(c.stderr, "Usage:")
			for _, line := range command.usage {
				fmt.Fprintf(c.stderr, "  shakerproxy %s\n", line)
			}
			fmt.Fprintf(c.stderr, "\nRun `shakerproxy help %s` for details and examples.\n", command.name)
		} else {
			fmt.Fprintln(c.stderr, "Run `shakerproxy help` to see all commands.")
		}
		return exitUsage
	}
	fmt.Fprintf(c.stderr, "Error: %s\n", capitalize(err.Error()))
	var hinted *hintError
	if errors.As(err, &hinted) {
		for _, hint := range hinted.hints {
			fmt.Fprintf(c.stderr, "  → %s\n", hint)
		}
	}
	return exitFailure
}

func capitalize(message string) string {
	if message == "" {
		return message
	}
	return strings.ToUpper(message[:1]) + message[1:]
}

// newFlags creates a quiet flag set; parse errors are reported as usage
// errors by parseFlags.
func newFlags(name string) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.Usage = func() {}
	return flags
}

// parseFlags parses flags that may appear before, between, or after
// positional arguments and returns the positionals. A literal "--" ends flag
// parsing.
func parseFlags(command string, flags *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	remaining := args
	for {
		terminator := -1
		for index, argument := range remaining {
			if argument == "--" {
				terminator = index
				break
			}
		}
		head, tail := remaining, []string(nil)
		if terminator >= 0 {
			head, tail = remaining[:terminator], remaining[terminator+1:]
		}
		if err := flags.Parse(head); err != nil {
			return nil, usagef(command, "%s", flagErrorMessage(err))
		}
		unparsed := flags.Args()
		if len(unparsed) == 0 {
			if terminator >= 0 {
				positional = append(positional, tail...)
			}
			return positional, nil
		}
		positional = append(positional, unparsed[0])
		remaining = unparsed[1:]
		if terminator >= 0 {
			remaining = append(append(append([]string{}, remaining...), "--"), tail...)
		}
	}
}

func flagErrorMessage(err error) string {
	message := err.Error()
	if strings.HasPrefix(message, "flag provided but not defined: ") {
		return fmt.Sprintf("Unknown option %s.", strings.TrimPrefix(message, "flag provided but not defined: "))
	}
	if strings.HasPrefix(message, "flag needs an argument: ") {
		return fmt.Sprintf("Option %s needs a value.", strings.TrimPrefix(message, "flag needs an argument: "))
	}
	return capitalize(message) + "."
}

// expectArgs checks positional argument counts and names what is missing
// or unexpected.
func expectArgs(command string, args []string, minimum, maximum int, names ...string) error {
	if len(args) < minimum {
		missing := "an argument"
		if len(args) < len(names) {
			missing = names[len(args)]
		}
		return usagef(command, "Missing %s.", missing)
	}
	if maximum >= 0 && len(args) > maximum {
		return usagef(command, "Unexpected extra argument %q.", args[maximum])
	}
	return nil
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
