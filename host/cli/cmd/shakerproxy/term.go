package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// isTerminal reports whether the file descriptor is an interactive terminal.
func isTerminal(fd int) bool {
	if fd < 0 {
		return false
	}
	_, err := unix.IoctlGetTermios(fd, ioctlReadTermios)
	return err == nil
}

func fileDescriptor(value any) int {
	if file, ok := value.(*os.File); ok && file != nil {
		return int(file.Fd())
	}
	return -1
}

// readPasswordFromTerminal prompts on stderr and reads one line from the
// terminal with echo disabled. The terminal state is always restored.
func readPasswordFromTerminal(input *os.File, prompt string, stderr io.Writer) (string, error) {
	fd := int(input.Fd())
	original, err := unix.IoctlGetTermios(fd, ioctlReadTermios)
	if err != nil {
		return "", errors.New("no terminal is available to ask for the password")
	}
	silent := *original
	silent.Lflag &^= unix.ECHO
	silent.Lflag |= unix.ICANON | unix.ISIG
	silent.Iflag |= unix.ICRNL
	fmt.Fprint(stderr, prompt)
	// Ctrl-C must not leave the shell without echo: restore the terminal
	// before exiting on an interrupt.
	interrupts := make(chan os.Signal, 1)
	signal.Notify(interrupts, os.Interrupt, syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		select {
		case <-interrupts:
			_ = unix.IoctlSetTermios(fd, ioctlWriteTermios, original)
			fmt.Fprintln(stderr)
			os.Exit(130)
		case <-done:
		}
	}()
	defer func() {
		signal.Stop(interrupts)
		close(done)
	}()
	if err := unix.IoctlSetTermios(fd, ioctlWriteTermios, &silent); err != nil {
		return "", fmt.Errorf("disable terminal echo: %w", err)
	}
	defer func() {
		_ = unix.IoctlSetTermios(fd, ioctlWriteTermios, original)
		fmt.Fprintln(stderr)
	}()
	return readLine(input, 1024)
}

// readLine reads one bounded line without the trailing newline.
func readLine(reader io.Reader, maximum int) (string, error) {
	buffered := bufio.NewReaderSize(reader, 64)
	var builder strings.Builder
	for {
		value, err := buffered.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) && builder.Len() > 0 {
				break
			}
			if errors.Is(err, io.EOF) {
				return "", errors.New("no input was provided")
			}
			return "", err
		}
		if value == '\n' {
			break
		}
		if builder.Len() >= maximum {
			return "", errors.New("input line is too long")
		}
		builder.WriteByte(value)
	}
	return strings.TrimRight(builder.String(), "\r"), nil
}
