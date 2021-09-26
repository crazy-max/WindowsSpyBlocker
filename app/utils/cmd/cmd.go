package cmd

import (
	"bytes"
	"os/exec"
	"strings"

	"golang.org/x/sys/windows"
)

// Options of command
type Options struct {
	Command    string
	Args       []string
	WorkingDir string
	HideWindow bool
}

// Result of command
type Result struct {
	Options  Options
	ExitCode uint32
	Stdout   string
	Stderr   string
}

// Exec command wrapper
func Exec(options Options) (Result, error) {
	result := Result{Options: options}

	command := exec.Command(options.Command, options.Args...)
	commandStdout := &bytes.Buffer{}
	command.Stdout = commandStdout
	commandStderr := &bytes.Buffer{}
	command.Stderr = commandStderr
	command.SysProcAttr = &windows.SysProcAttr{HideWindow: options.HideWindow}

	if options.WorkingDir != "" {
		command.Dir = options.WorkingDir
	}

	if err := command.Start(); err != nil {
		return result, err
	}

	command.Wait()
	waitStatus := command.ProcessState.Sys().(windows.WaitStatus)

	result.ExitCode = waitStatus.ExitCode
	result.Stdout = strings.TrimSpace(commandStdout.String())
	result.Stderr = strings.TrimSpace(commandStderr.String())

	return result, nil
}
