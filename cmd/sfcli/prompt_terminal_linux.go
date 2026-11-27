// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// errNoTerminal: a hidden prompt needs a terminal this process is in the
// foreground of. Without one the CLI fails at once instead of waiting.
var errNoTerminal = errors.New("no terminal to ask on (stdin is not a terminal or the command runs in the background)")

// openPromptTerminal opens the controlling terminal for a hidden prompt,
// only when stdin is that terminal and this process group is in its
// foreground. A background job reading /dev/tty would be stopped by
// SIGTTIN and wait forever; a piped or detached run has no one to answer.
func openPromptTerminal() (*os.File, error) {
	if nonInteractiveEnv() {
		return nil, errNoTerminal
	}
	if _, err := unix.IoctlGetTermios(int(os.Stdin.Fd()), unix.TCGETS); err != nil {
		return nil, errNoTerminal
	}
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, errNoTerminal
	}
	foreground, err := unix.IoctlGetInt(int(tty.Fd()), unix.TIOCGPGRP)
	if err != nil || foreground != unix.Getpgrp() {
		_ = tty.Close()
		return nil, errNoTerminal
	}
	return tty, nil
}

// nonInteractiveEnv: SFC_NONINTERACTIVE=1 (or true/yes) means never
// prompt, fail instead, even on a terminal. It is the only switch (there is
// no flag), named like GIT_TERMINAL_PROMPT and GH_PROMPT_DISABLED.
func nonInteractiveEnv() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("SFC_NONINTERACTIVE"))) {
	case "1", "true", "yes":
		return true
	}
	return false
}
