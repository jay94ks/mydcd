// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
)

var (
	// ErrDeclined means the person answered no. Nothing was sent.
	ErrDeclined = errors.New("cancelled; nothing was changed")
	// ErrNeedsConfirmation means no one can answer the question: input is
	// not a terminal or MYDC_NONINTERACTIVE=1 is set, and -y was not.
	ErrNeedsConfirmation = errors.New("this change needs confirmation; run it in a terminal or pass -y")
)

// Prompter asks y/N before a change. Interactive is true when In and Out are
// a terminal. Yes is -y; NoInput is MYDC_NONINTERACTIVE=1.
type Prompter struct {
	In          io.Reader
	Out         io.Writer
	Interactive bool
	Yes         bool
	NoInput     bool
}

// Confirm returns nil to go ahead. The caller prints what will change before
// asking, so the answer is about exactly that.
func (p Prompter) Confirm(question string) error {
	if p.Yes {
		return nil
	}
	if !p.Interactive || p.NoInput {
		return ErrNeedsConfirmation
	}
	fmt.Fprintf(p.Out, "%s [y/N] ", question)
	line, err := bufio.NewReader(p.In).ReadString('\n')
	if err != nil && line == "" {
		return ErrDeclined
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return nil
	}
	return ErrDeclined
}
