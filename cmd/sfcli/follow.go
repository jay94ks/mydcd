// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/jay94ks/seafield/internal/cli"
)

// waitFlags is --no-wait for changes whose work continues after the server
// accepts them.
type waitFlags struct{ noWait bool }

func (w *waitFlags) register(fs *flag.FlagSet) {
	fs.BoolVar(&w.noWait, "no-wait", false, "return once the server accepts the change; check later with 'sfcli op show ID'")
}

// errStillRunning is returned when waiting stopped (Ctrl-C) before the work
// finished. Nothing is cancelled on the server.
type errStillRunning struct{ id string }

func (e errStillRunning) Error() string {
	return fmt.Sprintf("stopped waiting; %s is still running on the server. Check it with 'sfcli op show %s'", e.id, e.id)
}

// follow polls an accepted operation until it is final, printing each new
// progress line on stderr and keeping the op index up to date. poll gets a
// context bounded by --timeout for one read. Ctrl-C stops waiting, not the
// work.
func (g *globals) follow(c *cli.Context, id string, poll func(c *cli.Context) (cli.State, string, error)) (cli.State, string, error) {
	last := ""
	for {
		st, line, err := poll(c)
		if err != nil {
			if c.Ctx.Err() != nil {
				return cli.Accepted, last, errStillRunning{id}
			}
			// A leader change refuses or loses one read; the work goes on on
			// the server, so read again after a pause.
			if !transient(err) {
				return "", "", err
			}
			if !pauseFor(c.Ctx, transientPause) {
				return cli.Accepted, last, errStillRunning{id}
			}
			continue
		}
		if line != last {
			fmt.Fprintf(c.Err, "%s: %s\n", id, line)
			last = line
		}
		if st.Final() {
			g.settle(id, st, line)
			if st == cli.Failed {
				return st, line, errors.New(line)
			}
			return st, line, nil
		}
		g.settle(id, st, line)
		timer := time.NewTimer(time.Second)
		select {
		case <-c.Ctx.Done():
			timer.Stop()
			return st, line, errStillRunning{id}
		case <-timer.C:
		}
	}
}
