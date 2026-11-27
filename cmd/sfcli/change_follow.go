// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"time"

	"github.com/jay94ks/seafield/internal/cli"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/userauth"
)

// A follower reads how far accepted long work has come. It returns Accepted
// while the work runs and Done or Failed at the end, with one line of
// progress.
type follower func(ctx context.Context, s *session, op control.UserOperation) (cli.State, string, error)

var followers = map[string]follower{}

// followKind registers an async kind: `sfcli op show|resume` settles the
// saved original like any change and then asks the follower how far the
// work has come.
func followKind(kind string, follow follower) {
	followers[kind] = follow
	opKinds[kind] = func(g *globals) cli.Handler {
		base := changeHandler(g, nil, true)
		then := func(call func(*cli.Context, cli.Op) (cli.State, string, error)) func(*cli.Context, cli.Op) (cli.State, string, error) {
			return func(c *cli.Context, op cli.Op) (cli.State, string, error) {
				st, detail, err := call(c, op)
				if err != nil || st != cli.Accepted {
					return st, detail, err
				}
				s, err := g.opSession(c, op)
				if err != nil {
					return "", "", err
				}
				defer s.Close()
				record, err := userauth.LoadOperation(s.Home, s.Client, s.Stored.Session, op.ID)
				if err != nil {
					return "", "", err
				}
				ctx, cancel := g.Deadline(c)
				defer cancel()
				return follow(ctx, s, record.Operation)
			}
		}
		return cli.Handler{Show: then(base.Show), Resume: then(base.Resume)}
	}
}

// apply sends ch and, for async work, follows it until it ends, Ctrl-C or
// --no-wait. Interrupting never cancels the work; `sfcli op show ID` picks
// it up again.
func (g *globals) apply(c *cli.Context, s *session, ch change, noWait bool) error {
	fmt.Fprintf(c.Err, "operation %s: %s\n", ch.ID, ch.Summary)
	if _, err := g.send(c, s, ch); err != nil {
		return unknown(err)
	}
	if !ch.Async {
		fmt.Fprintln(c.Out, "done")
		return nil
	}
	if noWait {
		fmt.Fprintf(c.Out, "accepted; follow with 'sfcli op show %s'\n", ch.ID)
		return nil
	}
	record, err := userauth.LoadOperation(s.Home, s.Client, s.Stored.Session, ch.ID)
	if err != nil {
		return err
	}
	follow := followers[ch.Kind]
	last := ""
	for {
		ctx, cancel := g.Deadline(c)
		st, detail, err := follow(ctx, s, record.Operation)
		cancel()
		// A leader change refuses or loses a progress read; the work goes on
		// on the server, so keep waiting and read again.
		if err != nil && c.Ctx.Err() == nil && !transient(err) {
			return err
		}
		if err == nil {
			if detail != last {
				fmt.Fprintln(c.Err, detail)
				last = detail
			}
			if st.Final() {
				g.settle(ch.ID, st, detail)
				fmt.Fprintln(c.Out, st)
				if st == cli.Failed {
					return cli.ExitError{Code: 1}
				}
				return nil
			}
		}
		select {
		case <-c.Ctx.Done():
			fmt.Fprintf(c.Out, "still running; follow with 'sfcli op show %s'\n", ch.ID)
			return nil
		case <-time.After(2 * time.Second):
		}
	}
}
