// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"slices"

	"github.com/jay94ks/mydcd/internal/cli"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/userauth"
)

// confirmSend prints what the change does, asks y/N (-y skips) and sends it
// with g.send. It is the usual path of the cd, lifecycle, ingress,
// certificate and standalone changes.
func (g *globals) confirmSend(c *cli.Context, s *session, impact string, ch change) (*state.Result, error) {
	if impact != "" {
		fmt.Fprintln(c.Err, impact)
	}
	if err := g.Prompter(c).Confirm("Go ahead?"); err != nil {
		return nil, err
	}
	fmt.Fprintf(c.Err, "Operation %s\n", ch.ID)
	return g.send(c, s, ch)
}

// sendAndPrint is confirmSend followed by the one-line result.
func (g *globals) sendAndPrint(c *cli.Context, s *session, impact string, ch change) error {
	result, err := g.confirmSend(c, s, impact, ch)
	if err != nil {
		return err
	}
	return printApplied(c, g, ch.ID, result)
}

// printApplied reports a change the server applied.
func printApplied(c *cli.Context, g *globals, id string, result *state.Result) error {
	return cli.Print(c.Out, g.output.Format(), map[string]any{"id": id, "state": cli.Done, "result": result}, func() cli.Rows {
		t := cli.Rows{Header: []string{"id", "state", "revision"}}
		t.Add(id, cli.Done, result.Revision)
		return t
	})
}

// moduleEpoch reads the module epoch a new change is signed for.
func (g *globals) moduleEpoch(c *cli.Context, s *session) (uint64, error) {
	ctx, cancel := g.Deadline(c)
	defer cancel()
	view, err := s.Client.Query(ctx, s.Target, s.Stored.Session, "whoami", "")
	if err != nil {
		return 0, err
	}
	return max(1, view.ModuleEpoch), nil
}

// savedChange continues the change this computer already saved under --id,
// without reading the current state again: after it was applied the state
// it was built from has moved on (the candidate is deployed, the revision
// went up), so rebuilding it would not match. It reports false when id is
// empty or has nothing saved. actions are the actions the command can send.
func (g *globals) savedChange(c *cli.Context, s *session, id, summary string, actions ...string) (bool, error) {
	if id == "" {
		return false, nil
	}
	record, err := userauth.LoadOperation(s.Home, s.Client, s.Stored.Session, id)
	if errors.Is(err, userauth.ErrOperationMissing) {
		return false, nil
	}
	if err != nil {
		return true, err
	}
	saved := record.Operation.Change
	if !slices.Contains(actions, saved.Action) {
		return true, fmt.Errorf("--id %s already names a %s change; choose another ID", id, saved.Action)
	}
	fmt.Fprintf(c.Err, "Operation %s (continuing the saved change)\n", id)
	result, err := g.send(c, s, change{ID: id, Summary: summary, Action: saved.Action, Expected: saved.Expected, Payload: saved.Payload})
	if err != nil {
		return true, err
	}
	return true, printApplied(c, g, id, result)
}
