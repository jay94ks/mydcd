// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"strconv"

	"github.com/jay94ks/seafield/internal/cli"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/containerops"
)

// Clearing logs is one request to every server's log store
// (devel/proposals/seafield-log-clear.md). Containers keep running, nothing
// is recreated and there is no operation to settle: a server that could not
// be reached keeps its logs, and sending the same command again clears them.

func appClearLogsCommand(g *globals) *cli.Command {
	var instance string
	return &cli.Command{
		Name:  "clear-logs",
		Args:  "APP [SERVICE]",
		Short: "Clear the stored logs of an app or one of its services",
		Long: `Clears the logs every server keeps for APP (or only SERVICE). The containers keep running.
Cleared logs cannot be restored. A server that is not reachable keeps its logs; run the command again later for it.`,
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&instance, "instance", "", "only this `TASK` of the service")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) < 1 || len(args) > 2 {
				return cli.Usagef("usage: sfcli app clear-logs APP [SERVICE]")
			}
			sel := containerops.Selection{App: args[0]}
			what := "app " + args[0]
			if len(args) == 2 {
				sel.Service = args[1]
				what = "service " + args[1] + " of app " + args[0]
			}
			if instance != "" {
				if sel.Service == "" {
					return cli.Usagef("--instance goes with SERVICE")
				}
				sel.Instance = instance
				what += " (" + instance + ")"
			}
			return clearLogs(c, g, s, sel, what)
		}),
	}
}

func standaloneClearLogsCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "clear-logs",
		Args:  "NAME",
		Short: "Clear a standalone's stored logs",
		Long: `Clears the logs every server keeps for the standalone. The container keeps running.
Cleared logs cannot be restored. A server that is not reachable keeps its logs; run the command again later for it.`,
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			name, err := standaloneName(args, "clear-logs", 0)
			if err != nil {
				return err
			}
			return clearLogs(c, g, s, containerops.Selection{Standalone: name}, "standalone "+name)
		}),
	}
}

// clearLogs confirms, sends one log clear and prints each server's answer.
// It fails (exit 1) when a server did not clear, after saying how many did.
func clearLogs(c *cli.Context, g *globals, s *session, sel containerops.Selection, what string) error {
	tenant, err := g.Tenant(s, true)
	if err != nil {
		return err
	}
	q := control.LogsClear{Tenant: tenant, Selection: sel}
	if !q.Valid() {
		return cli.Usagef("not a valid app, service, task or standalone name")
	}
	fmt.Fprintf(c.Err, "This clears the stored logs of %s on every server. The containers keep running; cleared logs cannot be restored.\n", what)
	if err := g.Prompter(c).Confirm("Go ahead?"); err != nil {
		return err
	}
	ctx, cancel := g.Deadline(c)
	defer cancel()
	reply, err := s.Client.ClearLogs(ctx, s.Target, s.Stored.Session, q)
	if err != nil {
		return err
	}
	cleared := 0
	for _, n := range reply.Nodes {
		if n.Code == "ok" {
			cleared++
		}
	}
	if err := cli.Print(c.Out, g.output.Format(), reply, func() cli.Rows {
		t := cli.Rows{Header: []string{"server", "result", "logs", "removed"}}
		for _, n := range reply.Nodes {
			t.Add(n.Node, n.Code, strconv.Itoa(n.Containers), strconv.Itoa(n.Removed))
		}
		return t
	}); err != nil {
		return err
	}
	if cleared < len(reply.Nodes) {
		fmt.Fprintf(c.Err, "%d of %d servers cleared; run the same command again for the rest.\n", cleared, len(reply.Nodes))
		return cli.ExitError{Code: 1}
	}
	return nil
}
