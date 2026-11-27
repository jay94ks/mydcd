// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/jay94ks/seafield/internal/cli"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
)

// nodeShellCommandTree is `sfcli node shell NODE` and its policy commands.
func nodeShellCommandTree(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "shell",
		Args:  "NODE",
		Short: "Open a shell on a server, or manage who may",
		Long: `Opens an interactive shell on NODE as the server's shell account. The
session is recorded on the server; losing the connection closes it and
never opens another one.`,
		Run: func(c *cli.Context, args []string) error {
			node, err := nodeArg(args, "shell")
			if err != nil {
				return err
			}
			rows, cols := containerTerminalSize(os.Stdin)
			q := control.NodeShellOpen{Node: node, Cols: cols, Rows: rows}
			if !q.Valid() {
				return cli.Usagef("run node shell in a terminal (1..1000 rows and columns)")
			}
			s, err := g.open(c)
			if err != nil {
				return err
			}
			defer s.Close()
			id := cli.NewID()
			if _, err := g.send(c, s, change{Summary: "node shell " + node, ID: id, Action: "open-node-shell", Payload: q}); err != nil {
				return unknown(err)
			}
			restore, err := makeContainerTerminalRaw(os.Stdin)
			if err != nil {
				return err
			}
			defer restore()
			channel, metadata, err := s.Client.OpenNodeShell(c.Ctx, s.Target, s.Stored.Session, id)
			if err != nil {
				return err
			}
			defer channel.Close()
			fmt.Fprintf(c.Err, "shell %s on %s as %s\r\n", id, metadata.Node, metadata.Account)
			if code := runNodeShellTerminal(c.Ctx, channel, c.Out, c.Err); code != 0 {
				return cli.ExitError{Code: code}
			}
			return nil
		},
		Sub: []*cli.Command{
			nodeShellPolicyCommand(g),
			nodeShellGrantCommand(g),
			nodeShellSessionsCommand(g),
			nodeShellCloseCommand(g),
		},
	}
}

func shellPolicy(ctx context.Context, s *session) (*control.NodeShellPolicyView, error) {
	reply, err := s.Client.NodeShellPolicy(ctx, s.Target, s.Stored.Session)
	if err != nil {
		return nil, err
	}
	if reply.NodeShellPolicy == nil {
		return nil, errors.New("server sent no shell policy")
	}
	return reply.NodeShellPolicy, nil
}

func nodeShellPolicyCommand(g *globals) *cli.Command {
	var f changeFlags
	var enable, disable, sudo bool
	var maxSessions int
	var idle time.Duration
	var shell string
	return &cli.Command{
		Name:  "policy",
		Args:  "[NODE]",
		Short: "Show or change the shell policy (system administrator)",
		Long: `Without options, shows the cluster shell policy, each server's setting
and the grants. --enable/--disable, --max-sessions and --idle change the
cluster default. With NODE, --shell on|off|inherit (and --sudo) set that
server.`,
		Flags: func(fs *flag.FlagSet) {
			fs.BoolVar(&enable, "enable", false, "allow shells by default")
			fs.BoolVar(&disable, "disable", false, "refuse shells by default")
			fs.IntVar(&maxSessions, "max-sessions", 0, "sessions per user per server (1..16)")
			fs.DurationVar(&idle, "idle", 0, "close a shell after this long without input (1m..24h)")
			fs.StringVar(&shell, "shell", "", "with NODE: on, off or inherit")
			fs.BoolVar(&sudo, "sudo", false, "with NODE and --shell on: allow sudo")
			f.register(fs, false, false)
		},
		Run: func(c *cli.Context, args []string) error {
			node := ""
			if len(args) > 0 {
				var err error
				if node, err = nodeArg(args, "policy"); err != nil {
					return err
				}
			}
			cluster := c.Set("enable") || c.Set("disable") || c.Set("max-sessions") || c.Set("idle")
			switch {
			case enable && disable:
				return cli.Usagef("--enable and --disable cannot be used together")
			case node != "" && cluster:
				return cli.Usagef("--enable, --disable, --max-sessions and --idle change the cluster default; leave out NODE")
			case node != "" && shell != "on" && shell != "off" && shell != "inherit":
				return cli.Usagef("with NODE, --shell must be on, off or inherit")
			case node == "" && (shell != "" || c.Set("sudo")):
				return cli.Usagef("--shell and --sudo need a NODE")
			}
			s, err := g.open(c)
			if err != nil {
				return err
			}
			defer s.Close()
			ctx, cancel := g.Deadline(c)
			defer cancel()
			p, err := shellPolicy(ctx, s)
			if err != nil {
				return err
			}
			switch {
			case node != "":
				return g.apply(c, s, change{Summary: "node shell policy " + node + " --shell " + shell, ID: f.id.Get(), Action: "set-node-shell-node",
					Expected: f.expect(p.Revision), Payload: control.NodeShellNodeChange{Node: node, Shell: shell, Sudo: sudo}}, false)
			case cluster:
				q := control.NodeShellPolicyChange{Enabled: p.Enabled, MaxSessions: p.MaxSessions, IdleSeconds: p.IdleSeconds}
				if enable || disable {
					q.Enabled = enable
				}
				if c.Set("max-sessions") {
					q.MaxSessions = maxSessions
				}
				if c.Set("idle") {
					q.IdleSeconds = int(idle / time.Second)
				}
				if q.MaxSessions < 1 || q.MaxSessions > 16 || q.IdleSeconds < 60 || q.IdleSeconds > 86400 {
					return cli.Usagef("--max-sessions must be 1..16 and --idle 1m..24h")
				}
				return g.apply(c, s, change{Summary: "node shell policy", ID: f.id.Get(), Action: "set-node-shell-policy",
					Expected: f.expect(p.Revision), Payload: q}, false)
			}
			if g.output.Format() == cli.Table {
				fmt.Fprintf(c.Out, "Shells: %s by default, %d per user per server, idle %s, account %s\n\n",
					map[bool]string{true: "allowed", false: "refused"}[p.Enabled], p.MaxSessions, time.Duration(p.IdleSeconds)*time.Second, p.Account)
			}
			return cli.Print(c.Out, g.output.Format(), p, func() cli.Rows {
				t := cli.Rows{Header: []string{"node", "shell", "sudo", "enabled", "ready"}}
				for _, n := range p.Nodes {
					t.Add(n.Node, n.Shell, n.Sudo, n.Enabled, n.Ready)
				}
				return t
			})
		},
	}
}

func nodeShellGrantCommand(g *globals) *cli.Command {
	var f changeFlags
	var revoke bool
	return &cli.Command{
		Name:  "grant",
		Args:  "USER [NODE...]",
		Short: "Set the servers a user may open shells on (system administrator)",
		Long:  "Replaces the user's grant with exactly the listed servers. --revoke removes the grant.",
		Flags: func(fs *flag.FlagSet) {
			fs.BoolVar(&revoke, "revoke", false, "remove the user's grant")
			f.register(fs, false, false)
		},
		Run: func(c *cli.Context, args []string) error {
			if len(args) == 0 || !lifecycle.ValidID(args[0]) {
				return cli.Usagef("grant needs a user")
			}
			user, nodes := args[0], args[1:]
			if revoke == (len(nodes) > 0) {
				return cli.Usagef("give the servers, or --revoke without servers")
			}
			seen := map[string]bool{}
			for _, n := range nodes {
				if !lifecycle.ValidID(n) || seen[n] {
					return cli.Usagef("invalid or repeated node %q", n)
				}
				seen[n] = true
			}
			if len(nodes) > 256 {
				return cli.Usagef("at most 256 servers")
			}
			s, err := g.open(c)
			if err != nil {
				return err
			}
			defer s.Close()
			ctx, cancel := g.Deadline(c)
			defer cancel()
			p, err := shellPolicy(ctx, s)
			if err != nil {
				return err
			}
			summary := "node shell grant " + user
			if revoke {
				summary += " --revoke"
				nodes = nil
			}
			return g.apply(c, s, change{Summary: summary, ID: f.id.Get(), Action: "set-node-shell-grant",
				Expected: f.expect(p.Revision), Payload: control.NodeShellGrantChange{User: user, Nodes: nodes}}, false)
		},
	}
}

func nodeShellSessionsCommand(g *globals) *cli.Command {
	var stateFilter, node string
	return &cli.Command{
		Name:  "sessions",
		Short: "List shell sessions",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&stateFilter, "state", "", "only `open` or closed sessions")
			fs.StringVar(&node, "node", "", "only sessions on this `node`")
		},
		Run: func(c *cli.Context, args []string) error {
			q := control.NodeShellSessionsQuery{State: stateFilter, Node: node}
			if len(args) != 0 || !q.Valid() {
				return cli.Usagef("sessions takes no arguments; --state is open or closed")
			}
			s, err := g.open(c)
			if err != nil {
				return err
			}
			defer s.Close()
			ctx, cancel := g.Deadline(c)
			defer cancel()
			sessions := []control.NodeShellSession{}
			after := ""
			for pages := 0; ; pages++ {
				if pages == 256 {
					return errors.New("too many session pages")
				}
				reply, err := s.Client.NodeShellSessions(ctx, s.Target, s.Stored.Session, after, q)
				if err != nil {
					return err
				}
				if reply.NodeShellSessions == nil {
					return errors.New("server sent no session page")
				}
				sessions = append(sessions, reply.NodeShellSessions.Sessions...)
				if after = reply.NodeShellSessions.Next; after == "" {
					break
				}
			}
			return cli.Print(c.Out, g.output.Format(), sessions, func() cli.Rows {
				t := cli.Rows{Header: []string{"session", "user", "node", "state", "opened", "sudo"}}
				for _, x := range sessions {
					opened := ""
					if x.OpenedAt > 0 {
						opened = time.Unix(x.OpenedAt, 0).Local().Format("2006-01-02 15:04")
					}
					t.Add(x.SessionID, x.Username, x.Node, x.State, opened, x.Sudo)
				}
				return t
			})
		},
	}
}

func nodeShellCloseCommand(g *globals) *cli.Command {
	var f changeFlags
	return &cli.Command{
		Name:  "close",
		Args:  "SESSION",
		Short: "Close an open shell session",
		Flags: func(fs *flag.FlagSet) { f.register(fs, false, false) },
		Run: func(c *cli.Context, args []string) error {
			if len(args) != 1 || !lifecycle.ValidID(args[0]) {
				return cli.Usagef("close needs one session ID (from 'sfcli node shell sessions')")
			}
			s, err := g.open(c)
			if err != nil {
				return err
			}
			defer s.Close()
			return g.apply(c, s, change{Summary: "node shell close " + args[0], ID: f.id.Get(), Action: "close-node-shell",
				Payload: control.NodeShellClose{SessionID: args[0]}}, false)
		},
	}
}

// Heartbeats keep the authenticated stream alive; only native byte movement
// advances its idle clock. A lost stream never creates a new session.
func nodeShellHeartbeat(ctx context.Context, c *userauth.NodeShellChannel) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(10 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				if c.Send(sfcp.NodeShellRecord{Kind: "ping"}) != nil {
					_ = c.Close()
					return
				}
			}
		}
	}()
	return done
}
