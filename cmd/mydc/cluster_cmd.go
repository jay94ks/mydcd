// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/jay94ks/mydcd/internal/cli"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/userauth"
)

// clusterCommand is `mydc cluster`: the running cluster as a whole. Local
// connection profiles are `mydc context`.
func clusterCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "cluster",
		Short: "Check and maintain the running cluster",
		Sub: []*cli.Command{
			clusterStatusCommand(g),
			clusterMeshCommand(g),
			clusterReconnectCommand(g),
			clusterCompactCommand(g),
			clusterCLIPolicyCommand(g),
		},
	}
}

func clusterStatusCommand(g *globals) *cli.Command {
	var writes bool
	return &cli.Command{
		Name:  "status",
		Short: "Show the leader, quorum and each server's replication state (system administrator)",
		Long: `Shows the consensus state as last applied by the server you are connected
to. It does not wait for a quorum read; check STALE before trusting a row.

With --writes, shows instead what the leader appended to the Raft log in its
current term, by kind. An idle cluster should add nothing. Only the leader
counts writes, so the command asks the leader when the context knows it.`,
		Flags: func(fs *flag.FlagSet) {
			fs.BoolVar(&writes, "writes", false, "show the leader's Raft writes by kind")
		},
		Run: func(c *cli.Context, args []string) error {
			if len(args) != 0 {
				return cli.Usagef("status takes no arguments")
			}
			s, err := g.open(c)
			if err != nil {
				return err
			}
			defer s.Close()
			ctx, cancel := g.Deadline(c)
			defer cancel()
			var status *userauth.RaftStatus
			after := ""
			for pages := 0; ; pages++ {
				if pages == 256 {
					return errors.New("too many status pages")
				}
				reply, err := s.Client.RaftStatusPage(ctx, s.Target, s.Stored.Session, after)
				if err != nil {
					return err
				}
				if reply.RaftStatus == nil {
					return errors.New("server sent no cluster status")
				}
				if status == nil {
					status = reply.RaftStatus
				} else {
					if reply.RaftStatus.NodesRootRevision != status.NodesRootRevision {
						return errors.New("the node list changed while it was read; try again")
					}
					status.Nodes = append(status.Nodes, reply.RaftStatus.Nodes...)
				}
				if after = reply.RaftStatus.NodesNext; after == "" {
					break
				}
			}
			status.NodesNext = ""
			if writes {
				if status.Writes == nil && status.Leader != status.ObservedBy {
					// Only the leader counts writes: ask it directly when the
					// context knows its endpoint.
					for _, peer := range s.Client.Peers {
						if peer.ID != status.Leader || status.Leader == "" {
							continue
						}
						reply, err := s.Client.RaftStatusPage(ctx, peer, s.Stored.Session, "")
						if err != nil {
							return fmt.Errorf("ask leader %s: %w", status.Leader, err)
						}
						if reply.RaftStatus != nil {
							status = reply.RaftStatus
						}
						break
					}
				}
				if status.Writes == nil && status.Leader != status.ObservedBy {
					return fmt.Errorf("%s is not the leader and the context has no endpoint for leader %s; add it with 'mydc context trust'", status.ObservedBy, status.Leader)
				}
				if g.output.Format() == cli.Table && status.WritesSince != 0 {
					fmt.Fprintf(c.Out, "Leader %s, term %d, since %s\n\n", status.Leader, status.Term, time.UnixMilli(int64(status.WritesSince)).Local().Format("2006-01-02 15:04:05"))
				}
				return cli.Print(c.Out, g.output.Format(), status.Writes, func() cli.Rows {
					t := cli.Rows{Header: []string{"kind", "count"}}
					for _, w := range status.Writes {
						t.Add(w.Kind, w.Count)
					}
					return t
				})
			}
			if g.output.Format() == cli.Table {
				fmt.Fprintf(c.Out, "Leader: %s  Term: %d  Voters: %d (quorum %d, responding %d)  Committed: %d  Stale: %v\n\n",
					status.Leader, status.Term, status.Voters, status.Quorum, status.RespondingVoters, status.CommitIndex, status.Stale)
			}
			return cli.Print(c.Out, g.output.Format(), status, func() cli.Rows {
				t := cli.Rows{Header: []string{"node", "role", "term", "applied", "lag", "stale"}}
				for _, n := range status.Nodes {
					t.Add(n.Node, n.Role, n.Term, countText(n.AppliedIndex), countText(n.Lag), n.Stale)
				}
				return t
			})
		},
	}
}

func clusterMeshCommand(g *globals) *cli.Command {
	var all bool
	var node string
	return &cli.Command{
		Name:  "mesh",
		Short: "Show the links between servers",
		Long:  "Shows the links between the servers the tenant may use, with --all every link (system administrator).",
		Flags: func(fs *flag.FlagSet) {
			fs.BoolVar(&all, "all", false, "every link, not only the tenant's servers (system administrator)")
			fs.StringVar(&node, "node", "", "only links of this `node`")
		},
		Run: func(c *cli.Context, args []string) error {
			if len(args) != 0 {
				return cli.Usagef("mesh takes no arguments")
			}
			if node != "" && !lifecycle.ValidID(node) {
				return cli.Usagef("%q is not a valid node name", node)
			}
			s, err := g.open(c)
			if err != nil {
				return err
			}
			defer s.Close()
			tenant := ""
			if !all {
				if tenant, err = g.Tenant(s, true); err != nil {
					return err
				}
			}
			ctx, cancel := g.Deadline(c)
			defer cancel()
			links := []control.MeshLinkView{}
			after := ""
			for pages := 0; ; pages++ {
				if pages == 256 {
					return errors.New("too many link pages")
				}
				reply, err := s.Client.NodeObservationPage(ctx, s.Target, s.Stored.Session, "mesh-links", tenant, node, after)
				if err != nil {
					return err
				}
				if reply.MeshLinks == nil {
					return errors.New("server sent no link page")
				}
				links = append(links, reply.MeshLinks.Links...)
				if after = reply.MeshLinks.Next; after == "" {
					break
				}
			}
			return cli.Print(c.Out, g.output.Format(), links, func() cli.Rows {
				t := cli.Rows{Header: []string{"node", "peer", "state", "stale"}}
				for _, l := range links {
					t.Add(l.NodeA, l.NodeB, l.State, l.Stale)
				}
				return t
			})
		},
	}
}

func init() {
	followKind("cluster-reconnect", followReconnect)
	followKind("cluster-compact", followCompact)
}

func clusterReconnectCommand(g *globals) *cli.Command {
	var f changeFlags
	return &cli.Command{
		Name:  "reconnect",
		Args:  "NODE PEER",
		Short: "Rebuild a broken link between two servers (system administrator)",
		Long:  "Rebuilds the link from NODE to PEER when 'mydc cluster mesh' shows it down. Working links are never touched.",
		Flags: func(fs *flag.FlagSet) { f.register(fs, true, true) },
		Run: func(c *cli.Context, args []string) error {
			if len(args) != 2 || !lifecycle.ValidID(args[0]) || !lifecycle.ValidID(args[1]) || args[0] == args[1] {
				return cli.Usagef("reconnect needs two different node names")
			}
			node, peer := args[0], args[1]
			id := f.id.Get()
			s, err := g.open(c)
			if err != nil {
				return err
			}
			defer s.Close()
			ctx, cancel := g.Deadline(c)
			defer cancel()
			reply, err := s.Client.QueryTunnelReconnect(ctx, s.Target, s.Stored.Session, true, control.TunnelQuery{Node: node, Peer: peer})
			if err != nil {
				return err
			}
			if reply.TunnelPlan == nil {
				return errors.New("server sent no reconnect plan")
			}
			fmt.Fprintf(c.Err, "%s -> %s (%s) is down\n", node, peer, reply.TunnelPlan.Endpoint)
			if f.dryRun {
				return cli.Print(c.Out, g.output.Format(), reply.TunnelPlan, nil)
			}
			return g.apply(c, s, change{Kind: "cluster-reconnect", Async: true, Summary: "cluster reconnect " + node + " " + peer, ID: id,
				Action: "reconnect-tunnel", Payload: control.TunnelChange{Operation: id, Plan: *reply.TunnelPlan}}, f.noWait)
		},
	}
}

func operationOf(op control.UserOperation) (string, error) {
	var q struct{ Operation string }
	if err := json.Unmarshal(op.Change.Payload, &q); err != nil {
		return "", err
	}
	return q.Operation, nil
}

func followReconnect(ctx context.Context, s *session, op control.UserOperation) (cli.State, string, error) {
	operation, err := operationOf(op)
	if err != nil {
		return "", "", err
	}
	reply, err := s.Client.QueryTunnelReconnect(ctx, s.Target, s.Stored.Session, false, control.TunnelQuery{Operation: operation})
	if err != nil {
		return "", "", err
	}
	if reply.TunnelStatus == nil {
		return "", "", errors.New("server sent no reconnect status")
	}
	return jobState(reply.TunnelStatus.State), "reconnect " + reply.TunnelStatus.State, nil
}

// jobState maps the queued/running/done/failed states of maintenance jobs.
func jobState(s string) cli.State {
	switch s {
	case "done":
		return cli.Done
	case "failed":
		return cli.Failed
	}
	return cli.Accepted
}

func clusterCompactCommand(g *globals) *cli.Command {
	var f changeFlags
	var nodes string
	var minimal, parallel bool
	var retain uint64
	return &cli.Command{
		Name:  "compact",
		Short: "Shrink the replicated log on servers (system administrator)",
		Long: `Takes a snapshot and trims the replicated log on the voters (or --nodes),
one server at a time with the current leader last. --minimal keeps only
--retain entries; it never raises the configured retention.`,
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&nodes, "nodes", "", "only these `nodes`, comma separated (default: voters)")
			fs.BoolVar(&minimal, "minimal", false, "keep as few log entries as possible")
			fs.Uint64Var(&retain, "retain", 1000, "with --minimal, keep at most this many entries")
			fs.BoolVar(&parallel, "parallel", false, "compact followers at the same time (leader still last)")
			f.register(fs, true, true)
		},
		Run: func(c *cli.Context, args []string) error {
			if len(args) != 0 {
				return cli.Usagef("compact takes no arguments")
			}
			sel := control.CompactSelection{Mode: "keep", Parallel: parallel}
			if minimal {
				sel.Mode, sel.Retain = "minimal", retain
			} else if c.Set("retain") {
				return cli.Usagef("--retain needs --minimal")
			}
			if nodes != "" {
				sel.Nodes = strings.Split(nodes, ",")
			}
			if !sel.Valid() {
				return cli.Usagef("invalid --nodes or --retain")
			}
			id := f.id.Get()
			s, err := g.open(c)
			if err != nil {
				return err
			}
			defer s.Close()
			ctx, cancel := g.Deadline(c)
			defer cancel()
			plan, err := s.Client.CompactPlan(ctx, s.Target, s.Stored.Session, sel)
			if err != nil {
				return err
			}
			names := make([]string, len(plan.Nodes))
			for i, n := range plan.Nodes {
				names[i] = n.Node
			}
			fmt.Fprintf(c.Err, "compact %s (%s)\n", strings.Join(names, ", "), plan.Selection.Mode)
			if f.dryRun {
				return cli.Print(c.Out, g.output.Format(), plan, nil)
			}
			return g.apply(c, s, change{Kind: "cluster-compact", Async: true, Summary: "cluster compact " + strings.Join(names, ","), ID: id,
				Action: "raft-compact", Payload: control.CompactChange{Operation: id, Selection: plan.Selection, Target: plan.Target}}, f.noWait)
		},
	}
}

func followCompact(ctx context.Context, s *session, op control.UserOperation) (cli.State, string, error) {
	operation, err := operationOf(op)
	if err != nil {
		return "", "", err
	}
	reply, err := s.Client.CompactStatus(ctx, s.Target, s.Stored.Session, control.CompactQuery{Operation: operation})
	if err != nil {
		return "", "", err
	}
	if reply.CompactStatus == nil {
		return "", "", errors.New("server sent no compaction status")
	}
	sum := reply.CompactStatus.Summary
	detail := fmt.Sprintf("%d of %d done, %d running, %d failed, %d skipped", sum.Done, sum.Total, sum.Running, sum.Failed, sum.Skipped)
	switch {
	case !sum.Complete:
		return cli.Accepted, detail, nil
	case sum.Failed > 0:
		return cli.Failed, detail, nil
	}
	return cli.Done, detail, nil
}

func clusterCLIPolicyCommand(g *globals) *cli.Command {
	var f changeFlags
	return &cli.Command{
		Name:  "cli-policy",
		Args:  "[block|allow]",
		Short: "Show or set whether servers' own keys may run management commands (system administrator)",
		Long: `With 'block', management commands signed only by a server's key (mydc run
as root on the server) are refused, and every change needs a registered
user. 'allow' lifts that. Without an argument, shows the policy.`,
		Flags: func(fs *flag.FlagSet) { f.register(fs, false, false) },
		Run: func(c *cli.Context, args []string) error {
			if len(args) > 1 || len(args) == 1 && args[0] != "block" && args[0] != "allow" {
				return cli.Usagef("cli-policy takes block, allow or nothing")
			}
			s, err := g.open(c)
			if err != nil {
				return err
			}
			defer s.Close()
			ctx, cancel := g.Deadline(c)
			defer cancel()
			reply, err := s.Client.Query(ctx, s.Target, s.Stored.Session, "node-cli-policy", "")
			if err != nil {
				return err
			}
			if reply.NodeCLI == nil {
				return errors.New("server sent no node CLI policy")
			}
			if len(args) == 0 {
				return cli.Print(c.Out, g.output.Format(), reply.NodeCLI, func() cli.Rows {
					t := cli.Rows{Header: []string{"node cli", "revision"}}
					t.Add(map[bool]string{true: "blocked", false: "allowed"}[reply.NodeCLI.DisableNodeCLIOperation], reply.NodeCLI.Revision)
					return t
				})
			}
			block := args[0] == "block"
			if reply.NodeCLI.DisableNodeCLIOperation == block {
				fmt.Fprintf(c.Out, "node CLI is already %s\n", map[bool]string{true: "blocked", false: "allowed"}[block])
				return nil
			}
			return g.apply(c, s, change{Summary: "cluster cli-policy " + args[0], ID: f.id.Get(), Action: "set-node-cli-policy",
				Expected: f.expect(reply.NodeCLI.Revision), Payload: control.NodeCLIChange{DisableNodeCLIOperation: block}}, false)
		},
	}
}
