// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jay94ks/seafield/internal/cli"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
)

// clusterCommand is `sfcli cluster`: the running cluster as a whole. Local
// connection profiles are `sfcli context`.
func clusterCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "cluster",
		Short: "Check and maintain the running cluster",
		Sub: []*cli.Command{
			clusterStatusCommand(g),
			clusterMeshCommand(g),
			clusterReconnectCommand(g),
			clusterCompactCommand(g),
			clusterBackupCommand(g),
			clusterCLIPolicyCommand(g),
			clusterUpgradeCommand(g),
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
			status, err := readRaftStatus(ctx, s, s.Target)
			if err != nil {
				return err
			}
			// A follower sees only itself and the leader, so with more than
			// three voters its count stays below quorum and reads as Stale.
			// Only the leader sees every voter's ACKs (and counts writes):
			// ask it directly when the context knows its endpoint.
			followerView := status.Leader != "" && status.Leader != status.ObservedBy
			unreachable := ""
			if followerView {
				for _, peer := range s.Client.Peers {
					if peer.ID != status.Leader {
						continue
					}
					leader, err := readRaftStatus(ctx, s, peer)
					if err != nil {
						// Only --writes needs the leader. A plain status is
						// most needed exactly when the leader cannot be
						// reached (an old endpoint, a failing leader), so
						// keep the follower's view and say why.
						if writes {
							return fmt.Errorf("ask leader %s: %w", status.Leader, err)
						}
						unreachable = fmt.Sprintf("could not reach leader %s: %v; showing follower view", status.Leader, err)
						break
					}
					status, followerView = leader, leader.Leader != leader.ObservedBy
					break
				}
			}
			if writes {
				if status.Writes == nil && status.Leader != status.ObservedBy {
					return fmt.Errorf("%s is not the leader and the context has no endpoint for leader %s; add it with 'sfcli context trust'", status.ObservedBy, status.Leader)
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
				fmt.Fprintf(c.Out, "Leader: %s  Term: %d  Voters: %d (quorum %d, responding %d)  Committed: %d  Stale: %v\n",
					status.Leader, status.Term, status.Voters, status.Quorum, status.RespondingVoters, status.CommitIndex, status.Stale)
				if unreachable != "" {
					fmt.Fprintln(c.Out, unreachable)
				} else if followerView {
					fmt.Fprintf(c.Out, "Observed by follower %s: it sees only itself and the leader; add the leader's endpoint with 'sfcli context trust' for every voter's contact\n", status.ObservedBy)
				}
				if mixed := mixedVersions(status.Nodes); mixed != "" {
					fmt.Fprintf(c.Out, "Versions are mixed: %s\n", mixed)
				}
				fmt.Fprintln(c.Out)
			}
			return cli.Print(c.Out, g.output.Format(), status, func() cli.Rows {
				t := cli.Rows{Header: []string{"node", "role", "version", "term", "applied", "lag", "stale"}}
				for _, n := range status.Nodes {
					v := n.Version
					if v == "" {
						v = "-"
					}
					role := n.Role
					if n.Waiting {
						role = "waiting"
					}
					t.Add(n.Node, role, v, n.Term, countText(n.AppliedIndex), countText(n.Lag), n.Stale)
				}
				return t
			})
		},
	}
}

// readRaftStatus reads every page of raft-status from target (the
// connected server, or the leader when a follower answered).
func readRaftStatus(ctx context.Context, s *session, target sfcp.Peer) (*userauth.RaftStatus, error) {
	var status *userauth.RaftStatus
	after := ""
	for pages := 0; ; pages++ {
		if pages == 256 {
			return nil, errors.New("too many status pages")
		}
		reply, err := s.Client.RaftStatusPage(ctx, target, s.Stored.Session, after)
		if err != nil {
			return nil, err
		}
		if reply.RaftStatus == nil {
			return nil, errors.New("server sent no cluster status")
		}
		if status == nil {
			status = reply.RaftStatus
		} else {
			if reply.RaftStatus.NodesRootRevision != status.NodesRootRevision {
				return nil, errors.New("the node list changed while it was read; try again")
			}
			status.Nodes = append(status.Nodes, reply.RaftStatus.Nodes...)
		}
		if after = reply.RaftStatus.NodesNext; after == "" {
			status.NodesNext = ""
			return status, nil
		}
	}
}

// upgradeStatus is `cluster upgrade status` output.
type upgradeStatus struct {
	Server          string
	Version         string
	ClusterFeatures []string
	Nodes           []upgradeNode
}

type upgradeNode struct {
	Node, Version string
	Features      []string
	// Lacks are features some other server announces that this one does
	// not: upgrading it lets the cluster use them.
	Lacks []string
}

func clusterUpgradeCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "upgrade",
		Short: "Follow a rolling upgrade",
		Sub: []*cli.Command{{
			Name:  "status",
			Short: "Show each server's version and features, and what the cluster can use (system administrator)",
			Long: `Shows the build version and feature names each server last reported, the
features every server has (the only ones the cluster uses), and what each
server lacks that another one has. Upgrade the servers that lack something
to let the cluster use it (devel/design/upgrades.md 3-1).`,
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
				version, err := s.Client.ServerVersion(ctx, s.Target)
				if err != nil {
					return err
				}
				status, err := readRaftStatus(ctx, s, s.Target)
				if err != nil {
					return err
				}
				v := newUpgradeStatus(status, version)
				if g.output.Format() == cli.Table {
					fmt.Fprintf(c.Out, "Connected to %s (sfcd %s)\n", v.Server, v.Version)
					if mixed := mixedVersions(status.Nodes); mixed != "" {
						fmt.Fprintf(c.Out, "Versions are mixed: %s\n", mixed)
					}
					if len(v.ClusterFeatures) == 0 {
						fmt.Fprintln(c.Out, "The cluster uses no features beyond the major's baseline.")
					} else {
						fmt.Fprintf(c.Out, "The cluster can use: %s\n", strings.Join(v.ClusterFeatures, ", "))
					}
					fmt.Fprintln(c.Out)
				}
				return cli.Print(c.Out, g.output.Format(), v, func() cli.Rows {
					t := cli.Rows{Header: []string{"node", "version", "features", "lacks"}}
					for _, n := range v.Nodes {
						t.Add(n.Node, dash(n.Version), dash(strings.Join(n.Features, ",")), dash(strings.Join(n.Lacks, ",")))
					}
					return t
				})
			},
		}},
	}
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func newUpgradeStatus(status *userauth.RaftStatus, version userauth.ServerVersion) upgradeStatus {
	v := upgradeStatus{Server: status.ObservedBy, Version: version.Version, ClusterFeatures: version.ClusterFeatures, Nodes: []upgradeNode{}}
	if v.ClusterFeatures == nil {
		v.ClusterFeatures = []string{}
	}
	var all []string
	for _, n := range status.Nodes {
		for _, f := range n.Features {
			if !slices.Contains(all, f) {
				all = append(all, f)
			}
		}
	}
	slices.Sort(all)
	for _, n := range status.Nodes {
		row := upgradeNode{Node: n.Node, Version: n.Version, Features: n.Features, Lacks: []string{}}
		if row.Features == nil {
			row.Features = []string{}
		}
		for _, f := range all {
			// A server with no report yet (no version) is unknown, not lacking.
			if n.Version != "" && !slices.Contains(n.Features, f) {
				row.Lacks = append(row.Lacks, f)
			}
		}
		v.Nodes = append(v.Nodes, row)
	}
	return v
}

// mixedVersions is "0.1.0 ×2, 0.1.1 ×2" when the servers that reported a
// version run more than one, else "" (devel/design/upgrades.md 3-5).
func mixedVersions(nodes []userauth.RaftNodeStatus) string {
	count := map[string]int{}
	var order []string
	for _, n := range nodes {
		if n.Version == "" {
			continue
		}
		if count[n.Version] == 0 {
			order = append(order, n.Version)
		}
		count[n.Version]++
	}
	if len(order) < 2 {
		return ""
	}
	slices.Sort(order)
	parts := make([]string, len(order))
	for i, v := range order {
		parts[i] = fmt.Sprintf("%s ×%d", v, count[v])
	}
	return strings.Join(parts, ", ")
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
				page, err := s.Client.MeshLinks(ctx, s.Target, s.Stored.Session, userauth.NodeObservationQuery{Tenant: tenant, Node: node, After: after})
				if err != nil {
					return err
				}
				links = append(links, page.Links...)
				if after = page.Next; after == "" {
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
		Long:  "Rebuilds the link from NODE to PEER when 'sfcli cluster mesh' shows it down. Working links are never touched.",
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
			plan, err := s.Client.TunnelReconnectPlan(ctx, s.Target, s.Stored.Session, node, peer)
			if err != nil {
				return err
			}
			fmt.Fprintf(c.Err, "%s -> %s (%s) is down\n", node, peer, plan.Endpoint)
			if f.dryRun {
				return cli.Print(c.Out, g.output.Format(), plan, nil)
			}
			return g.apply(c, s, change{Kind: "cluster-reconnect", Async: true, Summary: "cluster reconnect " + node + " " + peer, ID: id,
				Action: "reconnect-tunnel", Payload: control.TunnelChange{Operation: id, Plan: plan}}, f.noWait)
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
	status, err := s.Client.TunnelReconnectStatus(ctx, s.Target, s.Stored.Session, operation)
	if err != nil {
		return "", "", err
	}
	return jobState(status.State), "reconnect " + status.State, nil
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
	page, err := s.Client.CompactStatus(ctx, s.Target, s.Stored.Session, userauth.CompactStatusQuery{Operation: operation})
	if err != nil {
		return "", "", err
	}
	sum := page.Summary
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
		Long: `With 'block', management commands signed only by a server's key (sfcli run
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
			policy, err := s.Client.NodeCLIPolicy(ctx, s.Target, s.Stored.Session)
			if err != nil {
				return err
			}
			if len(args) == 0 {
				return cli.Print(c.Out, g.output.Format(), policy, func() cli.Rows {
					t := cli.Rows{Header: []string{"node cli", "revision"}}
					t.Add(map[bool]string{true: "blocked", false: "allowed"}[policy.DisableNodeCLIOperation], policy.Revision)
					return t
				})
			}
			block := args[0] == "block"
			if policy.DisableNodeCLIOperation == block {
				fmt.Fprintf(c.Out, "node CLI is already %s\n", map[bool]string{true: "blocked", false: "allowed"}[block])
				return nil
			}
			return g.apply(c, s, change{Summary: "cluster cli-policy " + args[0], ID: f.id.Get(), Action: "set-node-cli-policy",
				Expected: f.expect(policy.Revision), Payload: control.NodeCLIChange{DisableNodeCLIOperation: block}}, false)
		},
	}
}
