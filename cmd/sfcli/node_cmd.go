// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jay94ks/seafield/internal/cli"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/userauth"
)

// nodeCommand is `sfcli node`: the servers of the cluster.
func nodeCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "node",
		Short: "List and run the servers of the cluster",
		Sub: []*cli.Command{
			nodeListCommand(g),
			nodeShowCommand(g),
			nodeAddCommand(g),
			nodeInviteCommand(g),
			nodeVoteCommand(g, "promote"),
			nodeVoteCommand(g, "demote"),
			nodeCordonCommand(g, "cordon"),
			nodeCordonCommand(g, "uncordon"),
			nodeDrainCommand(g),
			nodeLifecycleCommand(g, "isolate"),
			nodeLifecycleCommand(g, "restore"),
			nodeRemoveCommand(g),
			nodeRenewCommand(g),
			nodeRotateKeyCommand(g),
			nodeSetEndpointCommand(g),
			nodeDiagnosticsCommand(g),
			nodeLogsCommand(g),
			nodeDisksCommand(g),
			nodeFirewallCommandTree(g),
			nodeTenantsCommand(g),
			nodeShellCommandTree(g),
			nodeImagesCommand(g),
			nodeStorageCommandTree(g),
			nodeQuotaCommandTree(g),
		},
	}
}

func nodeArg(args []string, what string) (string, error) {
	if len(args) != 1 {
		return "", cli.Usagef("%s needs one node name", what)
	}
	if !lifecycle.ValidID(args[0]) {
		return "", cli.Usagef("%q is not a valid node name", args[0])
	}
	return args[0], nil
}

// nodeDirectory is one consistent read of the member directory: every page
// came from the same committed revisions.
type nodeDirectory struct {
	Revision           uint64                `json:"revision"`
	RuntimeRevision    uint64                `json:"runtime_revision"`
	OperationEpoch     uint64                `json:"operation_epoch"`
	ConfigurationIndex uint64                `json:"configuration_index"`
	Voters             int                   `json:"voters"`
	Quorum             int                   `json:"quorum"`
	Members            []membership.Entry    `json:"members"`
	Nodes              []membership.NodeView `json:"nodes"`
}

func (d nodeDirectory) entry(node string) (membership.Entry, bool) {
	for _, e := range d.Members {
		if e.Peer.ID == node {
			return e, true
		}
	}
	return membership.Entry{}, false
}

func (d nodeDirectory) view(node string) (membership.NodeView, bool) {
	for _, v := range d.Nodes {
		if v.Node.Member.ID == node {
			return v, true
		}
	}
	return membership.NodeView{}, false
}

// readNodes reads every member page. A directory that changes between pages
// is an error, never a mixed view.
func readNodes(ctx context.Context, s *session) (nodeDirectory, error) {
	var d nodeDirectory
	after := ""
	var first *userauth.MembersReply
	for {
		reply, err := s.Client.MemberPage(ctx, s.Target, s.Stored.Session, after)
		if err != nil {
			return d, err
		}
		if first == nil {
			snapshot := reply
			first = &snapshot
		} else if first.RootRevision != reply.RootRevision || first.RuntimeRevision != reply.RuntimeRevision || first.OperationEpoch != reply.OperationEpoch {
			return d, errors.New("the node list changed while it was read; try again")
		}
		if len(reply.Members) > 8 || len(reply.Nodes) > len(reply.Members) || len(d.Members)+len(reply.Members) > 1024 {
			return d, errors.New("server sent an invalid node page")
		}
		last := after
		for _, entry := range reply.Members {
			if !lifecycle.ValidID(entry.Peer.ID) || entry.Peer.ID <= last {
				return d, errors.New("server sent node pages out of order")
			}
			last = entry.Peer.ID
		}
		d.Members = append(d.Members, reply.Members...)
		d.Nodes = append(d.Nodes, reply.Nodes...)
		if reply.Next == "" {
			break
		}
		if reply.Next != last {
			return d, errors.New("server sent an invalid node page cursor")
		}
		after = reply.Next
	}
	d.Revision, d.RuntimeRevision, d.OperationEpoch = first.RootRevision, first.RuntimeRevision, first.OperationEpoch
	d.ConfigurationIndex, d.Voters, d.Quorum = first.ConfigurationIndex, first.Voters, first.Quorum
	return d, nil
}

func scheduling(c membership.CordonView) string {
	if c.Enabled && c.Reason != "" {
		return "cordoned: " + c.Reason
	}
	if c.Enabled {
		return "cordoned"
	}
	return "open"
}

func voterText(voter bool) string {
	if voter {
		return "yes"
	}
	return "no"
}

func nodeListCommand(g *globals) *cli.Command {
	var all bool
	return &cli.Command{
		Name:  "list",
		Short: "List servers",
		Long: `Lists the servers the current tenant may use. With --all, or when no
tenant is set, a system administrator sees every server with its membership
and lifecycle state.`,
		Flags: func(fs *flag.FlagSet) {
			fs.BoolVar(&all, "all", false, "every server in the cluster (system administrator); the default when no tenant is set")
		},
		Run: func(c *cli.Context, args []string) error {
			if len(args) != 0 {
				return cli.Usagef("list takes no arguments")
			}
			s, err := g.open(c)
			if err != nil {
				return err
			}
			defer s.Close()
			ctx, cancel := g.Deadline(c)
			defer cancel()
			tenant := ""
			if !all {
				if tenant, err = g.Tenant(s, false); err != nil {
					return err
				}
				// With no tenant to look from, list the whole cluster. The
				// server allows that only for a system administrator.
				all = tenant == ""
			}
			if !all {
				nodes, err := nodeSummaries(ctx, s, tenant, "")
				if err != nil {
					return err
				}
				return cli.Print(c.Out, g.output.Format(), nodes, func() cli.Rows {
					t := cli.Rows{Header: []string{"node", "state", "ready", "scheduling", "stale", "build"}}
					for _, n := range nodes {
						state := n.State
						if n.Waiting {
							// The server did not answer in time; the
							// row is what was stored before.
							state = "waiting"
						} else if n.State == "unready" && n.Reason != "" {
							// Fixed codes only; the error text is in that
							// server's log.
							state = "unready (" + n.Reason
							if len(n.FailedSteps) > 0 {
								state += ": " + strings.Join(n.FailedSteps, ",")
							}
							state += ")"
						}
						t.Add(n.Node, state, n.Ready, scheduling(n.Scheduling), n.Stale, buildText(n.Build))
					}
					return t
				})
			}
			d, err := readNodes(ctx, s)
			if err != nil {
				return err
			}
			return cli.Print(c.Out, g.output.Format(), d, func() cli.Rows {
				t := cli.Rows{Header: []string{"node", "member", "voter", "lifecycle", "scheduling", "pending", "endpoint"}}
				for _, e := range d.Members {
					v, _ := d.view(e.Peer.ID)
					pending := ""
					if v.Node.Pending != nil {
						pending = string(v.Node.Pending.Action) + " " + v.Node.Pending.ID
					}
					t.Add(e.Peer.ID, e.Phase, voterText(e.Peer.Voter), v.Node.Phase, scheduling(v.Scheduling), pending, e.Peer.Endpoint)
				}
				return t
			})
		},
	}
}

// nodeSummaries reads every node-summary page for the tenant ("" = system).
func nodeSummaries(ctx context.Context, s *session, tenant, node string) ([]control.NodeSummaryView, error) {
	out := []control.NodeSummaryView{}
	after := ""
	for pages := 0; pages < 256; pages++ {
		page, err := s.Client.NodeSummary(ctx, s.Target, s.Stored.Session, userauth.NodeObservationQuery{Tenant: tenant, Node: node, After: after})
		if err != nil {
			return nil, err
		}
		out = append(out, page.Nodes...)
		if page.Next == "" {
			return out, nil
		}
		after = page.Next
	}
	return nil, errors.New("too many node pages")
}

// nodeDetail is `node show`: the directory row, the lifecycle view and the
// last observation of one server.
type nodeDetail struct {
	Member    membership.Entry         `json:"member"`
	Lifecycle *membership.NodeView     `json:"lifecycle,omitempty"`
	Summary   *control.NodeSummaryView `json:"summary,omitempty"`
}

func nodeShowCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "show",
		Args:  "NODE",
		Short: "Show one server (system administrator)",
		Run: func(c *cli.Context, args []string) error {
			node, err := nodeArg(args, "show")
			if err != nil {
				return err
			}
			s, err := g.open(c)
			if err != nil {
				return err
			}
			defer s.Close()
			ctx, cancel := g.Deadline(c)
			defer cancel()
			d, err := readNodes(ctx, s)
			if err != nil {
				return err
			}
			e, ok := d.entry(node)
			if !ok {
				return fmt.Errorf("no node %s", node)
			}
			out := nodeDetail{Member: e}
			if v, ok := d.view(node); ok {
				out.Lifecycle = &v
			}
			if nodes, err := nodeSummaries(ctx, s, "", node); err == nil && len(nodes) == 1 {
				out.Summary = &nodes[0]
			}
			return cli.Print(c.Out, g.output.Format(), out, nil)
		},
	}
}

func nodeDiagnosticsCommand(g *globals) *cli.Command {
	var file string
	var cpuProfile time.Duration
	return &cli.Command{
		Name:  "diagnostics",
		Args:  "NODE",
		Short: "Save a diagnostics bundle (tar.gz, no secrets) of a server",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&file, "out", "", "write the bundle to this new `file` (default NODE-diagnostics.tar.gz)")
			fs.DurationVar(&cpuProfile, "cpu-profile", 0, "also record a CPU profile of the server's sfcd for this `duration` (up to 20s; adds it to the request deadline)")
		},
		Run: func(c *cli.Context, args []string) error {
			node, err := nodeArg(args, "diagnostics")
			if err != nil {
				return err
			}
			if cpuProfile < 0 || cpuProfile > control.NodeDiagnosticsMaxCPUProfileSeconds*time.Second {
				return cli.Usagef("--cpu-profile must be between 0 and 20s")
			}
			if file == "" {
				file = node + "-diagnostics.tar.gz"
			}
			s, err := g.open(c)
			if err != nil {
				return err
			}
			defer s.Close()
			ctx, cancel := context.WithTimeout(c.Ctx, g.timeout+cpuProfile)
			defer cancel()
			bundle, err := s.Client.NodeDiagnostics(ctx, s.Target, s.Stored.Session, node, cpuProfile)
			if err != nil {
				return err
			}
			f, err := os.OpenFile(file, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
			if err != nil {
				return err
			}
			_, err = f.Write(bundle.Data)
			if err == nil {
				err = f.Sync()
			}
			if err = errors.Join(err, f.Close()); err != nil {
				return err
			}
			bundle.Data = nil
			fmt.Fprintf(c.Err, "saved %s\n", file)
			return cli.Print(c.Out, g.output.Format(), bundle, nil)
		},
	}
}

func nodeDisksCommand(g *globals) *cli.Command {
	var all bool
	return &cli.Command{
		Name:  "disks",
		Args:  "[NODE]",
		Short: "Show the disks of servers",
		Long:  "Shows the disks of the servers the tenant may use, with --all every disk (system administrator).",
		Flags: func(fs *flag.FlagSet) {
			fs.BoolVar(&all, "all", false, "every server, not only the tenant's (system administrator)")
		},
		Run: func(c *cli.Context, args []string) error {
			node := ""
			if len(args) > 0 {
				var err error
				if node, err = nodeArg(args, "disks"); err != nil {
					return err
				}
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
			disks := []control.NodeDiskView{}
			after := ""
			for pages := 0; ; pages++ {
				if pages == 256 {
					return errors.New("too many disk pages")
				}
				page, err := s.Client.NodeDisks(ctx, s.Target, s.Stored.Session, userauth.NodeObservationQuery{Tenant: tenant, Node: node, After: after})
				if err != nil {
					return err
				}
				disks = append(disks, page.Disks...)
				if after = page.Next; after == "" {
					break
				}
			}
			return cli.Print(c.Out, g.output.Format(), disks, func() cli.Rows {
				t := cli.Rows{Header: []string{"node", "disk", "mount", "state", "size", "free", "purposes"}}
				for _, d := range disks {
					t.Add(d.Node, d.ID, d.Mount, d.State, sizeText(d.Total), sizeText(d.Available), strings.Join(d.Purposes, ","))
				}
				return t
			})
		},
	}
}

func sizeText(v *uint64) string {
	if v == nil {
		return ""
	}
	return cli.Size(*v).String()
}

func nodeTenantsCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "tenants",
		Args:  "NODE",
		Short: "Show how much of a server each tenant uses (system administrator)",
		Run: func(c *cli.Context, args []string) error {
			node, err := nodeArg(args, "tenants")
			if err != nil {
				return err
			}
			s, err := g.open(c)
			if err != nil {
				return err
			}
			defer s.Close()
			ctx, cancel := g.Deadline(c)
			defer cancel()
			usage := []control.NodeUsageView{}
			after := ""
			for pages := 0; ; pages++ {
				if pages == 256 {
					return errors.New("too many usage pages")
				}
				page, err := s.Client.NodeTenantUsage(ctx, s.Target, s.Stored.Session, userauth.NodeTenantUsageQuery{Node: node, After: after})
				if err != nil {
					return err
				}
				usage = append(usage, page.Usage...)
				if after = page.Next; after == "" {
					break
				}
			}
			return cli.Print(c.Out, g.output.Format(), usage, func() cli.Rows {
				t := cli.Rows{Header: []string{"tenant", "cpu used", "memory used", "containers", "cpu quota", "memory quota", "stale"}}
				for _, u := range usage {
					t.Add(u.Tenant, countText(u.CPUUsed), sizeText(u.MemoryUsed), countText(u.Containers), u.QuotaCPU, cli.Size(u.QuotaMemory), u.Stale)
				}
				return t
			})
		},
	}
}

func countText(v *uint64) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(*v)
}

// buildText is the build column: "yes", or why the server does not build.
func buildText(b control.NodeBuildView) string {
	if b.Enabled {
		return "yes"
	}
	return "no (" + b.Reason + ")"
}
