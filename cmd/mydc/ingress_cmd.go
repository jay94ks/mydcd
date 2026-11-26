// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/jay94ks/mydcd/internal/cli"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/ingress"
)

// mydc ingress: external HTTP(S) entry points of apps — observation,
// temporary blocks, gateway listeners, load balancing and drains. Usage:
// docs/cli/ingress.md.

func ingressCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "ingress",
		Short: "Look at and control external access to apps",
		Long: `Ingress routes are declared in app.yaml. These commands show what each
server actually serves, block traffic for a while, and change the gateway
listeners, load balancing and drains on top of the app's routes.`,
		Sub: []*cli.Command{
			ingressListCommand(g),
			ingressDetailCommand(g, "show", "mappings", "Show one ingress: routes, backends, listeners and certificates"),
			ingressDetailCommand(g, "metrics", "metrics", "Show the last 60 seconds of request metrics of one ingress"),
			ingressDetailCommand(g, "errors", "errors", "Show recent failed requests of one ingress"),
			ingressHistoryCommand(g),
			ingressBlocksCommand(g),
			ingressBlockCommand(g),
			ingressUnblockCommand(g),
			ingressExtendCommand(g),
			ingressHostsCommand(g),
			ingressGatewaysCommand(g),
			ingressBalanceCommand(g),
			ingressDrainCommand(g, "drain"),
			ingressDrainCommand(g, "undrain"),
		},
	}
}

// ingressScope is the --all / --node / --app filter of the read commands.
type ingressScope struct {
	all       bool
	node, app string
}

func (f *ingressScope) register(fs *flag.FlagSet, withApp bool) {
	fs.BoolVar(&f.all, "all", false, "every tenant you can read (system administrators: the whole cluster)")
	fs.StringVar(&f.node, "node", "", "only this `node`")
	if withApp {
		fs.StringVar(&f.app, "app", "", "only this `app`")
	}
}

func (f *ingressScope) query(g *globals, s *session, part string) (control.IngressQuery, error) {
	q := control.IngressQuery{Part: part, Node: f.node, App: f.app}
	if f.all {
		if g.tenant != "" {
			return q, cli.Usagef("--all and --tenant cannot be used together")
		}
		return q, nil
	}
	tenant, err := g.Tenant(s, false)
	q.Tenant = tenant
	return q, err
}

// ingressPages reads every page of one ingress query. Lists continue with
// After; one ingress's details and the block list continue with a numeric
// Offset.
func ingressPages(c *cli.Context, g *globals, s *session, q control.IngressQuery, each func(control.IngressPage) uint32) error {
	for range 1024 {
		ctx, cancel := g.Deadline(c)
		page, err := s.Client.Ingresses(ctx, s.Target, s.Stored.Session, q)
		cancel()
		if err != nil {
			return err
		}
		next := each(page)
		switch {
		case next != 0 && next > q.Offset:
			q.Offset = next
		case page.Next != "" && page.Next != q.After && q.Part != "blocks" && q.Part != "policies":
			q.After, q.Offset = page.Next, 0
		case page.Next != "" && (q.Part == "blocks" || q.Part == "policies"):
			n, err := strconv.ParseUint(page.Next, 10, 32)
			if err != nil || uint32(n) <= q.Offset {
				return errors.New("the server returned a bad page cursor")
			}
			q.Offset = uint32(n)
		default:
			return nil
		}
	}
	return errors.New("too many pages; narrow the query with --node or --app")
}

func ingressListCommand(g *globals) *cli.Command {
	var scope ingressScope
	return &cli.Command{
		Name:  "list",
		Short: "List ingresses and their state on each server",
		Flags: func(fs *flag.FlagSet) { scope.register(fs, true) },
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 0 {
				return cli.Usagef("list takes no arguments")
			}
			q, err := scope.query(g, s, "mappings")
			if err != nil {
				return err
			}
			rows := []control.IngressMapping{}
			err = ingressPages(c, g, s, q, func(p control.IngressPage) uint32 {
				rows = append(rows, p.Mappings...)
				return 0
			})
			if err != nil {
				return err
			}
			return cli.Print(c.Out, g.output.Format(), rows, func() cli.Rows {
				t := cli.Rows{Header: []string{"key", "tenant", "app", "node", "state", "routes", "backends"}}
				for _, m := range rows {
					t.Add(m.Key, m.Tenant, m.App, m.Node, ingressState(m), m.RoutesTotal, m.BackendsTotal)
				}
				return t
			})
		}),
	}
}

func ingressState(m control.IngressMapping) string {
	switch {
	case m.Error != "":
		return m.Error
	case m.Draining:
		return "draining"
	case m.Ready:
		return "ready"
	}
	return "not ready"
}

func ingressDetailCommand(g *globals, verb, part, short string) *cli.Command {
	return &cli.Command{
		Name:  verb,
		Args:  "KEY",
		Short: short,
		Long:  short + ". KEY is a key from 'mydc ingress list'.",
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 1 || args[0] == "" {
				return cli.Usagef("%s needs one ingress key from 'mydc ingress list'", verb)
			}
			tenant, err := g.Tenant(s, false)
			if err != nil {
				return err
			}
			// Details of one ingress come in parts of a few listeners,
			// routes and backends each; every part is printed.
			parts := []control.IngressMapping{}
			err = ingressPages(c, g, s, control.IngressQuery{Tenant: tenant, Key: args[0], Part: part}, func(p control.IngressPage) uint32 {
				parts = append(parts, p.Mappings...)
				if len(p.Mappings) == 1 {
					return p.Mappings[0].Next
				}
				return 0
			})
			if err != nil {
				return err
			}
			if len(parts) == 0 {
				return fmt.Errorf("ingress %q not found", args[0])
			}
			if g.output.Format() != cli.Table {
				return cli.Print(c.Out, g.output.Format(), parts, nil)
			}
			m := parts[0]
			fmt.Fprintf(c.Out, "Key:     %s\nApp:     %s/%s\nNode:    %s\nState:   %s\nRoutes:  %d\nBackends: %d\nBlocks:  %d\n", m.Key, m.Tenant, m.App, m.Node, ingressState(m), m.RoutesTotal, m.BackendsTotal, m.BlocksTotal)
			fmt.Fprintln(c.Out, "\nDetails (use -o yaml for everything):")
			return cli.Print(c.Out, cli.YAML, parts, nil)
		}),
	}
}

func ingressHistoryCommand(g *globals) *cli.Command {
	var scope ingressScope
	return &cli.Command{
		Name:  "history",
		Short: "Show recent gateway, balance and drain changes",
		Flags: func(fs *flag.FlagSet) { scope.register(fs, true) },
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 0 {
				return cli.Usagef("history takes no arguments")
			}
			q, err := scope.query(g, s, "history")
			if err != nil {
				return err
			}
			rows := []control.IngressHistoryView{}
			if err = ingressPages(c, g, s, q, func(p control.IngressPage) uint32 { rows = append(rows, p.History...); return 0 }); err != nil {
				return err
			}
			return cli.Print(c.Out, g.output.Format(), rows, func() cli.Rows {
				t := cli.Rows{Header: []string{"time", "action", "by", "tenant", "app", "node", "route"}}
				for _, h := range rows {
					t.Add(time.Unix(h.At, 0).Local().Format("2006-01-02 15:04:05"), h.Action, h.Actor, h.Tenant, h.App, h.Node, h.Route)
				}
				return t
			})
		}),
	}
}

func ingressBlockRows(c *cli.Context, g *globals, s *session, q control.IngressQuery) ([]control.IngressBlockView, uint64, error) {
	rows := []control.IngressBlockView{}
	var epoch uint64
	err := ingressPages(c, g, s, q, func(p control.IngressPage) uint32 {
		rows = append(rows, p.Blocks...)
		epoch = p.Epoch
		return 0
	})
	return rows, epoch, err
}

func ingressBlocksCommand(g *globals) *cli.Command {
	var scope ingressScope
	return &cli.Command{
		Name:  "blocks",
		Short: "List blocks and where they are applied",
		Flags: func(fs *flag.FlagSet) { scope.register(fs, true) },
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 0 {
				return cli.Usagef("blocks takes no arguments")
			}
			q, err := scope.query(g, s, "blocks")
			if err != nil {
				return err
			}
			rows, _, err := ingressBlockRows(c, g, s, q)
			if err != nil {
				return err
			}
			return cli.Print(c.Out, g.output.Format(), rows, func() cli.Rows {
				t := cli.Rows{Header: []string{"id", "scope", "target", "response", "expires", "state"}}
				for _, b := range rows {
					expires := "never"
					if b.Block.ExpiresAt != 0 {
						expires = time.Unix(int64(b.Block.ExpiresAt), 0).Local().Format("2006-01-02 15:04")
					}
					state := "inactive"
					switch {
					case b.Removed:
						state = "removed"
					case b.TargetMissing:
						state = "target missing"
					case b.Active:
						state = "active"
					}
					t.Add(b.Block.ID, b.Block.Scope, blockTarget(b.Block), b.Block.Response, expires, state)
				}
				return t
			})
		}),
	}
}

func blockTarget(b ingress.Block) string {
	parts := []string{}
	for _, v := range []string{b.Tenant, b.App, b.Node, b.Gateway, b.Route, b.Host + b.Prefix, b.Service, b.Backend, b.Source} {
		if v != "" {
			parts = append(parts, v)
		}
	}
	return strings.Join(parts, " ")
}

func ingressBlockCommand(g *globals) *cli.Command {
	var b ingress.Block
	var apps string
	var lifetime time.Duration
	var id cli.IDFlag
	return &cli.Command{
		Name:  "block",
		Args:  "ID",
		Short: "Block traffic to an ingress target for a while",
		Long: `Creates block ID. --scope chooses what is blocked:
  route     --app --key --route --host --prefix   one route of an ingress
  host      --host                                 every route of a host
  backend   --app --key --service --backend       take one backend out
  instance  --app --key                           a whole ingress
  source    --source CIDR [--apps a,b]            clients from a network
  tenant                                          every ingress of the tenant
  node      --node                                (system administrators)
  gateway   --gateway external|local              (system administrators)
The reason (--reason) is shown with the block. A block ID is never reused.`,
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&b.Scope, "scope", "", "what to block: route, host, backend, instance, source, tenant, node or gateway")
			fs.StringVar(&b.App, "app", "", "`app` of the ingress")
			fs.StringVar(&b.Key, "key", "", "ingress `key` from 'mydc ingress list'")
			fs.StringVar(&b.Node, "node", "", "`node`")
			fs.StringVar(&b.Gateway, "gateway", "", "only on the external, local or both gateways")
			fs.StringVar(&b.Route, "route", "", "route `ID`")
			fs.StringVar(&b.Host, "host", "", "`host` name")
			fs.StringVar(&b.Prefix, "prefix", "", "path `prefix` of the route")
			fs.StringVar(&b.Service, "service", "", "`service` of the backend")
			fs.StringVar(&b.Backend, "backend", "", "`backend` ID")
			fs.StringVar(&b.Source, "source", "", "client network `CIDR`")
			fs.StringVar(&apps, "apps", "", "comma-separated `apps` a source block applies to")
			fs.StringVar(&b.Response, "response", "503", "answer blocked requests with 503, 403 or reset")
			fs.BoolVar(&b.CutExisting, "cut-existing", false, "also cut requests that are already running")
			fs.DurationVar(&lifetime, "for", 0, "remove the block after this long, such as 2h (default: until unblocked)")
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 1 || !lifecycle.ValidID(args[0]) {
				return cli.Usagef("block needs one block ID (letters, digits and -)")
			}
			block := b
			block.ID, block.Reason = args[0], g.reason
			if apps != "" {
				block.Apps = strings.Split(apps, ",")
			}
			if lifetime < 0 {
				return cli.Usagef("--for must be positive")
			}
			if lifetime > 0 {
				block.ExpiresAt = uint64(time.Now().Add(lifetime).Unix())
			}
			switch block.Scope {
			case "node", "gateway", "host":
			default:
				tenant, err := g.Tenant(s, true)
				if err != nil {
					return err
				}
				block.Tenant = tenant
			}
			// The server fills in who and when from the signed operation.
			check := block
			check.Actor, check.CreatedAt = "check", 1
			if lifetime > 0 {
				check.CreatedAt = uint64(time.Now().Unix())
			}
			if !check.Valid() {
				return cli.Usagef("these options do not describe a %q block; see 'mydc ingress block --help'", block.Scope)
			}
			opID := id.Get()
			return g.sendAndPrint(c, s, fmt.Sprintf("Block %s (%s) with %s.", blockTarget(block), block.Scope, block.Response), change{ID: opID, Summary: "ingress block " + block.ID, Action: "ingress-block", Payload: control.IngressBlockChange{Block: block}})
		}),
	}
}

// findBlock returns the current block record and the epoch of the read.
func findBlock(c *cli.Context, g *globals, s *session, id string) (control.IngressBlockView, uint64, error) {
	q := control.IngressQuery{Part: "blocks"}
	if g.tenant != "" {
		q.Tenant = g.tenant
	}
	rows, epoch, err := ingressBlockRows(c, g, s, q)
	if err != nil {
		return control.IngressBlockView{}, 0, err
	}
	for _, b := range rows {
		if b.Block.ID == id && !b.Removed {
			return b, epoch, nil
		}
	}
	return control.IngressBlockView{}, 0, fmt.Errorf("block %q not found", id)
}

func ingressUnblockCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	var revision cli.RevisionFlag
	return &cli.Command{
		Name:  "unblock",
		Args:  "ID",
		Short: "Remove a block",
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			fs.Var(&revision, "if-revision", "only if the block is still at this `revision`")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 1 || !lifecycle.ValidID(args[0]) {
				return cli.Usagef("unblock needs one block ID")
			}
			b, epoch, err := findBlock(c, g, s, args[0])
			if err != nil {
				return err
			}
			expected, _ := revision.Resolve(func() (uint64, error) { return b.Revision, nil })
			opID := id.Get()
			return g.sendAndPrint(c, s, fmt.Sprintf("Remove block %s (%s).", args[0], blockTarget(b.Block)), change{ID: opID, Summary: "ingress unblock " + args[0], Action: "ingress-unblock", Expected: expected, Epoch: epoch, Payload: control.IngressBlockSelection{ID: args[0]}})
		}),
	}
}

func ingressExtendCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	var revision cli.RevisionFlag
	var lifetime time.Duration
	return &cli.Command{
		Name:  "extend",
		Args:  "ID",
		Short: "Keep a block that expires for longer",
		Flags: func(fs *flag.FlagSet) {
			fs.DurationVar(&lifetime, "for", 0, "new lifetime from now, such as 2h")
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			fs.Var(&revision, "if-revision", "only if the block is still at this `revision`")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 1 || !lifecycle.ValidID(args[0]) {
				return cli.Usagef("extend needs one block ID")
			}
			if lifetime <= 0 {
				return cli.Usagef("extend needs --for, such as --for 2h")
			}
			b, epoch, err := findBlock(c, g, s, args[0])
			if err != nil {
				return err
			}
			expires := time.Now().Add(lifetime)
			expected, _ := revision.Resolve(func() (uint64, error) { return b.Revision, nil })
			opID := id.Get()
			return g.sendAndPrint(c, s, fmt.Sprintf("Keep block %s until %s.", args[0], expires.Local().Format("2006-01-02 15:04")), change{ID: opID, Summary: "ingress extend " + args[0], Action: "ingress-block-extend", Expected: expected, Epoch: epoch, Payload: control.IngressBlockSelection{ID: args[0], ExpiresAt: uint64(expires.Unix())}})
		}),
	}
}

// ingressHostsCommand is the tenant's host grant: which host names its apps
// may serve on the external and local gateways.
func ingressHostsCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	var revision cli.RevisionFlag
	var external, local string
	var externalAllowed bool
	policies := func(c *cli.Context, s *session, tenant string) ([]control.IngressHostPolicyView, uint64, error) {
		rows := []control.IngressHostPolicyView{}
		var epoch uint64
		err := ingressPages(c, g, s, control.IngressQuery{Tenant: tenant, Part: "policies"}, func(p control.IngressPage) uint32 {
			rows = append(rows, p.HostPolicies...)
			epoch = p.Epoch
			return 0
		})
		return rows, epoch, err
	}
	split := func(s string) []string {
		if s == "" {
			return []string{}
		}
		return strings.Split(s, ",")
	}
	return &cli.Command{
		Name:  "hosts",
		Short: "Show or set which host names a tenant may serve",
		Sub: []*cli.Command{
			{
				Name:  "show",
				Short: "Show the tenant's host grant",
				Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
					if len(args) != 0 {
						return cli.Usagef("show takes no arguments")
					}
					tenant, err := g.Tenant(s, false)
					if err != nil {
						return err
					}
					rows, _, err := policies(c, s, tenant)
					if err != nil {
						return err
					}
					return cli.Print(c.Out, g.output.Format(), rows, func() cli.Rows {
						t := cli.Rows{Header: []string{"tenant", "external", "external hosts", "local hosts", "revision"}}
						for _, p := range rows {
							t.Add(p.Tenant, p.Policy.ExternalAllowed, strings.Join(p.Policy.ExternalHosts, ","), strings.Join(p.Policy.LocalHosts, ","), p.Revision)
						}
						return t
					})
				}),
			},
			{
				Name:  "set",
				Short: "Replace the tenant's host grant (system administrators)",
				Long:  "Replaces the whole grant. Host patterns may start with '*.'.",
				Flags: func(fs *flag.FlagSet) {
					fs.BoolVar(&externalAllowed, "external-allowed", false, "allow serving on the external gateway")
					fs.StringVar(&external, "external", "", "comma-separated external host `patterns`")
					fs.StringVar(&local, "local", "", "comma-separated local host `patterns`")
					fs.Var(&id, "id", "operation `ID` (default: a new one)")
					fs.Var(&revision, "if-revision", "only if the grant is still at this `revision`")
				},
				Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
					if len(args) != 0 {
						return cli.Usagef("set takes no arguments")
					}
					tenant, err := g.Tenant(s, true)
					if err != nil {
						return err
					}
					rows, epoch, err := policies(c, s, tenant)
					if err != nil {
						return err
					}
					expected, _ := revision.Resolve(func() (uint64, error) {
						for _, p := range rows {
							if p.Tenant == tenant {
								return p.Revision, nil
							}
						}
						return 0, nil
					})
					policy := control.IngressHostPolicyChange{Tenant: tenant, Policy: ingress.HostPolicy{ExternalAllowed: externalAllowed, ExternalHosts: split(external), LocalHosts: split(local)}}
					opID := id.Get()
					return g.sendAndPrint(c, s, fmt.Sprintf("Tenant %s may serve external=%v hosts [%s], local hosts [%s].", tenant, externalAllowed, external, local), change{ID: opID, Summary: "ingress hosts set --tenant " + tenant, Action: "set-ingress-host-policy", Expected: expected, Epoch: epoch, Payload: policy})
				}),
			},
		},
	}
}

// gatewaysFile is gateways.yaml: the shared listeners of one node.
type gatewaysFile struct {
	Version  int              `yaml:"version"`
	External *ingress.Gateway `yaml:"external,omitempty"`
	Local    *ingress.Gateway `yaml:"local,omitempty"`
}

func decodeYAMLFile(c *cli.Context, path string, limit int, v any) error {
	raw, err := readInputFile(c, path, limit)
	if err != nil {
		return err
	}
	d := yaml.NewDecoder(bytes.NewReader(raw))
	d.KnownFields(true)
	if err = d.Decode(v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func ingressGatewaysCommand(g *globals) *cli.Command {
	var file string
	var id cli.IDFlag
	var revision cli.RevisionFlag
	read := func(c *cli.Context, s *session, node string) (control.NodeGatewaysView, bool, error) {
		var views []control.NodeGatewaysView
		err := ingressPages(c, g, s, control.IngressQuery{Node: node, Part: "gateways"}, func(p control.IngressPage) uint32 {
			views = append(views, p.NodeGateways...)
			return 0
		})
		for _, v := range views {
			if v.Node == node {
				return v, true, err
			}
		}
		return control.NodeGatewaysView{}, false, err
	}
	nodeArg := func(args []string, verb string) (string, error) {
		if len(args) != 1 || !lifecycle.ValidID(args[0]) {
			return "", cli.Usagef("%s needs one node name", verb)
		}
		return args[0], nil
	}
	return &cli.Command{
		Name:  "gateways",
		Short: "Show or set a node's shared gateway listeners (system administrators)",
		Sub: []*cli.Command{
			{
				Name:  "show",
				Args:  "NODE",
				Short: "Show the node's gateway settings and whether they are applied",
				Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
					node, err := nodeArg(args, "show")
					if err != nil {
						return err
					}
					view, found, err := read(c, s, node)
					if err != nil {
						return err
					}
					if !found {
						return fmt.Errorf("no gateway settings for node %q", node)
					}
					if g.output.Format() != cli.Table {
						return cli.Print(c.Out, g.output.Format(), view, nil)
					}
					fmt.Fprintf(c.Out, "Node:     %s\nFrom:     %s\nRevision: %d (applied %d)\n", view.Node, view.Source, view.Revision, view.AppliedRevision)
					if view.Error != "" {
						fmt.Fprintf(c.Out, "Error:    %s\n", view.Error)
					}
					fmt.Fprintln(c.Out)
					return yaml.NewEncoder(c.Out).Encode(gatewaysFile{Version: 1, External: &view.Configuration.External, Local: &view.Configuration.Local})
				}),
			},
			{
				Name:  "set",
				Args:  "NODE",
				Short: "Replace the node's gateway settings from gateways.yaml",
				Long: `Replaces the external and/or local gateway of NODE with gateways.yaml
(the format 'mydc ingress gateways show NODE' prints). A gateway left out
of the file keeps its settings. Addresses must be real addresses of NODE.`,
				Flags: func(fs *flag.FlagSet) {
					fs.StringVar(&file, "f", "", "gateways.yaml `file`")
					fs.Var(&id, "id", "operation `ID` (default: a new one)")
					fs.Var(&revision, "if-revision", "only if the settings are still at this `revision`")
				},
				Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
					node, err := nodeArg(args, "set")
					if err != nil {
						return err
					}
					if file == "" {
						return cli.Usagef("set needs -f gateways.yaml")
					}
					var f gatewaysFile
					if err = decodeYAMLFile(c, file, 32<<10, &f); err != nil {
						return err
					}
					if f.Version != 1 {
						return fmt.Errorf("%s: first line must be 'version: 1'", file)
					}
					if f.External == nil && f.Local == nil {
						return fmt.Errorf("%s sets neither external nor local", file)
					}
					view, found, err := read(c, s, node)
					if err != nil {
						return err
					}
					expected, _ := revision.Resolve(func() (uint64, error) {
						if found && view.Source == "cluster" {
							return view.Revision, nil
						}
						return 0, nil
					})
					opID := id.Get()
					return g.sendAndPrint(c, s, fmt.Sprintf("Replace the gateway listeners of node %s. Apps served on them may be cut off.", node), change{ID: opID, Summary: "ingress gateways set " + node, Action: "set-node-gateways", Expected: expected, Payload: control.NodeGatewaysChange{Node: node, External: f.External, Local: f.Local}})
				}),
			},
		},
	}
}

func ingressBalanceCommand(g *globals) *cli.Command {
	var file string
	var id cli.IDFlag
	var revision cli.RevisionFlag
	return &cli.Command{
		Name:  "balance",
		Args:  "APP ROUTE",
		Short: "Set how a route spreads requests over its backends",
		Long: `Replaces the load balancing of one route with balance.yaml, for example:
  method: weighted
  weights: {v1: 90, v2: 10}
The app.yaml route keeps its own setting; this one wins until changed.`,
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&file, "f", "", "balance.yaml `file`")
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			fs.Var(&revision, "if-revision", "only if the route's balance is still at this `revision`")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 2 || !lifecycle.ValidID(args[0]) || args[1] == "" {
				return cli.Usagef("balance needs APP and ROUTE")
			}
			if file == "" {
				return cli.Usagef("balance needs -f balance.yaml")
			}
			var b ingress.Balance
			if err := decodeYAMLFile(c, file, 32<<10, &b); err != nil {
				return err
			}
			if err := b.Validate(); err != nil {
				return fmt.Errorf("%s: %w", file, err)
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			app, route := args[0], args[1]
			found := false
			var current, epoch uint64
			err = ingressPages(c, g, s, control.IngressQuery{Tenant: tenant, App: app, Part: "mappings"}, func(p control.IngressPage) uint32 {
				epoch = p.Epoch
				for _, m := range p.Mappings {
					for _, r := range m.Spec.Routes {
						if r.ID == route {
							found, current = true, max(current, r.BalanceRevision)
						}
					}
				}
				return 0
			})
			if err != nil {
				return err
			}
			if !found {
				return fmt.Errorf("app %s has no ingress route %q", app, route)
			}
			expected, _ := revision.Resolve(func() (uint64, error) { return current, nil })
			opID := id.Get()
			return g.sendAndPrint(c, s, fmt.Sprintf("Change the load balancing of route %s of app %s.", route, app), change{ID: opID, Summary: "ingress balance " + app + " " + route, Action: "set-ingress-balance", Expected: expected, Epoch: epoch, Payload: control.IngressBalanceChange{Tenant: tenant, App: app, Route: route, Balance: b}})
		}),
	}
}

// drainRevision is the revision of the (tenant, app, node) drain record: the
// number of accepted drain and undrain changes of exactly that key. mydcd
// keeps the whole ingress history (it refuses changes when it is full).
func drainRevision(c *cli.Context, g *globals, s *session, tenant, app, node string) (uint64, error) {
	n := uint64(0)
	err := ingressPages(c, g, s, control.IngressQuery{Tenant: tenant, App: app, Part: "history"}, func(p control.IngressPage) uint32 {
		for _, h := range p.History {
			if (h.Action == "drain-ingress" || h.Action == "undrain-ingress") && h.Tenant == tenant && h.App == app && h.Node == node {
				n++
			}
		}
		return 0
	})
	return n, err
}

func ingressDrainCommand(g *globals, verb string) *cli.Command {
	var node string
	var wait time.Duration
	var id cli.IDFlag
	var revision cli.RevisionFlag
	short := "Stop sending new requests to an app (on one node or everywhere)"
	if verb == "undrain" {
		short = "Send requests to a drained app again"
	}
	return &cli.Command{
		Name:  verb,
		Args:  "APP",
		Short: short,
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&node, "node", "", "only on this `node` (default: every node of the app)")
			if verb == "drain" {
				fs.DurationVar(&wait, "grace", 30*time.Second, "let running requests finish for this long (at most 1h)")
			}
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			fs.Var(&revision, "if-revision", "only if the drain record is still at this `revision`")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 1 || !lifecycle.ValidID(args[0]) {
				return cli.Usagef("%s needs one app name", verb)
			}
			if node != "" && !lifecycle.ValidID(node) {
				return cli.Usagef("--node %q is not a valid node name", node)
			}
			if wait < 0 || wait > time.Hour || wait%time.Second != 0 {
				return cli.Usagef("--grace must be whole seconds up to 1h")
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			app := args[0]
			expected, err := revision.Resolve(func() (uint64, error) { return drainRevision(c, g, s, tenant, app, node) })
			if err != nil {
				return err
			}
			drain := control.IngressDrainChange{Tenant: tenant, App: app, Node: node}
			where := "every node"
			if node != "" {
				where = "node " + node
			}
			impact := fmt.Sprintf("Send requests to app %s on %s again.", app, where)
			summary := "ingress undrain " + app
			if verb == "drain" {
				drain.DrainSeconds = uint64(wait / time.Second)
				impact = fmt.Sprintf("Stop new requests to app %s on %s; running requests get %s.", app, where, wait)
				summary = "ingress drain " + app
			}
			if node != "" {
				summary += " --node " + node
			}
			opID := id.Get()
			return g.sendAndPrint(c, s, impact, change{ID: opID, Summary: summary, Action: verb + "-ingress", Expected: expected, Payload: drain})
		}),
	}
}
